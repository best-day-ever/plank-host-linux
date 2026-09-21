/**
 * @file src/session/greeter_signin.cpp
 * @brief GDM greeter sign-in through a handoff pass and XTest key events.
 */
#include "greeter_signin.h"

#include <atomic>
#include <chrono>
#include <dlfcn.h>
#include <optional>
#include <thread>
#include <unistd.h>

#include "src/auth/desktop_handoff_pass.h"

namespace plank::session {
  namespace {
    // Xlib/XTest are loaded at runtime like the other X extensions the worker
    // uses, so the package gains no link-time dependency.
    struct x_display;
    using keysym_t = unsigned long;
    using open_display_fn = x_display *(*) (const char *);
    using close_display_fn = int (*)(x_display *);
    using keysym_to_keycode_fn = unsigned char (*)(x_display *, keysym_t);
    using keycode_to_keysym_fn = keysym_t (*)(x_display *, unsigned char, int, int);
    using flush_fn = int (*)(x_display *);
    using fake_key_fn = int (*)(x_display *, unsigned int, int, unsigned long);

    constexpr keysym_t keysym_escape = 0xff1b;
    constexpr keysym_t keysym_return = 0xff0d;
    constexpr keysym_t keysym_shift_left = 0xffe1;
    // Let a new stream's input path and the greeter settle before typing.
    constexpr auto settle_delay = std::chrono::milliseconds {1500};
    constexpr auto stream_wait = std::chrono::seconds {15};
    constexpr auto key_gap = std::chrono::milliseconds {12};

    struct xtest_t {
      void *x11 {};
      void *xtst {};
      open_display_fn open_display {};
      close_display_fn close_display {};
      keysym_to_keycode_fn keysym_to_keycode {};
      keycode_to_keysym_fn keycode_to_keysym {};
      flush_fn flush {};
      fake_key_fn fake_key {};

      ~xtest_t() {
        if (xtst) dlclose(xtst);
        if (x11) dlclose(x11);
      }

      bool load() {
        x11 = dlopen("libX11.so.6", RTLD_NOW | RTLD_LOCAL);
        xtst = dlopen("libXtst.so.6", RTLD_NOW | RTLD_LOCAL);
        if (!x11 || !xtst) return false;
        open_display = reinterpret_cast<open_display_fn>(dlsym(x11, "XOpenDisplay"));
        close_display = reinterpret_cast<close_display_fn>(dlsym(x11, "XCloseDisplay"));
        keysym_to_keycode = reinterpret_cast<keysym_to_keycode_fn>(dlsym(x11, "XKeysymToKeycode"));
        keycode_to_keysym = reinterpret_cast<keycode_to_keysym_fn>(dlsym(x11, "XkbKeycodeToKeysym"));
        flush = reinterpret_cast<flush_fn>(dlsym(x11, "XFlush"));
        fake_key = reinterpret_cast<fake_key_fn>(dlsym(xtst, "XTestFakeKeyEvent"));
        return open_display && close_display && keysym_to_keycode && keycode_to_keysym && flush &&
               fake_key;
      }
    };

    class typist_t {
    public:
      explicit typist_t(xtest_t &x):
          x_ {x}, display_ {x.open_display(nullptr)} {}

      ~typist_t() {
        if (display_) x_.close_display(display_);
      }

      bool ready() const {
        return display_ != nullptr;
      }

      /** Resolve every key first, so an untypeable name sends nothing. */
      bool resolvable(keysym_t keysym) const {
        return stroke(keysym).has_value();
      }

      bool press(keysym_t keysym) {
        const auto key = stroke(keysym);
        if (!key) return false;
        if (key->shift) event(shift_, true);
        event(key->code, true);
        event(key->code, false);
        if (key->shift) event(shift_, false);
        return true;
      }

    private:
      struct stroke_t {
        unsigned char code;
        bool shift;
      };

      std::optional<stroke_t> stroke(keysym_t keysym) const {
        const unsigned char code = x_.keysym_to_keycode(display_, keysym);
        if (code == 0) return std::nullopt;
        // Honour the greeter's keyboard layout: pick the level that yields
        // the keysym, never assume US positions.
        if (x_.keycode_to_keysym(display_, code, 0, 0) == keysym) return stroke_t {code, false};
        if (shift_ != 0 && x_.keycode_to_keysym(display_, code, 0, 1) == keysym) {
          return stroke_t {code, true};
        }
        return std::nullopt;
      }

      void event(unsigned char code, bool down) {
        x_.fake_key(display_, code, down ? 1 : 0, 0);
        x_.flush(display_);
        std::this_thread::sleep_for(key_gap);
      }

      xtest_t &x_;
      x_display *display_;
      unsigned char shift_ {display_ ? x_.keysym_to_keycode(display_, keysym_shift_left) : static_cast<unsigned char>(0)};
    };

    std::atomic_uint64_t signin_generation {};
    std::atomic<uid_t> pending_uid {0};

    void log_line(const char *message) {
      // Shared stderr sink with the worker log; never includes account data.
      [[maybe_unused]] const auto ignored = write(STDERR_FILENO, message, std::char_traits<char>::length(message));
    }

    bool type_account(const std::string &account) {
      xtest_t x;
      if (!x.load()) {
        log_line("PLANK greeter sign-in: libX11/libXtst unavailable\n");
        return false;
      }
      typist_t typist {x};
      if (!typist.ready()) {
        log_line("PLANK greeter sign-in: cannot open the greeter display\n");
        return false;
      }
      for (const char c : account) {
        if (!typist.resolvable(static_cast<keysym_t>(static_cast<unsigned char>(c)))) {
          log_line("PLANK greeter sign-in: the greeter keymap cannot type the account name\n");
          return false;
        }
      }
      // Escape backs out of a half-finished prompt to the account entry.
      typist.press(keysym_escape);
      std::this_thread::sleep_for(std::chrono::milliseconds {400});
      for (const char c : account) {
        typist.press(static_cast<keysym_t>(static_cast<unsigned char>(c)));
      }
      return typist.press(keysym_return);
    }
  }  // namespace

  bool sign_into_greeter(uid_t uid, const std::string &account, std::function<bool()> stream_live) {
    namespace handoff = plank::auth::handoff;
    if (uid == 0 || !handoff::typeable_account_name(account)) return false;
    const auto generation = ++signin_generation;
    const uid_t previous = pending_uid.exchange(uid);
    if (previous != 0 && previous != uid) handoff::remove_pass(previous);
    const handoff::pass_t pass {uid, account, handoff::boottime_ms() + handoff::pass_lifetime_ms};
    if (!handoff::write_pass(pass)) {
      log_line("PLANK greeter sign-in: cannot write the handoff pass\n");
      return false;
    }
    std::thread {[generation, uid, account, stream_live = std::move(stream_live)]() {
      const auto started = std::chrono::steady_clock::now();
      while (!stream_live() && std::chrono::steady_clock::now() - started < stream_wait) {
        std::this_thread::sleep_for(std::chrono::milliseconds {100});
      }
      std::this_thread::sleep_for(settle_delay);
      if (signin_generation.load() == generation && stream_live()) {
        if (!type_account(account)) handoff::remove_pass(uid);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds {handoff::pass_lifetime_ms});
      // Unclaimed passes never outlive their lifetime, even though the PAM
      // module would refuse them anyway.
      if (signin_generation.load() == generation) {
        handoff::remove_pass(uid);
        uid_t expected = uid;
        pending_uid.compare_exchange_strong(expected, 0);
      }
    }}.detach();
    return true;
  }

  void cancel_greeter_signin() {
    ++signin_generation;
    const uid_t uid = pending_uid.exchange(0);
    if (uid != 0) plank::auth::handoff::remove_pass(uid);
  }
}  // namespace plank::session
