/**
 * @file src/platform/linux/x11_clipboard.cpp
 * @brief X11 UTF-8 clipboard watch and publish helpers for PLANK sessions.
 */
#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)

#include "x11_clipboard.h"

#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <X11/extensions/Xfixes.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <thread>

#include "src/logging.h"
#include "src/platform/common.h"

namespace platf::x11 {
  namespace {
    constexpr auto property_name = "PLANK_CLIPBOARD";
    constexpr auto poll_period = std::chrono::milliseconds(250);

    Atom clipboard_atom(Display *display) {
      return XInternAtom(display, "CLIPBOARD", False);
    }

    Atom primary_atom(Display *display) {
      return XInternAtom(display, "PRIMARY", False);
    }

    Atom utf8_atom(Display *display) {
      return XInternAtom(display, "UTF8_STRING", False);
    }

    Atom property_atom(Display *display) {
      return XInternAtom(display, property_name, False);
    }

    Atom targets_atom(Display *display) {
      return XInternAtom(display, "TARGETS", False);
    }
  }  // namespace

  std::optional<clipboard_t> clipboard_t::make() {
    clipboard_t clipboard;
    clipboard.display_ = XOpenDisplay(nullptr);
    if (clipboard.display_ == nullptr) {
      BOOST_LOG(error) << "Unable to open X11 display for PLANK clipboard sync"sv;
      return std::nullopt;
    }

    auto *display = static_cast<Display *>(clipboard.display_);
    const auto root = DefaultRootWindow(display);
    clipboard.window_ = XCreateSimpleWindow(display, root, 0, 0, 1, 1, 0, 0, 0);
    if (clipboard.window_ == 0) {
      XCloseDisplay(display);
      return std::nullopt;
    }

    int event_base = 0;
    int error_base = 0;
    if (!XFixesQueryExtension(display, &event_base, &error_base)) {
      BOOST_LOG(warning) << "XFixes unavailable; PLANK clipboard sync uses polling only"sv;
    } else {
      clipboard.xfixes_event_base_ = event_base;
      XFixesSelectSelectionInput(
        display,
        clipboard.window_,
        clipboard_atom(display),
        XFixesSetSelectionOwnerNotifyMask
      );
    }

    XFlush(display);
    return clipboard;
  }

  bool clipboard_t::read_selection(std::string &text) {
    auto *display = static_cast<Display *>(display_);
    const Atom clipboard = clipboard_atom(display);
    const Atom utf8 = utf8_atom(display);
    const Atom property = property_atom(display);
    const Window owner = XGetSelectionOwner(display, clipboard);
    if (owner == None) {
      return false;
    }
    if (owner == window_) {
      text = owned_text_;
      return !text.empty();
    }

    XConvertSelection(display, clipboard, utf8, property, window_, CurrentTime);
    XFlush(display);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    while (std::chrono::steady_clock::now() < deadline) {
      while (XPending(display) > 0) {
        XEvent event {};
        XNextEvent(display, &event);
        if (event.type == SelectionNotify &&
            event.xselection.requestor == window_ &&
            event.xselection.property != None) {
          Atom actual_type = None;
          int actual_format = 0;
          unsigned long item_count = 0;
          unsigned long bytes_after = 0;
          unsigned char *data = nullptr;
          if (XGetWindowProperty(
                display,
                window_,
                property,
                0,
                1024 * 1024,
                True,
                AnyPropertyType,
                &actual_type,
                &actual_format,
                &item_count,
                &bytes_after,
                &data
              ) == Success &&
              data != nullptr) {
            text.assign(reinterpret_cast<char *>(data), item_count);
            XFree(data);
            return !text.empty();
          }
          if (data != nullptr) {
            XFree(data);
          }
          return false;
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return false;
  }

  bool clipboard_t::poll_change(std::string &text) {
    auto *display = static_cast<Display *>(display_);
    while (XPending(display) > 0) {
      XEvent event {};
      XNextEvent(display, &event);
      if (xfixes_event_base_ >= 0 &&
          event.type == xfixes_event_base_ + XFixesSelectionNotify) {
        // Selection owner changed; fall through to read below.
      }
    }

    std::string candidate;
    if (!read_selection(candidate) || candidate == last_sent_text_) {
      return false;
    }
    text = std::move(candidate);
    return true;
  }

  bool clipboard_t::set_text(const std::vector<std::uint8_t> &text) {
    if (text.empty()) {
      return false;
    }
    auto *display = static_cast<Display *>(display_);
    const Atom clipboard = clipboard_atom(display);
    const Atom primary = primary_atom(display);
    const Atom utf8 = utf8_atom(display);

    owned_text_.assign(reinterpret_cast<const char *>(text.data()), text.size());
    last_sent_text_ = owned_text_;
    ++generation_;

    XSetSelectionOwner(display, clipboard, window_, CurrentTime);
    if (XGetSelectionOwner(display, clipboard) != window_) {
      BOOST_LOG(warning) << "Unable to become X11 CLIPBOARD owner for PLANK sync"sv;
      return false;
    }

    XChangeProperty(
      display,
      window_,
      utf8,
      utf8,
      8,
      PropModeReplace,
      text.data(),
      static_cast<int>(text.size())
    );
    XSetSelectionOwner(display, primary, window_, CurrentTime);
    XFlush(display);
    return true;
  }
}  // namespace platf::x11

#endif
