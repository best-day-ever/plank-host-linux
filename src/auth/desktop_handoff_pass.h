/**
 * @file src/auth/desktop_handoff_pass.h
 * @brief One-shot pass that signs a PLANK-authenticated account into GDM.
 *
 * After a PLANK login lands on the GDM greeter, the root media worker writes a
 * short-lived pass for that account and types the account name into the
 * greeter. `pam_plank_handoff.so`, first in the `gdm-password` auth stack,
 * consumes the pass instead of prompting for a second password. The pass holds
 * no secret: it lives in a root-only directory, names one account, expires
 * after a few seconds and is claimed with an atomic rename, so it admits at
 * most one GDM login. Both sides share this header so the format and every
 * validation rule are unit-testable.
 */
#pragma once

#include <cerrno>
#include <charconv>
#include <cstdint>
#include <ctime>
#include <fcntl.h>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace plank::auth::handoff {
  /// Root-owned 0700 directory holding at most one pass per account UID.
  constexpr std::string_view pass_directory = "/run/plank/handoff";
  /// First line of every pass; a format change needs a new version.
  constexpr std::string_view pass_magic = "PLANK-HANDOFF-1";
  /// How long a pass stays valid after the worker writes it.
  constexpr std::uint64_t pass_lifetime_ms = 45000;
  /// Upper bound for a serialized pass.
  constexpr std::size_t maximum_pass_size = 512;
  /// Longest account name the worker will type into the greeter.
  constexpr std::size_t maximum_account_name = 64;

  struct pass_t {
    uid_t uid {};  ///< Account the pass admits.
    std::string account;  ///< Account name, checked against the PAM user.
    std::uint64_t expires_ms {};  ///< CLOCK_BOOTTIME deadline in milliseconds.
  };

  /** Monotonic time that keeps counting across suspend and ignores wall-clock changes. */
  inline std::uint64_t boottime_ms() {
    timespec now {};
    clock_gettime(CLOCK_BOOTTIME, &now);
    return static_cast<std::uint64_t>(now.tv_sec) * 1000U +
           static_cast<std::uint64_t>(now.tv_nsec) / 1000000U;
  }

  /**
   * @brief Account names that are safe to type into the greeter.
   *
   * FreeIPA and local account names in this deployment are lower-case ASCII.
   * Anything else is refused rather than typed, so no keyboard layout or
   * input-method state can turn it into a different name.
   */
  inline bool typeable_account_name(std::string_view account) {
    if (account.empty() || account.size() > maximum_account_name || account.front() == '-') {
      return false;
    }
    for (const char c : account) {
      const bool allowed = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                           c == '.' || c == '_' || c == '-';
      if (!allowed) return false;
    }
    return true;
  }

  inline std::string pass_path(uid_t uid) {
    return std::string {pass_directory} + "/" + std::to_string(uid);
  }

  inline std::string encode(const pass_t &pass) {
    return std::string {pass_magic} + "\nuid=" + std::to_string(pass.uid) +
           "\naccount=" + pass.account + "\nexpires=" + std::to_string(pass.expires_ms) + "\n";
  }

  namespace detail {
    inline bool take_line(std::string_view &input, std::string_view &line) {
      const auto end = input.find('\n');
      if (end == std::string_view::npos) return false;
      line = input.substr(0, end);
      input.remove_prefix(end + 1);
      return true;
    }

    template<class T>
    bool take_number(std::string_view &input, std::string_view key, T &value) {
      std::string_view line;
      if (!take_line(input, line) || !line.starts_with(key)) return false;
      line.remove_prefix(key.size());
      if (line.empty()) return false;
      const auto [end, error] = std::from_chars(line.data(), line.data() + line.size(), value);
      return error == std::errc {} && end == line.data() + line.size();
    }
  }  // namespace detail

  inline std::optional<pass_t> parse(std::string_view input) {
    if (input.size() > maximum_pass_size) return std::nullopt;
    std::string_view line;
    if (!detail::take_line(input, line) || line != pass_magic) return std::nullopt;
    pass_t pass;
    if (!detail::take_number(input, "uid=", pass.uid)) return std::nullopt;
    if (!detail::take_line(input, line) || !line.starts_with("account=")) return std::nullopt;
    pass.account = std::string {line.substr(8)};
    if (!detail::take_number(input, "expires=", pass.expires_ms) || !input.empty()) {
      return std::nullopt;
    }
    if (pass.uid == 0 || !typeable_account_name(pass.account)) return std::nullopt;
    return pass;
  }

  /** A pass admits exactly the account it names, never root, until it expires. */
  inline bool admits(const pass_t &pass, uid_t uid, std::string_view account, std::uint64_t now_ms) {
    return uid != 0 && pass.uid == uid && pass.account == account && now_ms < pass.expires_ms &&
           pass.expires_ms - now_ms <= pass_lifetime_ms;
  }

  namespace detail {
    inline bool ensure_directory() {
      const std::string directory {pass_directory};
      if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) return false;
      struct stat status {};
      return lstat(directory.c_str(), &status) == 0 && S_ISDIR(status.st_mode) &&
             status.st_uid == 0 && (status.st_mode & 0777) == 0700;
    }

    inline bool write_all(int descriptor, std::string_view data) {
      while (!data.empty()) {
        const ssize_t written = write(descriptor, data.data(), data.size());
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        data.remove_prefix(static_cast<std::size_t>(written));
      }
      return true;
    }
  }  // namespace detail

  /** Replace the account's pass. Root only; the parent directory must already be /run/plank. */
  inline bool write_pass(const pass_t &pass) {
    if (geteuid() != 0 || !detail::ensure_directory()) return false;
    const std::string path = pass_path(pass.uid);
    const std::string temporary = path + ".new." + std::to_string(getpid());
    unlink(temporary.c_str());
    const int descriptor = open(
      temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600
    );
    if (descriptor < 0) return false;
    const bool written = detail::write_all(descriptor, encode(pass)) && fsync(descriptor) == 0;
    close(descriptor);
    if (!written || rename(temporary.c_str(), path.c_str()) != 0) {
      unlink(temporary.c_str());
      return false;
    }
    return true;
  }

  inline void remove_pass(uid_t uid) {
    unlink(pass_path(uid).c_str());
  }

  /**
   * @brief Claim and delete the account's pass.
   *
   * The rename is the single-use guarantee: of any number of concurrent GDM
   * conversations, only one can move the file away. The claimed file must be a
   * root-owned 0600 regular file; anything else is deleted and rejected.
   */
  inline std::optional<pass_t> consume_pass(uid_t uid) {
    const std::string path = pass_path(uid);
    const std::string claimed = path + ".claim." + std::to_string(getpid());
    if (rename(path.c_str(), claimed.c_str()) != 0) return std::nullopt;
    const int descriptor = open(claimed.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    unlink(claimed.c_str());
    if (descriptor < 0) return std::nullopt;
    struct stat status {};
    std::string content(maximum_pass_size + 1, '\0');
    ssize_t size = -1;
    if (fstat(descriptor, &status) == 0 && S_ISREG(status.st_mode) && status.st_uid == 0 &&
        (status.st_mode & 0777) == 0600 && status.st_size >= 0 &&
        static_cast<std::size_t>(status.st_size) <= maximum_pass_size) {
      size = read(descriptor, content.data(), content.size());
    }
    close(descriptor);
    if (size < 0) return std::nullopt;
    content.resize(static_cast<std::size_t>(size));
    return parse(content);
  }
}  // namespace plank::auth::handoff
