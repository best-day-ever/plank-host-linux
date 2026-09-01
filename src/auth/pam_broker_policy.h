/**
 * @file src/auth/pam_broker_policy.h
 * @brief Root-login policy loaded by the PLANK PAM broker.
 */
#pragma once

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace plank::auth {
  /** Administrator-owned authentication policy. */
  struct broker_policy_t {
    bool allow_root_login {false};  ///< Root remains denied unless explicitly enabled.
  };

  namespace detail {
    inline std::string_view trim(std::string_view value) {
      while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
      }
      while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1);
      }
      return value;
    }

    inline std::string lowercase(std::string_view value) {
      std::string result {value};
      std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
      });
      return result;
    }
  }  // namespace detail

  /**
   * @brief Parse the authentication policy from PLANK INI text.
   *
   * A missing option preserves the secure default. Duplicate or malformed
   * declarations fail closed so an administrator typo cannot enable root.
   */
  inline std::optional<broker_policy_t> parse_broker_policy(
    std::string_view contents,
    std::string &error
  ) {
    broker_policy_t policy;
    bool in_security = false;
    bool root_option_seen = false;
    std::size_t line_number = 0;
    while (!contents.empty()) {
      ++line_number;
      const auto newline = contents.find('\n');
      auto line = contents.substr(0, newline);
      contents = newline == std::string_view::npos ? std::string_view {} : contents.substr(newline + 1);
      if (!line.empty() && line.back() == '\r') {
        line.remove_suffix(1);
      }
      const auto comment = line.find_first_of("#;");
      if (comment != std::string_view::npos) {
        line = line.substr(0, comment);
      }
      line = detail::trim(line);
      if (line.empty()) {
        continue;
      }
      if (line.front() == '[') {
        if (line.size() < 3 || line.back() != ']') {
          error = "malformed section header on line " + std::to_string(line_number);
          return std::nullopt;
        }
        in_security = detail::lowercase(detail::trim(line.substr(1, line.size() - 2))) == "security";
        continue;
      }
      const auto separator = line.find('=');
      if (separator == std::string_view::npos) {
        error = "malformed setting on line " + std::to_string(line_number);
        return std::nullopt;
      }
      if (!in_security ||
          detail::lowercase(detail::trim(line.substr(0, separator))) != "allow_root_login") {
        continue;
      }
      if (root_option_seen) {
        error = "duplicate security.allow_root_login setting";
        return std::nullopt;
      }
      root_option_seen = true;
      const auto value = detail::lowercase(detail::trim(line.substr(separator + 1)));
      if (value == "true") {
        policy.allow_root_login = true;
      } else if (value == "false") {
        policy.allow_root_login = false;
      } else {
        error = "security.allow_root_login must be true or false";
        return std::nullopt;
      }
    }
    return policy;
  }

  /**
   * @brief Load policy from a root-owned, non-writable regular file.
   */
  inline std::optional<broker_policy_t> load_broker_policy(
    const std::string &path,
    std::string &error
  ) {
    constexpr std::size_t maximum_size = 1024U * 1024U;
    const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
      error = "unable to open " + path + ": " + std::strerror(errno);
      return std::nullopt;
    }
    struct descriptor_owner_t {
      int value;
      ~descriptor_owner_t() { close(value); }
    } owner {descriptor};

    struct stat metadata {};
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != 0 || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
      error = path + " must be a root-owned regular file not writable by group or other";
      return std::nullopt;
    }
    if (metadata.st_size < 0 || static_cast<std::size_t>(metadata.st_size) > maximum_size) {
      error = path + " exceeds the one-megabyte policy limit";
      return std::nullopt;
    }

    std::string contents(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t offset = 0;
    while (offset < contents.size()) {
      const ssize_t received = read(descriptor, contents.data() + offset, contents.size() - offset);
      if (received < 0 && errno == EINTR) {
        continue;
      }
      if (received <= 0) {
        error = "unable to read " + path;
        return std::nullopt;
      }
      offset += static_cast<std::size_t>(received);
    }
    return parse_broker_policy(contents, error);
  }
}  // namespace plank::auth
