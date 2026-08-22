/**
 * @file src/session/session_context.cpp
 * @brief Logind-backed graphical-session selection for StationConnect.
 */
#include "session_context.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <regex>
#include <string_view>
#include <vector>

#include <systemd/sd-login.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

namespace stationconnect::session {
  namespace {
    using login_string_t = std::unique_ptr<char, decltype(&free)>;

    std::optional<std::string> session_string(
      int (*getter)(const char *, char **),
      std::string_view session_id
    ) {
      char *raw = nullptr;
      const std::string id {session_id};
      if (getter(id.c_str(), &raw) < 0 || raw == nullptr) {
        return std::nullopt;
      }
      login_string_t value {raw, &free};
      return std::string {value.get()};
    }

    bool owned_path(const std::filesystem::path &path, uid_t uid, bool directory) {
      struct stat status {};
      if (lstat(path.c_str(), &status) != 0 || status.st_uid != uid) {
        return false;
      }
      return directory ? S_ISDIR(status.st_mode) : S_ISREG(status.st_mode);
    }

    std::optional<pid_t> parse_pid(const std::filesystem::path &path) {
      const auto name = path.filename().string();
      pid_t pid {};
      const auto result = std::from_chars(name.data(), name.data() + name.size(), pid);
      if (result.ec != std::errc {} || result.ptr != name.data() + name.size() || pid <= 0) {
        return std::nullopt;
      }
      return pid;
    }

    std::map<std::string, std::string> read_selected_environment(pid_t pid) {
      constexpr std::size_t maximum_environment_size = 1024U * 1024U;
      const std::array<std::string_view, 4> allowed {
        "DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"
      };
      std::ifstream input {
        "/proc/" + std::to_string(pid) + "/environ",
        std::ios::binary
      };
      if (!input) {
        return {};
      }
      std::string contents(
        std::istreambuf_iterator<char> {input},
        std::istreambuf_iterator<char> {}
      );
      if (contents.size() > maximum_environment_size) {
        return {};
      }

      std::map<std::string, std::string> result;
      std::size_t offset = 0;
      while (offset < contents.size()) {
        const auto end = contents.find('\0', offset);
        const auto length = (end == std::string::npos ? contents.size() : end) - offset;
        const std::string_view entry {contents.data() + offset, length};
        const auto separator = entry.find('=');
        if (separator != std::string_view::npos) {
          const auto name = entry.substr(0, separator);
          if (std::ranges::find(allowed, name) != allowed.end()) {
            result.emplace(name, entry.substr(separator + 1));
          }
        }
        if (end == std::string::npos) {
          break;
        }
        offset = end + 1;
      }
      return result;
    }

    struct attestation_t {
      std::string session_id;
      uid_t uid {};
    };

    std::optional<attestation_t> read_supervisor_attestation() {
      const char *raw_descriptor = getenv("STATIONCONNECT_SESSION_ATTESTATION_FD");
      if (raw_descriptor == nullptr) {
        return std::nullopt;
      }
      const std::string_view descriptor_text {raw_descriptor};
      int descriptor = -1;
      const auto parsed_descriptor = std::from_chars(
        descriptor_text.data(), descriptor_text.data() + descriptor_text.size(), descriptor
      );
      if (parsed_descriptor.ec != std::errc {} ||
          parsed_descriptor.ptr != descriptor_text.data() + descriptor_text.size() ||
          descriptor <= STDERR_FILENO) {
        return std::nullopt;
      }

      ucred peer {};
      socklen_t peer_size = sizeof(peer);
      if (getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) != 0 ||
          peer_size != sizeof(peer) || peer.uid != 0 || peer.pid <= 1) {
        close(descriptor);
        return std::nullopt;
      }
      std::array<char, 512> buffer {};
      const ssize_t size = recv(descriptor, buffer.data(), buffer.size(), 0);
      close(descriptor);
      if (size <= 0 || static_cast<std::size_t>(size) == buffer.size()) {
        return std::nullopt;
      }
      const std::string_view message {buffer.data(), static_cast<std::size_t>(size)};
      constexpr std::string_view prefix = "SC-SESSION-1\n";
      if (!message.starts_with(prefix)) {
        return std::nullopt;
      }
      const auto session_end = message.find('\n', prefix.size());
      if (session_end == std::string_view::npos || session_end == prefix.size()) {
        return std::nullopt;
      }
      const auto uid_text = message.substr(session_end + 1);
      unsigned long long wire_uid {};
      const auto parsed_uid = std::from_chars(
        uid_text.data(), uid_text.data() + uid_text.size(), wire_uid
      );
      if (parsed_uid.ec != std::errc {} || parsed_uid.ptr != uid_text.data() + uid_text.size() ||
          wire_uid > std::numeric_limits<uid_t>::max()) {
        return std::nullopt;
      }
      return attestation_t {
        std::string {message.substr(prefix.size(), session_end - prefix.size())},
        static_cast<uid_t>(wire_uid),
      };
    }
  }  // namespace

  bool eligible_graphical_session(const descriptor_t &session) {
    return session.active && !session.remote && session.seat == "seat0" &&
           session.type == "x11" && session.state == "active" &&
           (session.session_class == "user" || session.session_class == "greeter");
  }

  std::optional<descriptor_t> describe(std::string_view session_id) {
    if (session_id.empty() || session_id.find('\0') != std::string_view::npos) {
      return std::nullopt;
    }
    const std::string id {session_id};
    descriptor_t result;
    result.id = id;
    if (sd_session_get_uid(id.c_str(), &result.uid) < 0) {
      return std::nullopt;
    }
    const auto seat = session_string(sd_session_get_seat, id);
    const auto type = session_string(sd_session_get_type, id);
    const auto session_class = session_string(sd_session_get_class, id);
    const auto state = session_string(sd_session_get_state, id);
    if (!seat || !type || !session_class || !state) {
      return std::nullopt;
    }
    result.seat = *seat;
    result.type = *type;
    result.session_class = *session_class;
    result.state = *state;
    const int active = sd_session_is_active(id.c_str());
    const int remote = sd_session_is_remote(id.c_str());
    if (active < 0 || remote < 0) {
      return std::nullopt;
    }
    result.active = active > 0;
    result.remote = remote > 0;
    return result;
  }

  std::optional<descriptor_t> active_seat0_graphical_session() {
    char *raw_session = nullptr;
    uid_t uid {};
    if (sd_seat_get_active("seat0", &raw_session, &uid) < 0 || raw_session == nullptr) {
      return std::nullopt;
    }
    login_string_t session_id {raw_session, &free};
    auto result = describe(session_id.get());
    if (!result || result->uid != uid || !eligible_graphical_session(*result)) {
      return std::nullopt;
    }
    return result;
  }

  std::optional<environment_t> discover_environment(const descriptor_t &session) {
    if (!eligible_graphical_session(session)) {
      return std::nullopt;
    }
    const std::string required_runtime = "/run/user/" + std::to_string(session.uid);
    if (!owned_path(required_runtime, session.uid, true)) {
      return std::nullopt;
    }
    static const std::regex local_display {R"(^:[0-9]+(?:\.[0-9]+)?$)"};

    std::error_code error;
    for (const auto &entry : std::filesystem::directory_iterator("/proc", error)) {
      if (error) {
        break;
      }
      const auto pid = parse_pid(entry.path());
      if (!pid) {
        continue;
      }
      char *raw_session = nullptr;
      if (sd_pid_get_session(*pid, &raw_session) < 0 || raw_session == nullptr) {
        continue;
      }
      login_string_t process_session {raw_session, &free};
      if (session.id != process_session.get()) {
        continue;
      }
      const auto values = read_selected_environment(*pid);
      const auto display = values.find("DISPLAY");
      const auto xauthority = values.find("XAUTHORITY");
      const auto runtime = values.find("XDG_RUNTIME_DIR");
      if (display == values.end() || xauthority == values.end() || runtime == values.end() ||
          !std::regex_match(display->second, local_display) ||
          runtime->second != required_runtime || xauthority->second.empty() ||
          xauthority->second.front() != '/' ||
          !owned_path(xauthority->second, session.uid, false)) {
        continue;
      }
      environment_t result {
        display->second,
        xauthority->second,
        runtime->second,
        {},
      };
      if (const auto dbus = values.find("DBUS_SESSION_BUS_ADDRESS"); dbus != values.end()) {
        result.dbus_address = dbus->second;
      }
      return result;
    }
    return std::nullopt;
  }

  std::string session_attestation_message(const descriptor_t &session) {
    if (!eligible_graphical_session(session) || session.id.empty() ||
        session.id.find('\n') != std::string::npos || session.id.size() > 256) {
      return {};
    }
    return "SC-SESSION-1\n" + session.id + "\n" + std::to_string(session.uid);
  }

  bool supervisor_attests_account_for_active_seat0(uid_t account_uid) {
    static const auto attestation = read_supervisor_attestation();
    if (geteuid() != 0 || account_uid == 0 || !attestation) {
      return false;
    }
    const auto active = active_seat0_graphical_session();
    if (!active || active->id != attestation->session_id ||
        active->uid != attestation->uid) {
      return false;
    }
    return active->session_class == "greeter" || active->uid == account_uid;
  }
}  // namespace stationconnect::session
