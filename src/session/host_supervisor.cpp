/**
 * @file src/session/host_supervisor.cpp
 * @brief Boot-time StationConnect graphical-session worker supervisor.
 */
#include "session_context.h"
#include "../stationconnect_topology.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <poll.h>
#include <pwd.h>
#include <systemd/sd-login.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <grp.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
  constexpr std::string_view default_worker = "/usr/bin/stationconnect-host";
  constexpr std::string_view machine_home = "/var/lib/stationconnect";
  constexpr std::string_view runtime_pulse_cookie =
    "/run/stationconnect/host/pulse-cookie";
  constexpr std::string_view systemctl_path = "/usr/bin/systemctl";
  constexpr std::string_view systemd_run_path = "/usr/bin/systemd-run";
  constexpr std::string_view display_prepare_path =
    "/usr/libexec/stationconnect/stationconnect-display-prepare";
  constexpr std::string_view xrandr_path = "/usr/bin/xrandr";
  constexpr std::string_view display_overlay_path =
    "/etc/X11/xorg.conf.d/99-stationconnect-headless.conf";
  constexpr std::string_view stationconnect_config_path =
    "/etc/stationconnect/stationconnect.conf";

  struct account_t {
    uid_t uid {};
    gid_t gid {};
    std::string name;
    std::string home;
  };

  struct worker_t {
    pid_t pid {-1};
    int control_descriptor {-1};
    std::string session_id;
    std::uint64_t generation {};
  };

  std::optional<account_t> account_for_uid(uid_t uid) {
    constexpr std::size_t maximum_buffer = 1024U * 1024U;
    std::size_t size = 16384;
    std::vector<char> buffer(size);
    passwd record {};
    passwd *result = nullptr;
    while (true) {
      const int status = getpwuid_r(uid, &record, buffer.data(), buffer.size(), &result);
      if (status == 0 && result != nullptr) {
        return account_t {
          uid,
          record.pw_gid,
          record.pw_name == nullptr ? "" : record.pw_name,
          record.pw_dir == nullptr ? "" : record.pw_dir,
        };
      }
      if (status != ERANGE || buffer.size() >= maximum_buffer) {
        return std::nullopt;
      }
      buffer.resize(std::min(buffer.size() * 2, maximum_buffer));
    }
  }

  void set_environment_value(const char *name, const std::string &value) {
    if (!value.empty() && setenv(name, value.c_str(), 1) != 0) {
      std::cerr << "Unable to set " << name << ": " << std::strerror(errno) << '\n';
      std::_Exit(126);
    }
  }

  bool stage_pulse_cookie(const std::filesystem::path &source, uid_t uid) {
    constexpr off_t maximum_cookie_size = 4096;
    int source_descriptor = open(source.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source_descriptor < 0) return false;
    auto close_source = std::unique_ptr<int, std::function<void(int *)>> {
      &source_descriptor, [](int *descriptor) { close(*descriptor); }
    };

    struct stat source_status {};
    if (fstat(source_descriptor, &source_status) != 0 ||
        source_status.st_uid != uid || !S_ISREG(source_status.st_mode) ||
        source_status.st_size <= 0 || source_status.st_size > maximum_cookie_size) {
      return false;
    }

    int destination_descriptor = open(
      runtime_pulse_cookie.data(),
      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
      S_IRUSR | S_IWUSR
    );
    if (destination_descriptor < 0) return false;
    auto close_destination = std::unique_ptr<int, std::function<void(int *)>> {
      &destination_descriptor, [](int *descriptor) { close(*descriptor); }
    };
    if (fchmod(destination_descriptor, S_IRUSR | S_IWUSR) != 0) return false;

    std::array<char, 4096> buffer {};
    off_t copied = 0;
    while (copied < source_status.st_size) {
      const auto remaining = static_cast<std::size_t>(source_status.st_size - copied);
      const ssize_t received = read(
        source_descriptor, buffer.data(), std::min(buffer.size(), remaining)
      );
      if (received <= 0) return false;
      ssize_t offset = 0;
      while (offset < received) {
        const ssize_t written = write(
          destination_descriptor, buffer.data() + offset,
          static_cast<std::size_t>(received - offset)
        );
        if (written <= 0) return false;
        offset += written;
      }
      copied += received;
    }
    return fsync(destination_descriptor) == 0;
  }

  stationconnect::session::environment_t add_audio_environment(
    stationconnect::session::environment_t environment,
    const account_t &account
  ) {
    const std::filesystem::path pulse_socket =
      std::filesystem::path {environment.runtime_directory} / "pulse/native";
    const std::filesystem::path pulse_cookie =
      std::filesystem::path {account.home} / ".config/pulse/cookie";
    struct stat socket_status {};
    struct stat cookie_status {};
    if (lstat(pulse_socket.c_str(), &socket_status) == 0 &&
        socket_status.st_uid == account.uid && S_ISSOCK(socket_status.st_mode) &&
        lstat(pulse_cookie.c_str(), &cookie_status) == 0 &&
        cookie_status.st_uid == account.uid && S_ISREG(cookie_status.st_mode) &&
        stage_pulse_cookie(pulse_cookie, account.uid)) {
      environment.pulse_server = "unix:" + pulse_socket.string();
      environment.pulse_cookie = std::string {runtime_pulse_cookie};
    }
    return environment;
  }

  bool restrict_worker_capabilities() {
    __user_cap_header_struct header {
      _LINUX_CAPABILITY_VERSION_3,
      0,
    };
    std::array<__user_cap_data_struct, 2> capabilities {};
    constexpr auto capability = static_cast<unsigned int>(CAP_DAC_READ_SEARCH);
    constexpr auto word_bits = 32U;
    const auto mask = 1U << (capability % word_bits);
    capabilities[capability / word_bits].effective = mask;
    capabilities[capability / word_bits].permitted = mask;
    return syscall(SYS_capset, &header, capabilities.data()) == 0;
  }

  [[noreturn]] void launch_child(
    const std::filesystem::path &worker,
    const stationconnect::session::descriptor_t &session,
    const stationconnect::session::environment_t &environment,
    int control_descriptor,
    int supervisor_descriptor
  ) {
    close(supervisor_descriptor);
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() == 1) {
      std::_Exit(126);
    }
    sigset_t empty_mask;
    sigemptyset(&empty_mask);
    if (sigprocmask(SIG_SETMASK, &empty_mask, nullptr) != 0) {
      std::_Exit(126);
    }
    if (geteuid() != 0 || getegid() != 0) {
      std::cerr << "StationConnect machine worker lost root identity\n";
      std::_Exit(126);
    }
    if (!restrict_worker_capabilities()) {
      std::cerr << "Unable to restrict machine worker capabilities: "
                << std::strerror(errno) << '\n';
      std::_Exit(126);
    }

    const int descriptor_flags = fcntl(control_descriptor, F_GETFD);
    if (descriptor_flags < 0 ||
        fcntl(control_descriptor, F_SETFD, descriptor_flags & ~FD_CLOEXEC) != 0) {
      std::_Exit(126);
    }
    clearenv();
    set_environment_value("HOME", std::string {machine_home});
    set_environment_value("USER", "root");
    set_environment_value("LOGNAME", "root");
    set_environment_value("SHELL", "/bin/sh");
    set_environment_value("PATH", "/usr/local/bin:/usr/bin:/bin");
    set_environment_value("DISPLAY", environment.display);
    set_environment_value("XAUTHORITY", environment.xauthority);
    set_environment_value("XDG_RUNTIME_DIR", environment.runtime_directory);
    set_environment_value("XDG_SESSION_ID", session.id);
    set_environment_value("XDG_SESSION_TYPE", session.type);
    set_environment_value("XDG_SESSION_CLASS", session.session_class);
    set_environment_value("XDG_SEAT", session.seat);
    set_environment_value("DBUS_SESSION_BUS_ADDRESS", environment.dbus_address);
    set_environment_value("PULSE_SERVER", environment.pulse_server);
    set_environment_value("PULSE_COOKIE", environment.pulse_cookie);
    set_environment_value(
      "STATIONCONNECT_SESSION_CONTROL_FD", std::to_string(control_descriptor)
    );
    if (chdir(machine_home.data()) != 0) {
      std::cerr << "Unable to enter machine worker home directory\n";
      std::_Exit(126);
    }
    execl(worker.c_str(), worker.c_str(), static_cast<char *>(nullptr));
    std::cerr << "Unable to execute StationConnect worker: " << std::strerror(errno) << '\n';
    std::_Exit(127);
  }

  bool send_update(
    worker_t &worker,
    const stationconnect::session::descriptor_t &session,
    const stationconnect::session::environment_t &environment
  ) {
    const stationconnect::session::update_t update {
      worker.generation + 1, session, environment
    };
    const std::string message = stationconnect::session::session_update_message(update);
    if (message.empty()) {
      return false;
    }
    const ssize_t sent = send(
      worker.control_descriptor, message.data(), message.size(), MSG_NOSIGNAL
    );
    if (sent != static_cast<ssize_t>(message.size())) {
      return false;
    }
    pollfd response {worker.control_descriptor, POLLIN, 0};
    if (poll(&response, 1, 10000) != 1 || (response.revents & POLLIN) == 0) {
      return false;
    }
    std::array<char, 128> reply {};
    const ssize_t reply_size = recv(
      worker.control_descriptor, reply.data(), reply.size(), 0
    );
    const std::string expected =
      "SC-ACK-2\n" + std::to_string(update.generation) + "\nOK";
    if (reply_size != static_cast<ssize_t>(expected.size()) ||
        std::string_view {reply.data(), static_cast<std::size_t>(reply_size)} != expected) {
      return false;
    }
    worker.session_id = session.id;
    worker.generation = update.generation;
    return true;
  }

  worker_t launch_worker(
    const std::filesystem::path &worker,
    const stationconnect::session::descriptor_t &session,
    const stationconnect::session::environment_t &environment
  ) {
    int control_sockets[2] {-1, -1};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control_sockets) != 0) {
      return {};
    }
    const pid_t child = fork();
    if (child == 0) {
      launch_child(
        worker, session, environment, control_sockets[1], control_sockets[0]
      );
    }
    close(control_sockets[1]);
    if (child <= 0) {
      close(control_sockets[0]);
      return {};
    }
    worker_t result {child, control_sockets[0], {}, 0};
    if (!send_update(result, session, environment)) {
      kill(child, SIGKILL);
      waitpid(child, nullptr, 0);
      close(control_sockets[0]);
      return {};
    }
    return result;
  }

  void stop_worker(worker_t &worker) {
    if (worker.pid <= 0) {
      return;
    }
    kill(worker.pid, SIGTERM);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {10};
    while (std::chrono::steady_clock::now() < deadline) {
      const pid_t result = waitpid(worker.pid, nullptr, WNOHANG);
      if (result == worker.pid || (result < 0 && errno == ECHILD)) {
        close(worker.control_descriptor);
        worker = {};
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds {50});
    }
    kill(worker.pid, SIGKILL);
    waitpid(worker.pid, nullptr, 0);
    close(worker.control_descriptor);
    worker = {};
  }

  bool run_bounded_command(
    const std::filesystem::path &program,
    const std::vector<std::string> &arguments,
    std::chrono::seconds timeout
  ) {
    if (!program.is_absolute() || access(program.c_str(), X_OK) != 0) return false;
    const pid_t child = fork();
    if (child == 0) {
      std::vector<char *> command;
      command.reserve(arguments.size() + 2);
      command.push_back(const_cast<char *>(program.c_str()));
      for (const auto &argument : arguments) {
        command.push_back(const_cast<char *>(argument.c_str()));
      }
      command.push_back(nullptr);
      execv(program.c_str(), command.data());
      std::_Exit(127);
    }
    if (child <= 0) return false;

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    int status {};
    while (std::chrono::steady_clock::now() < deadline) {
      const pid_t result = waitpid(child, &status, WNOHANG);
      if (result == child) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
      if (result < 0 && errno != EINTR) return false;
      std::this_thread::sleep_for(std::chrono::milliseconds {50});
    }
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
    return false;
  }

  bool run_bounded_user_command(
    const std::filesystem::path &program,
    const std::vector<std::string> &arguments,
    std::chrono::seconds timeout,
    const account_t &account,
    const stationconnect::session::environment_t &environment
  ) {
    if (!program.is_absolute() || access(program.c_str(), X_OK) != 0 ||
        account.uid == 0 || account.name.empty()) return false;
    std::vector<std::string> transient_arguments {
      "--quiet", "--wait", "--collect", "--service-type=exec",
      "--uid=" + account.name,
      "--gid=" + std::to_string(account.gid),
      "--property=NoNewPrivileges=yes",
      "--property=ProtectSystem=strict",
      "--property=ProtectHome=yes",
      "--property=RestrictAddressFamilies=AF_UNIX",
      "--property=RuntimeMaxSec=" + std::to_string(timeout.count()) + "s",
      "--setenv=HOME=" + account.home,
      "--setenv=USER=" + account.name,
      "--setenv=LOGNAME=" + account.name,
      "--setenv=PATH=/usr/local/bin:/usr/bin:/bin",
      "--setenv=DISPLAY=" + environment.display,
      "--setenv=XAUTHORITY=" + environment.xauthority,
      "--setenv=XDG_RUNTIME_DIR=" + environment.runtime_directory,
      "--", program.string()
    };
    transient_arguments.insert(
      transient_arguments.end(), arguments.begin(), arguments.end()
    );
    return run_bounded_command(
      systemd_run_path, transient_arguments, timeout + std::chrono::seconds {2}
    );
  }

  bool apply_live_display_transition(
    const stationconnect::session::display_request_t &request,
    const stationconnect::session::descriptor_t &session,
    const stationconnect::session::environment_t &environment
  ) {
    const auto account = account_for_uid(session.uid);
    const auto first = stationconnect::topology::virtual_mode_size(request.mode_1);
    const auto second = stationconnect::topology::virtual_mode_size(request.mode_2);
    if (!account || first.width <= 0 || first.height <= 0 ||
        (request.layout == "dual-horizontal" &&
         (second.width <= 0 || second.height <= 0))) {
      return false;
    }

    const auto layout_arguments = [&](const std::string &mode_1,
                                      const std::string &mode_2) {
      std::vector<std::string> arguments {
        "--output", "DP-0", "--mode", mode_1, "--rate", "60",
        "--pos", "0x0", "--primary"
      };
      if (request.layout == "dual-horizontal") {
        arguments.insert(arguments.end(), {
          "--output", "DP-2", "--set", "non-desktop", "0",
          "--mode", mode_2, "--rate", "60",
          "--pos", std::to_string(first.width) + "x0"
        });
      } else {
        arguments.insert(arguments.end(), {
          "--output", "DP-2", "--off", "--set", "non-desktop", "1"
        });
      }
      return arguments;
    };

    // Every qualified mode is part of each virtual monitor's EDID. NVIDIA
    // validates this pool at Xorg startup, so live transitions never inject
    // or approve an ad hoc timing.
    return run_bounded_user_command(
      xrandr_path,
      layout_arguments(request.mode_1, request.mode_2),
      std::chrono::seconds {10}, *account, environment
    );
  }

  std::optional<bool> overlay_secondary_visibility() {
    constexpr std::size_t maximum_overlay_size = 64U * 1024U;
    std::ifstream input {display_overlay_path.data(), std::ios::binary};
    if (!input) return std::nullopt;
    std::string contents(
      std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {}
    );
    if (contents.size() > maximum_overlay_size) return std::nullopt;
    return stationconnect::session::secondary_output_visible_from_overlay(contents);
  }

  bool virtual_display_transitions_enabled() {
    return stationconnect::session::configured_display_policy(
             stationconnect_config_path
           ) == stationconnect::session::display_policy_t::virtual_outputs;
  }

  bool set_secondary_desktop_visibility(
    bool visible,
    const stationconnect::session::descriptor_t &session,
    const stationconnect::session::environment_t &environment
  ) {
    const auto account = account_for_uid(session.uid);
    if (!account) return false;
    const std::vector<std::string> arguments = visible ?
      std::vector<std::string> {"--output", "DP-2", "--set", "non-desktop", "0"} :
      std::vector<std::string> {
        "--output", "DP-2", "--off", "--set", "non-desktop", "1"
      };
    return run_bounded_user_command(
      xrandr_path, arguments, std::chrono::seconds {10}, *account, environment
    );
  }

  bool apply_display_transition(const stationconnect::session::display_request_t &request) {
    const bool stopped = run_bounded_command(
      systemctl_path, {"stop", "display-manager.service"}, std::chrono::seconds {30}
    );
    if (!stopped) {
      std::cerr << "Unable to stop the display manager for StationConnect topology transition\n";
      return false;
    }

    std::vector<std::string> prepare_arguments {
      "--layout", request.layout, "--mode-1", request.mode_1
    };
    if (!request.mode_2.empty()) {
      prepare_arguments.insert(
        prepare_arguments.end(), {"--mode-2", request.mode_2}
      );
    }
    const bool prepared = run_bounded_command(
      display_prepare_path, prepare_arguments, std::chrono::seconds {15}
    );
    const bool started = run_bounded_command(
      systemctl_path, {"start", "display-manager.service"}, std::chrono::seconds {30}
    );
    if (!prepared) {
      std::cerr << "StationConnect display preparation failed; restored the prior GDM topology\n";
    }
    if (!started) {
      std::cerr << "Unable to restart the display manager after StationConnect topology transition\n";
    }
    return prepared && started;
  }

  void usage(const char *program) {
    std::cerr << "usage: " << program << " [--worker ABSOLUTE_PATH]\n";
  }
}  // namespace

int main(int argc, char **argv) {
  std::filesystem::path worker_path {default_worker};
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument {argv[index]};
    if (argument == "--worker" && index + 1 < argc) {
      worker_path = argv[++index];
    } else {
      usage(argv[0]);
      return 2;
    }
  }
  if (geteuid() != 0) {
    std::cerr << "stationconnect-host-supervisor must run as root\n";
    return 3;
  }
  if (!worker_path.is_absolute() || access(worker_path.c_str(), X_OK) != 0) {
    std::cerr << "StationConnect worker is unavailable: " << worker_path << '\n';
    return 4;
  }
  sigset_t signal_mask;
  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, SIGTERM);
  sigaddset(&signal_mask, SIGINT);
  sigaddset(&signal_mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &signal_mask, nullptr) != 0) {
    return 6;
  }
  const int signal_fd = signalfd(-1, &signal_mask, SFD_CLOEXEC | SFD_NONBLOCK);
  if (signal_fd < 0) {
    return 7;
  }
  sd_login_monitor *raw_monitor = nullptr;
  if (sd_login_monitor_new("session", &raw_monitor) < 0 || raw_monitor == nullptr) {
    close(signal_fd);
    return 8;
  }
  std::unique_ptr<sd_login_monitor, decltype(&sd_login_monitor_unref)> monitor {
    raw_monitor, &sd_login_monitor_unref
  };

  worker_t worker;
  std::optional<stationconnect::session::display_request_t> pending_display_request;
  const auto initial_display_policy =
    stationconnect::session::configured_display_policy(stationconnect_config_path);
  const bool initial_virtual_display_policy =
    initial_display_policy == stationconnect::session::display_policy_t::virtual_outputs;
  if (initial_display_policy == stationconnect::session::display_policy_t::invalid) {
    std::cerr << "StationConnect display policy is invalid; virtual display transitions are disabled\n";
  }
  std::optional<bool> desired_secondary_visibility =
    initial_virtual_display_policy ? overlay_secondary_visibility() : std::nullopt;
  bool initial_secondary_visibility = desired_secondary_visibility.has_value();
  std::string visibility_session_id;
  auto display_request_deadline = std::chrono::steady_clock::time_point::max();
  std::string pending_session;
  auto next_launch = std::chrono::steady_clock::now();
  bool stopping = false;
  while (!stopping) {
    if (pending_display_request &&
        std::chrono::steady_clock::now() >= display_request_deadline) {
      const auto selected = stationconnect::session::active_seat0_graphical_session();
      if (!virtual_display_transitions_enabled()) {
        std::cerr << "Refusing StationConnect virtual display transition because the host is configured for physical displays\n";
      } else if (!selected || selected->id != worker.session_id) {
        std::cerr << "Refusing StationConnect display transition because the graphical session changed\n";
      } else if (selected->session_class == "greeter") {
        const auto request = std::move(*pending_display_request);
        std::clog << "Applying StationConnect display transition: "
                  << request.layout << ' ' << request.mode_1;
        if (!request.mode_2.empty()) std::clog << ' ' << request.mode_2;
        std::clog << '\n';
        stop_worker(worker);
        if (apply_display_transition(request)) {
          desired_secondary_visibility = request.layout == "dual-horizontal";
          visibility_session_id.clear();
          initial_secondary_visibility = false;
          std::clog << "StationConnect display transition completed\n";
        }
      } else if (selected->session_class == "user" &&
                 selected->uid == pending_display_request->account_uid) {
        const auto environment = stationconnect::session::discover_environment(*selected);
        if (!environment) {
          std::cerr << "Unable to discover the active user's X11 environment for a live display transition\n";
        } else if (apply_live_display_transition(
                     *pending_display_request, *selected, *environment
                   )) {
          desired_secondary_visibility =
            pending_display_request->layout == "dual-horizontal";
          visibility_session_id = selected->id;
          initial_secondary_visibility = false;
          std::clog << "StationConnect live display transition completed for UID "
                    << selected->uid << '\n';
        } else {
          std::cerr << "StationConnect live display transition failed for UID "
                    << selected->uid << '\n';
        }
      } else {
        std::cerr << "Refusing StationConnect display transition for a user other than the active desktop owner\n";
      }
      pending_display_request.reset();
      display_request_deadline = std::chrono::steady_clock::time_point::max();
      next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
      continue;
    }

    const auto selected = stationconnect::session::active_seat0_graphical_session();
    if (!selected) {
      pending_session.clear();
    } else if ((worker.pid <= 0 || worker.session_id != selected->id) &&
               std::chrono::steady_clock::now() >= next_launch) {
      const auto environment = stationconnect::session::discover_environment(*selected);
      const auto account = account_for_uid(selected->uid);
      if (!environment || !account || account->home.empty()) {
        if (pending_session != selected->id) {
          std::clog << "Waiting for graphical environment for seat0 session "
                    << selected->id << '\n';
          pending_session = selected->id;
        }
      } else {
        const auto confirmed = stationconnect::session::active_seat0_graphical_session();
        if (!confirmed || confirmed->id != selected->id || confirmed->uid != selected->uid) {
          continue;
        }
        const auto complete_environment = add_audio_environment(*environment, *account);
        if (desired_secondary_visibility && visibility_session_id != selected->id) {
          // An existing user X server retains this connector property across
          // a supervisor restart, so do not replace its live state with a
          // potentially older boot overlay. Once the supervisor has observed
          // or changed a visibility state, reapply it to every newly created
          // GDM or user X server before launching that session's worker.
          if (initial_secondary_visibility && selected->session_class == "user") {
            desired_secondary_visibility.reset();
            visibility_session_id.clear();
            initial_secondary_visibility = false;
          } else if (!set_secondary_desktop_visibility(
                       *desired_secondary_visibility, *selected, *environment
                     )) {
            std::cerr << "Unable to apply StationConnect secondary-monitor visibility\n";
            next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
            continue;
          } else {
            std::clog << "StationConnect secondary virtual monitor is "
                      << (*desired_secondary_visibility ? "available" : "hidden")
                      << " to the desktop\n";
            visibility_session_id = selected->id;
            initial_secondary_visibility = false;
          }
        }
        if (worker.pid > 0) {
          const auto previous_session = worker.session_id;
          std::clog << "Graphical session changed from " << previous_session
                    << " to " << selected->id
                    << "; restarting the StationConnect media worker for fresh X11/NvFBC state\n";
          stop_worker(worker);
        }
        if (worker.pid <= 0) {
          auto launched = launch_worker(worker_path, *selected, complete_environment);
          if (launched.pid > 0) {
            worker = std::move(launched);
            pending_session.clear();
            std::clog << "Attached persistent StationConnect machine worker to session "
                      << selected->id << ", UID " << selected->uid << '\n';
          } else {
            std::cerr << "Unable to fork StationConnect worker: " << std::strerror(errno) << '\n';
          }
        }
        if (worker.pid > 0) {
          pending_session.clear();
        }
        next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
      }
    }

    std::array<pollfd, 3> descriptors {{
      {signal_fd, POLLIN, 0},
      {sd_login_monitor_get_fd(monitor.get()), POLLIN, 0},
      {worker.control_descriptor, POLLIN, 0},
    }};
    const int status = poll(descriptors.data(), descriptors.size(), 1000);
    if (status < 0 && errno != EINTR) {
      std::cerr << "Supervisor poll failed: " << std::strerror(errno) << '\n';
      break;
    }
    if ((descriptors[1].revents & POLLIN) != 0) {
      sd_login_monitor_flush(monitor.get());
    }
    if ((descriptors[2].revents & POLLIN) != 0 && worker.pid > 0) {
      std::array<char, 8193> message {};
      const ssize_t size = recv(worker.control_descriptor, message.data(), message.size(), 0);
      const auto request = size > 0 ? stationconnect::session::parse_display_request(
        std::string_view {message.data(), static_cast<std::size_t>(size)}
      ) : std::nullopt;
      const auto active = stationconnect::session::active_seat0_graphical_session();
      if (!request) {
        std::cerr << "Rejected malformed StationConnect display transition request\n";
      } else if (!virtual_display_transitions_enabled()) {
        std::cerr << "Refused StationConnect virtual display transition because the host is configured for physical displays\n";
      } else if (!active || active->id != worker.session_id ||
                 (active->session_class == "user" &&
                  active->uid != request->account_uid) ||
                 (active->session_class != "greeter" &&
                  active->session_class != "user")) {
        std::cerr << "Refused StationConnect display transition outside an authorized graphical session\n";
      } else if (!pending_display_request) {
        pending_display_request = *request;
        // Allow the HTTPS worker to return its transition response before it
        // is stopped and GDM is restarted.
        display_request_deadline =
          std::chrono::steady_clock::now() + std::chrono::milliseconds {750};
        std::clog << "Scheduled StationConnect display transition from "
                  << (active->session_class == "greeter" ? "GDM" : "the active user desktop")
                  << '\n';
      }
    }
    if ((descriptors[0].revents & POLLIN) != 0) {
      signalfd_siginfo information {};
      while (read(signal_fd, &information, sizeof(information)) == sizeof(information)) {
        if (information.ssi_signo == SIGTERM || information.ssi_signo == SIGINT) {
          stopping = true;
        } else if (information.ssi_signo == SIGCHLD && worker.pid > 0) {
          const pid_t result = waitpid(worker.pid, nullptr, WNOHANG);
          if (result == worker.pid) {
            std::clog << "StationConnect worker exited; scheduling restart\n";
            close(worker.control_descriptor);
            worker = {};
            next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
          }
        }
      }
    }
  }

  stop_worker(worker);
  close(signal_fd);
  return 0;
}
