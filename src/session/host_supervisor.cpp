/**
 * @file src/session/host_supervisor.cpp
 * @brief Boot-time StationConnect graphical-session worker supervisor.
 */
#include "session_context.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <systemd/sd-login.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
  constexpr std::string_view default_worker = "/usr/bin/stationconnect-host";
  constexpr std::string_view auth_group = "stationconnect-auth";

  struct account_t {
    uid_t uid {};
    gid_t gid {};
    std::string name;
    std::string home;
    std::string shell;
  };

  struct worker_t {
    pid_t pid {-1};
    std::string session_id;
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
          record.pw_shell == nullptr ? "/bin/sh" : record.pw_shell,
        };
      }
      if (status != ERANGE || buffer.size() >= maximum_buffer) {
        return std::nullopt;
      }
      buffer.resize(std::min(buffer.size() * 2, maximum_buffer));
    }
  }

  std::optional<gid_t> group_id(std::string_view name) {
    const std::string group_name {name};
    constexpr std::size_t maximum_buffer = 1024U * 1024U;
    std::size_t size = 16384;
    std::vector<char> buffer(size);
    group record {};
    group *result = nullptr;
    while (true) {
      const int status = getgrnam_r(
        group_name.c_str(), &record, buffer.data(), buffer.size(), &result
      );
      if (status == 0 && result != nullptr) {
        return record.gr_gid;
      }
      if (status != ERANGE || buffer.size() >= maximum_buffer) {
        return std::nullopt;
      }
      buffer.resize(std::min(buffer.size() * 2, maximum_buffer));
    }
  }

  bool install_groups(const account_t &account, gid_t extra_group) {
    int count = 0;
    getgrouplist(account.name.c_str(), account.gid, nullptr, &count);
    if (count <= 0 || count > 4096) {
      return false;
    }
    std::vector<gid_t> groups(static_cast<std::size_t>(count));
    if (getgrouplist(account.name.c_str(), account.gid, groups.data(), &count) < 0) {
      return false;
    }
    groups.resize(static_cast<std::size_t>(count));
    if (std::ranges::find(groups, extra_group) == groups.end()) {
      groups.push_back(extra_group);
    }
    return setgroups(groups.size(), groups.data()) == 0;
  }

  void set_environment_value(const char *name, const std::string &value) {
    if (!value.empty() && setenv(name, value.c_str(), 1) != 0) {
      std::cerr << "Unable to set " << name << ": " << std::strerror(errno) << '\n';
      std::_Exit(126);
    }
  }

  [[noreturn]] void launch_child(
    const std::filesystem::path &worker,
    const stationconnect::session::descriptor_t &session,
    const stationconnect::session::environment_t &environment,
    const account_t &account,
    gid_t extra_group,
    int attestation_descriptor,
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
    if (!install_groups(account, extra_group) || setgid(account.gid) != 0 ||
        setuid(account.uid) != 0 || geteuid() == 0) {
      std::cerr << "Unable to drop worker privileges for UID " << account.uid << '\n';
      std::_Exit(126);
    }

    const char *host_options = getenv("STATIONCONNECT_HOST_OPTIONS");
    const std::string inherited_options = host_options == nullptr ? "" : host_options;
    const int descriptor_flags = fcntl(attestation_descriptor, F_GETFD);
    if (descriptor_flags < 0 ||
        fcntl(attestation_descriptor, F_SETFD, descriptor_flags & ~FD_CLOEXEC) != 0) {
      std::_Exit(126);
    }
    clearenv();
    set_environment_value("HOME", account.home);
    set_environment_value("USER", account.name);
    set_environment_value("LOGNAME", account.name);
    set_environment_value("SHELL", account.shell);
    set_environment_value("PATH", "/usr/local/bin:/usr/bin:/bin");
    set_environment_value("DISPLAY", environment.display);
    set_environment_value("XAUTHORITY", environment.xauthority);
    set_environment_value("XDG_RUNTIME_DIR", environment.runtime_directory);
    set_environment_value("XDG_SESSION_ID", session.id);
    set_environment_value("XDG_SESSION_TYPE", session.type);
    set_environment_value("XDG_SESSION_CLASS", session.session_class);
    set_environment_value("XDG_SEAT", session.seat);
    set_environment_value("DBUS_SESSION_BUS_ADDRESS", environment.dbus_address);
    set_environment_value("STATIONCONNECT_HOST_OPTIONS", inherited_options);
    set_environment_value(
      "STATIONCONNECT_SESSION_ATTESTATION_FD", std::to_string(attestation_descriptor)
    );
    if (chdir(account.home.c_str()) != 0) {
      std::cerr << "Unable to enter worker home directory\n";
      std::_Exit(126);
    }
    execl(worker.c_str(), worker.c_str(), static_cast<char *>(nullptr));
    std::cerr << "Unable to execute StationConnect worker: " << std::strerror(errno) << '\n';
    std::_Exit(127);
  }

  pid_t launch_worker(
    const std::filesystem::path &worker,
    const stationconnect::session::descriptor_t &session,
    const stationconnect::session::environment_t &environment,
    const account_t &account,
    gid_t extra_group
  ) {
    int attestation_sockets[2] {-1, -1};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, attestation_sockets) != 0) {
      return -1;
    }
    const std::string attestation = stationconnect::session::greeter_attestation_message(session);
    if (attestation.empty()) {
      close(attestation_sockets[0]);
      close(attestation_sockets[1]);
      return -1;
    }
    const pid_t child = fork();
    if (child == 0) {
      launch_child(
        worker, session, environment, account, extra_group,
        attestation_sockets[1], attestation_sockets[0]
      );
    }
    close(attestation_sockets[1]);
    if (child > 0) {
      const ssize_t sent = send(
        attestation_sockets[0], attestation.data(), attestation.size(), MSG_NOSIGNAL
      );
      if (sent != static_cast<ssize_t>(attestation.size())) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        close(attestation_sockets[0]);
        return -1;
      }
    }
    close(attestation_sockets[0]);
    return child;
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
        worker = {};
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds {50});
    }
    kill(worker.pid, SIGKILL);
    waitpid(worker.pid, nullptr, 0);
    worker = {};
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
  const auto extra_group = group_id(auth_group);
  if (!extra_group) {
    std::cerr << "Required group is unavailable: " << auth_group << '\n';
    return 5;
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
  std::string pending_session;
  auto next_launch = std::chrono::steady_clock::now();
  bool stopping = false;
  while (!stopping) {
    const auto selected = stationconnect::session::active_seat0_graphical_session();
    if (!selected) {
      if (worker.pid > 0) {
        std::clog << "Active seat0 graphical session ended; stopping worker\n";
        stop_worker(worker);
      }
      pending_session.clear();
    } else if (worker.pid > 0 && worker.session_id != selected->id) {
      std::clog << "Active seat0 session changed from " << worker.session_id << " to "
                << selected->id << "; stopping old worker\n";
      stop_worker(worker);
      next_launch = std::chrono::steady_clock::now();
    }

    if (selected && worker.pid <= 0 && std::chrono::steady_clock::now() >= next_launch) {
      const auto environment = stationconnect::session::discover_environment(*selected);
      const auto account = account_for_uid(selected->uid);
      if (!environment || !account || account->name.empty() || account->home.empty()) {
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
        const pid_t child = launch_worker(
          worker_path, *selected, *environment, *account, *extra_group
        );
        if (child > 0) {
          worker = {child, selected->id};
          pending_session.clear();
          std::clog << "Started unprivileged StationConnect worker for session "
                    << selected->id << ", UID " << selected->uid << '\n';
        } else {
          std::cerr << "Unable to fork StationConnect worker: " << std::strerror(errno) << '\n';
        }
        next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
      }
    }

    std::array<pollfd, 2> descriptors {{
      {signal_fd, POLLIN, 0},
      {sd_login_monitor_get_fd(monitor.get()), POLLIN, 0},
    }};
    const int status = poll(descriptors.data(), descriptors.size(), 1000);
    if (status < 0 && errno != EINTR) {
      std::cerr << "Supervisor poll failed: " << std::strerror(errno) << '\n';
      break;
    }
    if ((descriptors[1].revents & POLLIN) != 0) {
      sd_login_monitor_flush(monitor.get());
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
