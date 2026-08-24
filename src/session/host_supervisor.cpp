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

#include <poll.h>
#include <pwd.h>
#include <systemd/sd-login.h>
#include <linux/capability.h>
#include <sys/prctl.h>
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

  struct account_t {
    uid_t uid {};
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
  std::string pending_session;
  auto next_launch = std::chrono::steady_clock::now();
  bool stopping = false;
  while (!stopping) {
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
