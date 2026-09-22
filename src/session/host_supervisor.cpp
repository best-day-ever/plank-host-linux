/**
 * @file src/session/host_supervisor.cpp
 * @brief Boot-time PLANK graphical-session worker supervisor.
 */
#include "display_inventory.h"
#include "display_metamode.h"
#include "session_context.h"
#include "worker_control.h"
#include "../plank_arrangement.h"
#include "../plank_topology.h"
#include "../auth/pam_broker_channel.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
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
  constexpr std::string_view default_worker = "/usr/bin/plank-host";
  constexpr std::string_view machine_home = "/var/lib/plank";
  constexpr std::string_view runtime_pulse_cookie =
    "/run/plank/host/pulse-cookie";
  constexpr std::string_view systemctl_path = "/usr/bin/systemctl";
  constexpr std::string_view systemd_run_path = "/usr/bin/systemd-run";
  constexpr std::string_view display_prepare_path =
    "/usr/libexec/plank/plank-display-prepare";
  constexpr std::string_view xrandr_path = "/usr/bin/xrandr";
  constexpr std::string_view nvidia_settings_path = "/usr/bin/nvidia-settings";
  constexpr std::string_view display_overlay_path =
    "/etc/X11/xorg.conf.d/99-plank-headless.conf";
  constexpr std::string_view plank_config_path =
    "/etc/plank/host.conf";
  constexpr std::string_view runtime_display_state_path =
    "/run/plank/host/display-state";

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
    int pam_descriptor {-1};  ///< Private descriptor-only broker delegation endpoint.
    bool greeter {false};
  };

  using plank::display::physical_snapshot_t;

  struct physical_display_lease_t {
    uid_t uid {};
    plank::session::display_request_t request;
    std::string session_id;
    physical_snapshot_t snapshot;
    bool active {};
    std::chrono::steady_clock::time_point deadline;
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

  plank::session::environment_t add_audio_environment(
    plank::session::environment_t environment,
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
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment,
    int control_descriptor,
    int supervisor_descriptor,
    int pam_descriptor,
    int supervisor_pam_descriptor
  ) {
    close(supervisor_descriptor);
    close(supervisor_pam_descriptor);
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() == 1) {
      std::_Exit(126);
    }
    sigset_t empty_mask;
    sigemptyset(&empty_mask);
    if (sigprocmask(SIG_SETMASK, &empty_mask, nullptr) != 0) {
      std::_Exit(126);
    }
    if (geteuid() != 0 || getegid() != 0) {
      std::cerr << "PLANK machine worker lost root identity\n";
      std::_Exit(126);
    }
    if (!restrict_worker_capabilities()) {
      std::cerr << "Unable to restrict machine worker capabilities: "
                << std::strerror(errno) << '\n';
      std::_Exit(126);
    }

    for (const int descriptor : {control_descriptor, pam_descriptor}) {
      const int descriptor_flags = fcntl(descriptor, F_GETFD);
      if (descriptor_flags < 0 ||
          fcntl(descriptor, F_SETFD, descriptor_flags & ~FD_CLOEXEC) != 0) {
        std::_Exit(126);
      }
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
      "PLANK_SESSION_CONTROL_FD", std::to_string(control_descriptor)
    );
    set_environment_value(
      plank::auth::broker_channel::environment_name, std::to_string(pam_descriptor)
    );
    if (chdir(machine_home.data()) != 0) {
      std::cerr << "Unable to enter machine worker home directory\n";
      std::_Exit(126);
    }
    execl(worker.c_str(), worker.c_str(), static_cast<char *>(nullptr));
    std::cerr << "Unable to execute PLANK worker: " << std::strerror(errno) << '\n';
    std::_Exit(127);
  }

  bool send_update(
    worker_t &worker,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
  ) {
    const plank::session::update_t update {
      worker.generation + 1, session, environment
    };
    const std::string message = plank::session::session_update_message(update);
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
    worker.greeter = session.session_class == "greeter";
    return true;
  }

  worker_t launch_worker(
    const std::filesystem::path &worker,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
  ) {
    int control_sockets[2] {-1, -1};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control_sockets) != 0) {
      return {};
    }
    int pam_sockets[2] {-1, -1};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pam_sockets) != 0) {
      close(control_sockets[0]);
      close(control_sockets[1]);
      return {};
    }
    const pid_t child = fork();
    if (child == 0) {
      launch_child(
        worker, session, environment, control_sockets[1], control_sockets[0],
        pam_sockets[1], pam_sockets[0]
      );
    }
    close(control_sockets[1]);
    close(pam_sockets[1]);
    if (child <= 0) {
      close(control_sockets[0]);
      close(pam_sockets[0]);
      return {};
    }
    worker_t result {child, control_sockets[0], {}, 0, pam_sockets[0], false};
    if (!send_update(result, session, environment)) {
      kill(child, SIGKILL);
      waitpid(child, nullptr, 0);
      close(control_sockets[0]);
      close(pam_sockets[0]);
      return {};
    }
    return result;
  }

  void stop_worker(worker_t &worker, bool opening_desktop = false) {
    if (worker.pid <= 0) {
      return;
    }
    const auto command = plank::session::desktop_handoff_command;
    const bool notified = opening_desktop && worker.greeter &&
      send(worker.control_descriptor, command.data(), command.size(),
           MSG_NOSIGNAL | MSG_DONTWAIT) == static_cast<ssize_t>(command.size());
    // The private command lets the worker notify the client before issuing its
    // own normal SIGTERM. Failure retains ordinary shutdown and reconnect UI.
    if (!notified) kill(worker.pid, SIGTERM);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {10};
    while (std::chrono::steady_clock::now() < deadline) {
      const pid_t result = waitpid(worker.pid, nullptr, WNOHANG);
      if (result == worker.pid || (result < 0 && errno == ECHILD)) {
        close(worker.control_descriptor);
        close(worker.pam_descriptor);
        worker = {};
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds {50});
    }
    kill(worker.pid, SIGKILL);
    waitpid(worker.pid, nullptr, 0);
    close(worker.control_descriptor);
    close(worker.pam_descriptor);
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

  std::optional<std::string> run_bounded_command_capture(
    const std::filesystem::path &program,
    const std::vector<std::string> &arguments,
    std::chrono::seconds timeout
  ) {
    constexpr std::size_t maximum_output_size = 64U * 1024U;
    if (!program.is_absolute() || access(program.c_str(), X_OK) != 0) {
      return std::nullopt;
    }
    int output_pipe[2] {-1, -1};
    if (pipe2(output_pipe, O_CLOEXEC | O_NONBLOCK) != 0) return std::nullopt;
    const pid_t child = fork();
    if (child == 0) {
      close(output_pipe[0]);
      if (dup2(output_pipe[1], STDOUT_FILENO) < 0) std::_Exit(127);
      close(output_pipe[1]);
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
    close(output_pipe[1]);
    if (child <= 0) {
      close(output_pipe[0]);
      return std::nullopt;
    }

    std::string output;
    int status {};
    bool exited = false;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      std::array<char, 4096> buffer {};
      while (true) {
        const ssize_t size = read(output_pipe[0], buffer.data(), buffer.size());
        if (size > 0) {
          if (output.size() + static_cast<std::size_t>(size) > maximum_output_size) {
            kill(child, SIGKILL);
            waitpid(child, nullptr, 0);
            close(output_pipe[0]);
            return std::nullopt;
          }
          output.append(buffer.data(), static_cast<std::size_t>(size));
          continue;
        }
        if (size < 0 && errno != EAGAIN && errno != EINTR) {
          kill(child, SIGKILL);
          waitpid(child, nullptr, 0);
          close(output_pipe[0]);
          return std::nullopt;
        }
        break;
      }
      const pid_t result = waitpid(child, &status, WNOHANG);
      if (result == child) {
        exited = true;
        break;
      }
      if (result < 0 && errno != EINTR) break;
      pollfd descriptor {output_pipe[0], POLLIN, 0};
      poll(&descriptor, 1, 50);
    }
    if (!exited) {
      kill(child, SIGKILL);
      waitpid(child, nullptr, 0);
      close(output_pipe[0]);
      return std::nullopt;
    }
    std::array<char, 4096> tail {};
    while (true) {
      const ssize_t size = read(output_pipe[0], tail.data(), tail.size());
      if (size <= 0) break;
      if (output.size() + static_cast<std::size_t>(size) > maximum_output_size) {
        close(output_pipe[0]);
        return std::nullopt;
      }
      output.append(tail.data(), static_cast<std::size_t>(size));
    }
    close(output_pipe[0]);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ?
      std::optional<std::string> {std::move(output)} : std::nullopt;
  }

  bool run_bounded_user_command(
    const std::filesystem::path &program,
    const std::vector<std::string> &arguments,
    std::chrono::seconds timeout,
    const account_t &account,
    const plank::session::environment_t &environment
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

  std::optional<std::string> run_bounded_user_command_capture(
    const std::filesystem::path &program,
    const std::vector<std::string> &arguments,
    std::chrono::seconds timeout,
    const account_t &account,
    const plank::session::environment_t &environment
  ) {
    if (!program.is_absolute() || access(program.c_str(), X_OK) != 0 ||
        account.uid == 0 || account.name.empty()) return std::nullopt;
    std::vector<std::string> transient_arguments {
      "--quiet", "--pipe", "--wait", "--collect", "--service-type=exec",
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
    return run_bounded_command_capture(
      systemd_run_path, transient_arguments, timeout + std::chrono::seconds {2}
    );
  }

  std::optional<physical_snapshot_t> capture_physical_snapshot(
    const account_t &account,
    const plank::session::environment_t &environment
  ) {
    const auto response = run_bounded_user_command_capture(
      nvidia_settings_path, {"--query", "CurrentMetaMode", "--terse"},
      std::chrono::seconds {10}, account, environment
    );
    return response ? plank::display::parse_current_metamode(*response) : std::nullopt;
  }

  bool assign_metamode(
    std::string_view assignment,
    const account_t &account,
    const plank::session::environment_t &environment
  ) {
    return !assignment.empty() && run_bounded_user_command(
      nvidia_settings_path,
      {"--assign", "CurrentMetaMode=" + std::string {assignment}},
      std::chrono::seconds {10}, account, environment
    );
  }

  bool write_runtime_display_state(
    const plank::session::runtime_display_state_t &state
  ) {
    const std::string contents =
      plank::session::runtime_display_state_message(state);
    if (contents.empty()) return false;
    const std::string temporary = std::string {runtime_display_state_path} +
      ".tmp." + std::to_string(getpid());
    const int descriptor = open(
      temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
      S_IRUSR | S_IWUSR
    );
    if (descriptor < 0) return false;
    ssize_t offset = 0;
    while (offset < static_cast<ssize_t>(contents.size())) {
      const ssize_t written = write(
        descriptor, contents.data() + offset, contents.size() - offset
      );
      if (written <= 0) break;
      offset += written;
    }
    const bool complete = offset == static_cast<ssize_t>(contents.size()) &&
      fsync(descriptor) == 0 && close(descriptor) == 0 &&
      rename(temporary.c_str(), runtime_display_state_path.data()) == 0;
    if (!complete) {
      close(descriptor);
      unlink(temporary.c_str());
    }
    return complete;
  }

  void clear_runtime_display_state() {
    if (unlink(runtime_display_state_path.data()) != 0 && errno != ENOENT) {
      std::cerr << "Unable to remove the PLANK runtime display state: "
                << std::strerror(errno) << '\n';
    }
  }

  /**
   * Apply a temporary physical-display lease. `retained` is the snapshot of an
   * existing lease on the same X server: a second acquire must restore the
   * original layout, never the first lease's temporary MetaMode.
   */
  bool apply_physical_lease(
    physical_display_lease_t &lease,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment,
    const physical_snapshot_t *retained = nullptr
  ) {
    const auto account = account_for_uid(session.uid);
    if (!account) return false;
    const auto captured = retained != nullptr ? std::nullopt :
      capture_physical_snapshot(*account, environment);
    if (retained == nullptr && !captured) {
      std::cerr << "Unable to capture the physical NVIDIA MetaMode before the PLANK session\n";
      return false;
    }
    const auto plan = plank::display::plan_physical_lease(
      retained, captured, lease.request.layout, lease.request.mode_1, lease.request.mode_2
    );
    if (!plan || !assign_metamode(plan->temporary, *account, environment)) {
      std::cerr << "Unable to apply the temporary PLANK physical-display layout\n";
      return false;
    }
    if (!write_runtime_display_state({
          lease.request.layout, lease.request.mode_1, lease.request.mode_2,
          lease.uid
        })) {
      assign_metamode(plan->snapshot.assignment, *account, environment);
      std::cerr << "Unable to publish the temporary PLANK display state; restored the physical layout\n";
      return false;
    }
    lease.session_id = session.id;
    lease.snapshot = plan->snapshot;
    return true;
  }

  bool restore_physical_lease(
    const physical_display_lease_t &lease,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
  ) {
    const auto account = account_for_uid(session.uid);
    if (!account) return false;
    if (assign_metamode(lease.snapshot.assignment, *account, environment)) {
      clear_runtime_display_state();
      std::clog << "Restored the exact pre-session physical NVIDIA MetaMode\n";
      return true;
    }
    const auto fallback = plank::display::safe_physical_metamode(lease.snapshot);
    const bool recovered = !fallback.empty() &&
      assign_metamode(fallback, *account, environment);
    clear_runtime_display_state();
    std::cerr << "ERROR: Exact PLANK physical-display restoration failed; "
              << (recovered ? "enabled one safe native physical output" :
                              "safe physical-output recovery also failed")
              << '\n';
    return recovered;
  }

  bool apply_live_display_transition(
    const plank::session::display_request_t &request,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
  ) {
    const auto account = account_for_uid(session.uid);
    const auto first = plank::topology::virtual_mode_size(request.mode_1);
    const auto second = plank::topology::virtual_mode_size(request.mode_2);
    if (!account || first.width <= 0 || first.height <= 0 ||
        (request.layout == "dual-horizontal" &&
         (second.width <= 0 || second.height <= 0))) {
      return false;
    }

    const auto layout_arguments = [&](const std::string &mode_1,
                                      const std::string &mode_2) {
      const int canvas_width = first.width +
        (request.layout == "dual-horizontal" ? second.width : 0);
      const int canvas_height = request.layout == "dual-horizontal" ?
        std::max(first.height, second.height) : first.height;
      std::vector<std::string> arguments {
        "--fb", std::to_string(canvas_width) + "x" + std::to_string(canvas_height),
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
    return plank::session::secondary_output_visible_from_overlay(contents);
  }

  bool set_secondary_desktop_visibility(
    bool visible,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
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

  bool apply_display_transition(const plank::session::display_request_t &request) {
    const bool stopped = run_bounded_command(
      systemctl_path, {"stop", "display-manager.service"}, std::chrono::seconds {30}
    );
    if (!stopped) {
      std::cerr << "Unable to stop the display manager for PLANK topology transition\n";
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
      std::cerr << "PLANK display preparation failed; restored the prior GDM topology\n";
    }
    if (!started) {
      std::cerr << "Unable to restart the display manager after PLANK topology transition\n";
    }
    return prepared && started;
  }

  // --- display inventory, hybrid policy and arrangement leases ---------------

  constexpr std::string_view runtime_display_transition_path =
    "/run/plank/host/display-transition";
  constexpr std::string_view hybrid_restart_marker_path =
    "/run/plank/host/display-hybrid-restart";
  constexpr std::string_view nvidia_pci_driver_path = "/sys/bus/pci/drivers/nvidia";
  constexpr std::string_view nvidia_version_path = "/sys/module/nvidia/version";
  // Hardware probe P2: non-desktop works on physical outputs too, so outputs a
  // lease switches off also leave the desktop, and come back at restore.
  constexpr bool hide_unused_physical_outputs = true;
  constexpr auto lease_command_timeout = std::chrono::seconds {10};

  /**
   * One arrangement lease: the canonical request, the exact pre-lease
   * MetaMode and every output's pre-lease visibility (SC-DISPLAY-STATE-2).
   */
  struct arrangement_lease_t {
    uid_t uid {};
    std::string session_id;
    std::string display;
    std::string origin {"arrangement"};
    std::string layout;
    std::string mode_1;
    std::string mode_2;
    std::string request;
    physical_snapshot_t snapshot;
    std::vector<plank::session::runtime_display_output_t> outputs;
    bool active {};
    std::chrono::steady_clock::time_point deadline;
  };

  bool write_root_file(std::string_view path, std::string_view contents) {
    if (contents.empty()) return false;
    const std::string temporary = std::string {path} + ".tmp." + std::to_string(getpid());
    const int descriptor = open(
      temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR
    );
    if (descriptor < 0) return false;
    ssize_t offset = 0;
    while (offset < static_cast<ssize_t>(contents.size())) {
      const ssize_t written = write(descriptor, contents.data() + offset, contents.size() - offset);
      if (written <= 0) break;
      offset += written;
    }
    const bool complete = offset == static_cast<ssize_t>(contents.size()) &&
      fchmod(descriptor, S_IRUSR | S_IWUSR) == 0 && fsync(descriptor) == 0 &&
      close(descriptor) == 0 && rename(temporary.c_str(), std::string {path}.c_str()) == 0;
    if (!complete) {
      close(descriptor);
      unlink(temporary.c_str());
    }
    return complete;
  }

  void remove_root_file(std::string_view path) {
    if (unlink(std::string {path}.c_str()) != 0 && errno != ENOENT) {
      std::cerr << "Unable to remove " << path << ": " << std::strerror(errno) << '\n';
    }
  }

  void write_transition(std::string_view state, std::string_view reason,
                        std::string_view request, uid_t uid) {
    const auto message = plank::session::display_transition_message({
      std::string {state}, std::string {reason}, std::string {request}, uid,
      static_cast<std::int64_t>(std::time(nullptr)),
    });
    if (message.empty() || !write_root_file(runtime_display_transition_path, message)) {
      std::cerr << "Unable to publish the PLANK display transition state\n";
    }
  }

  void clear_transition() {
    remove_root_file(runtime_display_transition_path);
  }

  std::optional<std::string> live_gpu_bus_id() {
    std::error_code error;
    std::optional<std::string> result;
    for (const auto &entry : std::filesystem::directory_iterator(nvidia_pci_driver_path, error)) {
      const auto bus = plank::display::xorg_bus_id(entry.path().filename().string());
      if (!bus) continue;
      if (result) return std::nullopt;  // More than one NVIDIA GPU.
      result = bus;
    }
    return error ? std::nullopt : result;
  }

  std::optional<std::string> nvidia_driver_version() {
    std::ifstream input {std::string {nvidia_version_path}};
    std::string version;
    if (!input || !std::getline(input, version)) return std::nullopt;
    while (!version.empty() && (version.back() == ' ' || version.back() == '\n')) version.pop_back();
    return version.empty() ? std::nullopt : std::optional {version};
  }

  std::optional<std::string> read_overlay() {
    constexpr std::size_t maximum_overlay_size = 64U * 1024U;
    std::ifstream input {display_overlay_path.data(), std::ios::binary};
    if (!input) return std::nullopt;
    std::string contents(std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {});
    if (contents.size() > maximum_overlay_size) return std::nullopt;
    return contents;
  }

  std::optional<plank::display::randr_screen_t> capture_randr(
    const account_t &account, const plank::session::environment_t &environment
  ) {
    const auto response = run_bounded_user_command_capture(
      xrandr_path, {"--verbose", "--prop"}, lease_command_timeout, account, environment
    );
    return response ? plank::display::parse_randr_verbose(*response) : std::nullopt;
  }

  /** Two identical `xrandr --verbose` reads 300 ms apart, for at most three seconds. */
  bool settle_randr(const account_t &account, const plank::session::environment_t &environment) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {3};
    std::optional<std::string> previous;
    while (std::chrono::steady_clock::now() < deadline) {
      auto current = run_bounded_user_command_capture(
        xrandr_path, {"--verbose"}, std::chrono::seconds {3}, account, environment
      );
      if (current && previous && *current == *previous) return true;
      previous = std::move(current);
      std::this_thread::sleep_for(std::chrono::milliseconds {300});
    }
    return false;
  }

  std::optional<plank::display::inventory_t> capture_inventory(
    const account_t &account,
    const plank::session::environment_t &environment,
    std::string_view policy
  ) {
    const auto bus = live_gpu_bus_id();
    const auto driver = nvidia_driver_version();
    if (!bus || !driver) return std::nullopt;
    const auto devices = run_bounded_user_command_capture(
      nvidia_settings_path, {"--query", "dpys", "--verbose"}, lease_command_timeout, account,
      environment
    );
    const auto screen = capture_randr(account, environment);
    if (!devices || !screen) return std::nullopt;
    const auto overlay = read_overlay();
    return plank::display::build_inventory(
      plank::display::parse_display_devices(*devices), *screen, *bus, *driver, policy,
      overlay ? plank::display::parse_overlay_facts(*overlay) : std::nullopt
    );
  }

  bool write_inventory(const plank::display::inventory_t &inventory) {
    return write_root_file(plank::display::inventory_path,
                           plank::display::inventory_message(inventory));
  }

  /** Fingerprints the greeter was already restarted for, surviving a supervisor restart. */
  std::set<std::string> read_hybrid_restarts() {
    std::set<std::string> fingerprints;
    std::ifstream input {std::string {hybrid_restart_marker_path}};
    std::string line;
    while (fingerprints.size() < 64 && std::getline(input, line)) {
      if (line.size() == 64) fingerprints.insert(line);
    }
    return fingerprints;
  }

  void write_hybrid_restarts(const std::set<std::string> &fingerprints) {
    std::string contents;
    for (const auto &fingerprint : fingerprints) contents += fingerprint + "\n";
    if (!write_root_file(hybrid_restart_marker_path, contents)) {
      std::cerr << "Unable to record the PLANK hybrid greeter restart\n";
    }
  }

  /** Stop GDM, rebuild the boot overlay from the display inventory, start GDM. */
  bool restart_greeter_with_boot_overlay() {
    const bool stopped = run_bounded_command(
      systemctl_path, {"stop", "display-manager.service"}, std::chrono::seconds {30}
    );
    if (!stopped) {
      std::cerr << "Unable to stop the display manager to apply the PLANK hybrid layout\n";
      return false;
    }
    const bool prepared = run_bounded_command(display_prepare_path, {}, std::chrono::seconds {15});
    const bool started = run_bounded_command(
      systemctl_path, {"start", "display-manager.service"}, std::chrono::seconds {30}
    );
    if (!prepared) std::cerr << "PLANK hybrid display preparation failed\n";
    if (!started) std::cerr << "Unable to restart the display manager after PLANK hybrid preparation\n";
    return prepared && started;
  }

  /**
   * Hybrid: hide the reserved virtual heads on a new X server as early as
   * possible (gnome-shell otherwise lays out every connected head), then
   * reassert the boot MetaMode if the physical desktop was disturbed.
   */
  void hide_virtual_heads(
    const plank::display::inventory_t &inventory,
    const plank::session::descriptor_t &session,
    const account_t &account,
    const plank::session::environment_t &environment
  ) {
    const auto arguments = plank::display::hide_virtual_head_arguments(inventory);
    if (arguments.empty()) return;
    if (!run_bounded_user_command(xrandr_path, arguments, lease_command_timeout, account, environment)) {
      std::cerr << "Unable to hide the PLANK virtual heads\n";
      return;
    }
    const auto current = capture_physical_snapshot(account, environment);
    if (current && !plank::display::rest_needed(*current, inventory, session.session_class == "greeter")) {
      return;
    }
    const auto boot = plank::display::boot_metamode(inventory);
    if (!boot.empty() && assign_metamode(boot, account, environment)) {
      std::clog << "Reasserted the PLANK boot display layout after hiding the virtual heads\n";
    } else {
      std::cerr << "Unable to reassert the PLANK boot display layout\n";
    }
  }

  bool write_arrangement_state(const arrangement_lease_t &lease) {
    plank::session::runtime_display_state_2_t state;
    state.lease_uid = lease.uid;
    state.session_id = lease.session_id;
    state.display = lease.display;
    state.origin = lease.origin;
    state.layout = lease.layout;
    state.mode_1 = lease.mode_1;
    state.mode_2 = lease.mode_2;
    state.request = lease.request;
    state.outputs = lease.outputs;
    state.snapshot = lease.snapshot.assignment;
    return write_root_file(runtime_display_state_path,
                           plank::session::runtime_display_state_2_message(state));
  }

  /**
   * End an arrangement lease on its X server: visibility back first, then the
   * exact snapshot, verified; else the first physical output at its native mode.
   */
  bool restore_arrangement_lease(
    const arrangement_lease_t &lease,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment,
    const std::optional<plank::display::inventory_t> &inventory
  ) {
    const auto account = account_for_uid(session.uid);
    if (!account) {
      clear_runtime_display_state();
      return false;
    }
    std::vector<std::string> visibility;
    for (const auto &output : lease.outputs) {
      if (output.non_desktop_before == 0) {
        visibility.insert(visibility.end(), {"--output", output.randr, "--set", "non-desktop", "0"});
      } else if (output.non_desktop_before == 1) {
        visibility.insert(visibility.end(), {"--output", output.randr, "--off", "--set", "non-desktop", "1"});
      }
    }
    if (!visibility.empty() &&
        !run_bounded_user_command(xrandr_path, visibility, lease_command_timeout, *account, environment)) {
      std::cerr << "Unable to restore the pre-session PLANK output visibility\n";
    }
    settle_randr(*account, environment);
    bool exact = assign_metamode(lease.snapshot.assignment, *account, environment);
    if (exact) {
      const auto restored = capture_physical_snapshot(*account, environment);
      exact = restored && restored->assignment == lease.snapshot.assignment;
    }
    clear_runtime_display_state();
    if (exact) {
      std::clog << "Restored the exact pre-session NVIDIA MetaMode\n";
      return true;
    }
    const auto fallback = inventory ? plank::display::rest_metamode(*inventory) :
                                      plank::display::safe_physical_metamode(lease.snapshot);
    const bool recovered = !fallback.empty() && assign_metamode(fallback, *account, environment);
    std::cerr << "ERROR: Exact PLANK display restoration failed; "
              << (recovered ? "enabled the first physical output at its native mode" :
                              "physical-output recovery also failed")
              << '\n';
    return recovered;
  }

  /**
   * Apply an arrangement lease as the session user: snapshot (first acquire
   * only), visibility first, settle, one CurrentMetaMode, primary, verify
   * (retry once). Any failure restores the snapshot.
   *
   * @return An empty string on success, else a short failure reason.
   */
  std::string apply_arrangement_lease(
    arrangement_lease_t &lease,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment,
    const plank::display::inventory_t &inventory,
    const arrangement_lease_t *retained
  ) {
    namespace arrangement = plank::arrangement;
    const auto account = account_for_uid(session.uid);
    if (!account) return "unavailable";
    const auto capabilities = plank::display::capabilities_from_inventory(inventory, {});
    const auto result = arrangement::evaluate(lease.request, capabilities);
    if (!result.resolution) return std::string {arrangement::error_code(result.error)};
    std::string reason;
    const auto plan = plank::display::plan_arrangement(*result.resolution, inventory, reason);
    if (!plan) return reason;

    std::map<std::string, int> before;
    if (retained != nullptr) {
      lease.snapshot = retained->snapshot;
      for (const auto &output : retained->outputs) before[output.randr] = output.non_desktop_before;
    } else {
      const auto snapshot = capture_physical_snapshot(*account, environment);
      if (!snapshot) {
        std::cerr << "Unable to capture the NVIDIA MetaMode before the PLANK display arrangement\n";
        return "snapshot_failed";
      }
      lease.snapshot = *snapshot;
    }
    if (std::any_of(plan->outputs.begin(), plan->outputs.end(),
                    [&](const auto &output) { return !before.contains(output.randr); })) {
      const auto screen = capture_randr(*account, environment);
      for (const auto &output : plan->outputs) {
        if (before.contains(output.randr)) continue;
        int value = -1;
        if (screen) {
          for (const auto &live : screen->outputs) {
            if (live.name == output.randr && live.non_desktop) value = *live.non_desktop ? 1 : 0;
          }
        }
        before[output.randr] = value;
      }
    }
    lease.outputs.clear();
    for (const auto &output : plan->outputs) {
      lease.outputs.push_back({
        output.randr, output.dpy, output.backing, output.mode, output.index,
        output.rect.x, output.rect.y, output.rect.width, output.rect.height,
        before[output.randr],
      });
    }
    lease.session_id = session.id;
    lease.display = environment.display;

    if (!run_bounded_user_command(
          xrandr_path, plank::display::visibility_arguments(*plan, hide_unused_physical_outputs),
          lease_command_timeout, *account, environment
        )) {
      restore_arrangement_lease(lease, session, environment, inventory);
      return "visibility_failed";
    }
    if (!settle_randr(*account, environment)) {
      std::cerr << "PLANK outputs did not settle within three seconds; applying the arrangement anyway\n";
    }
    bool live = false;
    for (int attempt = 0; attempt < 2 && !live; ++attempt) {
      if (!assign_metamode(plan->metamode, *account, environment)) continue;
      run_bounded_user_command(
        xrandr_path, {"--output", plan->primary, "--primary"}, lease_command_timeout, *account,
        environment
      );
      settle_randr(*account, environment);
      const auto screen = capture_randr(*account, environment);
      live = screen && plank::display::arrangement_live(*screen, *plan);
      if (!live) std::cerr << "PLANK display arrangement did not verify (attempt " << attempt + 1 << ")\n";
    }
    if (!live) {
      restore_arrangement_lease(lease, session, environment, inventory);
      return "verify_failed";
    }
    if (!write_arrangement_state(lease)) {
      restore_arrangement_lease(lease, session, environment, inventory);
      return "state_failed";
    }
    return {};
  }

  /** Recover a supervisor-owned STATE-2 left by a previous supervisor on the same X server. */
  void recover_stale_arrangement(
    const plank::session::runtime_display_state_2_t &state,
    const plank::session::descriptor_t &session,
    const plank::session::environment_t &environment
  ) {
    if (state.session_id != session.id || state.display != environment.display) {
      clear_runtime_display_state();
      std::clog << "Discarded a stale PLANK display arrangement from an X server that has ended\n";
      return;
    }
    arrangement_lease_t lease;
    lease.uid = state.lease_uid;
    lease.session_id = state.session_id;
    lease.display = state.display;
    lease.request = state.request;
    lease.outputs = state.outputs;
    lease.snapshot.assignment = state.snapshot;
    if (const auto parsed = plank::display::parse_current_metamode(":: " + state.snapshot)) {
      lease.snapshot = *parsed;
    }
    restore_arrangement_lease(lease, session, environment, plank::display::read_inventory());
    std::clog << "Recovered a stale PLANK display arrangement\n";
  }

  std::string legacy_arrangement(const plank::session::display_request_t &request) {
    const auto legacy = plank::arrangement::from_legacy(request.layout, request.mode_1, request.mode_2);
    return legacy ? plank::arrangement::serialize(*legacy) : std::string {};
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
    std::cerr << "plank-host-supervisor must run as root\n";
    return 3;
  }
  if (!worker_path.is_absolute() || access(worker_path.c_str(), X_OK) != 0) {
    std::cerr << "PLANK worker is unavailable: " << worker_path << '\n';
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
  std::optional<plank::session::display_request_t> pending_display_request;
  std::optional<physical_display_lease_t> physical_display_lease;
  std::optional<arrangement_lease_t> arrangement_lease;
  const auto startup_layout =
    plank::session::configured_startup_layout(plank_config_path);
  const bool physical_startup =
    startup_layout == plank::session::startup_layout_t::physical;
  const bool hybrid_startup =
    startup_layout == plank::session::startup_layout_t::hybrid;
  const bool virtual_startup =
    startup_layout == plank::session::startup_layout_t::virtual_display;
  // Physical and hybrid hosts keep a display inventory and accept arrangements.
  const bool arrangement_startup = physical_startup || hybrid_startup;
  const std::string_view startup_policy = hybrid_startup ? "hybrid" : "physical";
  if (startup_layout == plank::session::startup_layout_t::invalid) {
    std::cerr << "PLANK startup display policy is invalid; display transitions are disabled\n";
  }
  // STATE-1 is still recovered for one release after arrangement leases.
  bool recover_stale_runtime_state = arrangement_startup &&
    plank::session::read_runtime_display_state(
      runtime_display_state_path
    ).has_value();
  auto stale_arrangement = arrangement_startup ?
    plank::session::read_runtime_display_state_2(runtime_display_state_path) : std::nullopt;
  std::optional<plank::display::inventory_t> inventory;
  std::string inventory_session_id;
  auto hybrid_restarts = read_hybrid_restarts();
  // A pending or failed transition belongs to the previous supervisor.
  clear_transition();
  std::optional<bool> desired_secondary_visibility =
    virtual_startup ? overlay_secondary_visibility() : std::nullopt;
  bool initial_secondary_visibility = desired_secondary_visibility.has_value();
  std::string visibility_session_id;
  auto display_request_deadline = std::chrono::steady_clock::time_point::max();
  std::string pending_session;
  auto next_launch = std::chrono::steady_clock::now();
  bool stopping = false;
  while (!stopping) {
    if (physical_display_lease && !physical_display_lease->active &&
        std::chrono::steady_clock::now() >= physical_display_lease->deadline) {
      const auto selected = plank::session::active_seat0_graphical_session();
      const auto environment = selected &&
        selected->id == physical_display_lease->session_id ?
          plank::session::discover_environment(*selected) : std::nullopt;
      if (selected && environment) {
        restore_physical_lease(*physical_display_lease, *selected, *environment);
      } else {
        clear_runtime_display_state();
        std::cerr << "Temporary PLANK display lease expired after its X server disappeared\n";
      }
      physical_display_lease.reset();
    }

    if (arrangement_lease && !arrangement_lease->active &&
        std::chrono::steady_clock::now() >= arrangement_lease->deadline) {
      const auto selected = plank::session::active_seat0_graphical_session();
      const auto environment = selected && selected->id == arrangement_lease->session_id ?
        plank::session::discover_environment(*selected) : std::nullopt;
      if (selected && environment) {
        restore_arrangement_lease(*arrangement_lease, *selected, *environment, inventory);
      } else {
        clear_runtime_display_state();
        std::cerr << "PLANK display arrangement lease expired after its X server disappeared\n";
      }
      arrangement_lease.reset();
    }

    if (pending_display_request &&
        std::chrono::steady_clock::now() >= display_request_deadline) {
      const auto selected = plank::session::active_seat0_graphical_session();
      const auto canonical = !pending_display_request->arrangement.empty() ?
        pending_display_request->arrangement : legacy_arrangement(*pending_display_request);
      const auto request_uid = pending_display_request->account_uid;
      // Hybrid hosts serve legacy single/dual requests with the arrangement engine.
      const bool engine = !pending_display_request->arrangement.empty() || hybrid_startup;
      if (!selected || selected->id != worker.session_id) {
        std::cerr << "Refusing PLANK display transition because the graphical session changed\n";
        if (!canonical.empty() && arrangement_startup) {
          write_transition("failed", "unavailable", canonical, request_uid);
        }
      } else if (engine && arrangement_startup) {
        const auto environment = plank::session::discover_environment(*selected);
        std::string reason;
        if (!environment) {
          reason = "unavailable";
        } else if ((arrangement_lease && arrangement_lease->uid != request_uid) ||
                   (physical_display_lease && physical_display_lease->uid != request_uid)) {
          reason = "busy";
        } else if (!inventory || inventory_session_id != selected->id) {
          reason = "no_inventory";
        } else if (canonical.empty()) {
          reason = "malformed";
        } else {
          if (physical_display_lease) {
            // One lease kind at a time: end the legacy physical lease first.
            if (physical_display_lease->session_id == selected->id) {
              restore_physical_lease(*physical_display_lease, *selected, *environment);
            } else {
              clear_runtime_display_state();
            }
            physical_display_lease.reset();
          }
          arrangement_lease_t lease;
          lease.uid = request_uid;
          lease.request = canonical;
          if (pending_display_request->arrangement.empty()) {
            lease.origin = "legacy";
            lease.layout = pending_display_request->layout;
            lease.mode_1 = pending_display_request->mode_1;
            lease.mode_2 = pending_display_request->mode_2;
          }
          lease.deadline = std::chrono::steady_clock::now() + std::chrono::seconds {45};
          const arrangement_lease_t *retained =
            arrangement_lease && arrangement_lease->session_id == selected->id ?
              &*arrangement_lease : nullptr;
          if (retained != nullptr) {
            // Re-acquire: keep the lease active while its stream runs.
            lease.active = retained->active;
            if (lease.active) lease.deadline = std::chrono::steady_clock::time_point::max();
          }
          reason = apply_arrangement_lease(lease, *selected, *environment, *inventory, retained);
          if (reason.empty()) {
            if (!lease.active) {
              // Applying can take several seconds; the setup deadline starts now.
              lease.deadline = std::chrono::steady_clock::now() + std::chrono::seconds {45};
            }
            arrangement_lease = std::move(lease);
            clear_transition();
            std::clog << "PLANK display arrangement applied for UID " << request_uid << ": "
                      << arrangement_lease->request << '\n';
          } else if (retained != nullptr) {
            // The failed re-acquire restored the original snapshot.
            arrangement_lease.reset();
          }
        }
        if (!reason.empty()) {
          std::cerr << "PLANK display arrangement failed (" << reason << "): " << canonical << '\n';
          if (!canonical.empty()) write_transition("failed", reason, canonical, request_uid);
        }
      } else if (!pending_display_request->arrangement.empty()) {
        std::cerr << "Refusing a PLANK display arrangement: display.startup_layout is not physical or hybrid\n";
      } else if (physical_startup) {
        const auto environment = plank::session::discover_environment(*selected);
        physical_display_lease_t lease {
          pending_display_request->account_uid, *pending_display_request, {}, {}, false,
          std::chrono::steady_clock::now() + std::chrono::seconds {45}
        };
        if (arrangement_lease && environment && arrangement_lease->uid == lease.uid) {
          // One lease kind at a time: end the arrangement lease first.
          if (arrangement_lease->session_id == selected->id) {
            restore_arrangement_lease(*arrangement_lease, *selected, *environment, inventory);
          } else {
            clear_runtime_display_state();
          }
          arrangement_lease.reset();
        }
        if (!environment) {
          std::cerr << "Unable to discover the active X11 environment for a temporary physical-display lease\n";
          write_transition("failed", "unavailable", canonical, lease.uid);
        } else if ((physical_display_lease &&
                    physical_display_lease->uid != lease.uid) ||
                   (arrangement_lease && arrangement_lease->uid != lease.uid)) {
          std::cerr << "Refusing to replace a temporary display lease owned by another account\n";
          write_transition("failed", "busy", canonical, lease.uid);
        } else if (apply_physical_lease(
                     lease, *selected, *environment,
                     physical_display_lease &&
                         physical_display_lease->session_id == selected->id ?
                       &physical_display_lease->snapshot : nullptr
                   )) {
          physical_display_lease = std::move(lease);
          clear_transition();
          std::clog << "Temporary PLANK physical-display lease acquired for UID "
                    << physical_display_lease->uid << '\n';
        } else {
          write_transition("failed", "apply_failed", canonical, lease.uid);
        }
      } else if (!virtual_startup) {
        std::cerr << "Refusing a display transition because display.startup_layout is invalid\n";
      } else if (selected->session_class == "greeter") {
        const auto request = std::move(*pending_display_request);
        std::clog << "Applying PLANK display transition: "
                  << request.layout << ' ' << request.mode_1;
        if (!request.mode_2.empty()) std::clog << ' ' << request.mode_2;
        std::clog << '\n';
        stop_worker(worker);
        if (apply_display_transition(request)) {
          desired_secondary_visibility = request.layout == "dual-horizontal";
          visibility_session_id.clear();
          initial_secondary_visibility = false;
          std::clog << "PLANK display transition completed\n";
        }
      } else if (selected->session_class == "user" &&
                 selected->uid == pending_display_request->account_uid) {
        const auto environment = plank::session::discover_environment(*selected);
        if (!environment) {
          std::cerr << "Unable to discover the active user's X11 environment for a live display transition\n";
        } else if (apply_live_display_transition(
                     *pending_display_request, *selected, *environment
                   )) {
          desired_secondary_visibility =
            pending_display_request->layout == "dual-horizontal";
          visibility_session_id = selected->id;
          initial_secondary_visibility = false;
          std::clog << "PLANK live display transition completed for UID "
                    << selected->uid << '\n';
        } else {
          std::cerr << "PLANK live display transition failed for UID "
                    << selected->uid << '\n';
        }
      } else {
        std::cerr << "Refusing PLANK display transition for a user other than the active desktop owner\n";
      }
      pending_display_request.reset();
      display_request_deadline = std::chrono::steady_clock::time_point::max();
      next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
      continue;
    }

    const auto selected = plank::session::active_seat0_graphical_session();
    if (!selected) {
      pending_session.clear();
    } else if ((worker.pid <= 0 || worker.session_id != selected->id) &&
               std::chrono::steady_clock::now() >= next_launch) {
      const auto environment = plank::session::discover_environment(*selected);
      const auto account = account_for_uid(selected->uid);
      if (!environment || !account || account->home.empty()) {
        if (pending_session != selected->id) {
          std::clog << "Waiting for graphical environment for seat0 session "
                    << selected->id << '\n';
          pending_session = selected->id;
        }
      } else {
        const auto confirmed = plank::session::active_seat0_graphical_session();
        if (!confirmed || confirmed->id != selected->id || confirmed->uid != selected->uid) {
          continue;
        }
        if (worker.pid > 0 && worker.session_id != selected->id) {
          const auto previous_session = worker.session_id;
          std::clog << "Graphical session changed from " << previous_session
                    << " to " << selected->id
                    << "; restarting the PLANK media worker for fresh X11/NvFBC state\n";
          stop_worker(worker, selected->session_class == "user");
        }

        if (recover_stale_runtime_state) {
          const auto stale_snapshot = capture_physical_snapshot(*account, *environment);
          const auto fallback = stale_snapshot ?
            plank::display::safe_physical_metamode(*stale_snapshot) : std::string {};
          if (!fallback.empty() && assign_metamode(fallback, *account, *environment)) {
            std::cerr << "Recovered a stale temporary PLANK layout with one safe native physical output\n";
          } else {
            std::cerr << "ERROR: Unable to recover the stale temporary PLANK physical layout\n";
          }
          clear_runtime_display_state();
          recover_stale_runtime_state = false;
        }
        if (stale_arrangement) {
          recover_stale_arrangement(*stale_arrangement, *selected, *environment);
          stale_arrangement.reset();
        }

        if (arrangement_startup && inventory_session_id != selected->id) {
          // Record the display inventory of every new X server before its
          // worker starts; the worker builds display_capabilities from it.
          inventory = capture_inventory(*account, *environment, startup_policy);
          inventory_session_id = selected->id;
          if (inventory && write_inventory(*inventory)) {
            std::clog << "PLANK display inventory: " << inventory->physical.size()
                      << " physical output(s), " << inventory->virtual_heads << " of "
                      << inventory->virtual_candidates.size() << " virtual head(s) reserved\n";
          } else {
            std::cerr << "Unable to record the PLANK display inventory for session "
                      << selected->id << '\n';
          }
          if (hybrid_startup && inventory && inventory->virtual_heads > 0) {
            hide_virtual_heads(*inventory, *selected, *account, *environment);
          }
          if (hybrid_startup && inventory && selected->session_class == "greeter" &&
              !arrangement_lease && !physical_display_lease) {
            const auto overlay = read_overlay();
            const auto facts = overlay ? plank::display::parse_overlay_facts(*overlay) : std::nullopt;
            if ((!facts || facts->fingerprint != inventory->fingerprint) &&
                !hybrid_restarts.contains(inventory->fingerprint)) {
              // One bounded greeter-only restart per inventory: nobody is
              // signed in, no worker streams this X server and no lease exists.
              hybrid_restarts.insert(inventory->fingerprint);
              write_hybrid_restarts(hybrid_restarts);
              std::clog << "Restarting the greeter once to apply the PLANK hybrid display inventory\n";
              stop_worker(worker);
              restart_greeter_with_boot_overlay();
              inventory_session_id.clear();
              next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
              continue;
            }
          }
        }

        if (arrangement_lease && arrangement_lease->session_id != selected->id) {
          // GDM to user: the new X server gets the lease on a fresh snapshot.
          std::string reason = "session_ended";
          if (selected->session_class == "user" && selected->uid == arrangement_lease->uid &&
              inventory && inventory_session_id == selected->id) {
            auto carried = *arrangement_lease;
            reason = apply_arrangement_lease(carried, *selected, *environment, *inventory, nullptr);
            if (reason.empty()) {
              arrangement_lease = std::move(carried);
              std::clog << "Carried the PLANK display arrangement into user session "
                        << selected->id << '\n';
            }
          }
          if (!reason.empty()) {
            clear_runtime_display_state();
            arrangement_lease.reset();
            std::clog << "Discarded the PLANK display arrangement (" << reason << ")\n";
          }
        }

        if (physical_display_lease &&
            physical_display_lease->session_id != selected->id) {
          if (selected->session_class == "user" &&
              selected->uid == physical_display_lease->uid) {
            if (!apply_physical_lease(
                  *physical_display_lease, *selected, *environment
                )) {
              clear_runtime_display_state();
              physical_display_lease.reset();
              std::cerr << "Unable to carry the temporary display lease from GDM into the authenticated desktop\n";
            } else {
              std::clog << "Carried the temporary PLANK display lease into user session "
                        << selected->id << '\n';
            }
          } else {
            clear_runtime_display_state();
            physical_display_lease.reset();
            std::clog << "Discarded the temporary display lease after its X server ended\n";
          }
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
            std::cerr << "Unable to apply PLANK secondary-monitor visibility\n";
            next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
            continue;
          } else {
            std::clog << "PLANK secondary virtual monitor is "
                      << (*desired_secondary_visibility ? "available" : "hidden")
                      << " to the desktop\n";
            visibility_session_id = selected->id;
            initial_secondary_visibility = false;
          }
        }
        if (worker.pid <= 0) {
          auto launched = launch_worker(worker_path, *selected, complete_environment);
          if (launched.pid > 0) {
            worker = std::move(launched);
            pending_session.clear();
            std::clog << "Attached persistent PLANK machine worker to session "
                      << selected->id << ", UID " << selected->uid << '\n';
          } else {
            std::cerr << "Unable to fork PLANK worker: " << std::strerror(errno) << '\n';
          }
        }
        if (worker.pid > 0) {
          pending_session.clear();
        }
        next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
      }
    }

    std::array<pollfd, 4> descriptors {{
      {signal_fd, POLLIN, 0},
      {sd_login_monitor_get_fd(monitor.get()), POLLIN, 0},
      {worker.control_descriptor, POLLIN, 0},
      {worker.pam_descriptor, POLLIN, 0},
    }};
    const int status = poll(descriptors.data(), descriptors.size(), 1000);
    if (status < 0 && errno != EINTR) {
      std::cerr << "Supervisor poll failed: " << std::strerror(errno) << '\n';
      break;
    }
    if ((descriptors[1].revents & POLLIN) != 0) {
      sd_login_monitor_flush(monitor.get());
    }
    if ((descriptors[3].revents & (POLLIN | POLLHUP | POLLERR)) != 0 && worker.pid > 0) {
      namespace delegation = plank::auth::broker_channel;
      int unexpected_descriptor = -1;
      const bool valid = delegation::receive_record(
        worker.pam_descriptor, delegation::request_byte, false, unexpected_descriptor);
      const auto active = plank::session::active_seat0_graphical_session();
      const int broker = valid && active && active->id == worker.session_id ?
        delegation::connect_broker() : -1;
      const bool sent = valid && delegation::send_connection(worker.pam_descriptor, broker);
      if (broker >= 0) close(broker);
      if (!sent) {
        close(worker.pam_descriptor);
        worker.pam_descriptor = -1;
        std::cerr << "PLANK private PAM delegation channel closed\n";
      }
    }
    if ((descriptors[2].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0 && worker.pid > 0) {
      std::array<char, 8193> message {};
      const ssize_t size = plank::session::receive_worker_control(
        worker.control_descriptor, message.data(), message.size());
      if (size > 0) {
        const auto request = static_cast<std::size_t>(size) <= message.size() ? plank::session::parse_display_request(
          std::string_view {message.data(), static_cast<std::size_t>(size)}
        ) : std::nullopt;
        const auto active = plank::session::active_seat0_graphical_session();
        if (!request) {
          std::cerr << "Rejected malformed PLANK display transition request\n";
        } else if (!active || active->id != worker.session_id ||
                   (active->session_class == "user" &&
                    active->uid != request->account_uid) ||
                   (active->session_class != "greeter" &&
                    active->session_class != "user")) {
          std::cerr << "Refused PLANK display transition outside an authorized graphical session\n";
        } else if (request->action ==
                     plank::session::display_request_t::action_t::activate) {
          if (physical_display_lease &&
              physical_display_lease->uid == request->account_uid) {
            physical_display_lease->active = true;
            physical_display_lease->deadline =
              std::chrono::steady_clock::time_point::max();
            std::clog << "Temporary PLANK display lease is active\n";
          }
          if (arrangement_lease && arrangement_lease->uid == request->account_uid) {
            arrangement_lease->active = true;
            arrangement_lease->deadline = std::chrono::steady_clock::time_point::max();
            std::clog << "PLANK display arrangement lease is active\n";
          }
        } else if (request->action ==
                     plank::session::display_request_t::action_t::release) {
          if (physical_display_lease &&
              physical_display_lease->uid == request->account_uid) {
            const auto environment = active->id == physical_display_lease->session_id ?
              plank::session::discover_environment(*active) : std::nullopt;
            if (environment) {
              restore_physical_lease(*physical_display_lease, *active, *environment);
            } else {
              clear_runtime_display_state();
              std::cerr << "Released a temporary display lease after its X server disappeared\n";
            }
            physical_display_lease.reset();
          }
          if (arrangement_lease && arrangement_lease->uid == request->account_uid) {
            const auto environment = active->id == arrangement_lease->session_id ?
              plank::session::discover_environment(*active) : std::nullopt;
            if (environment) {
              restore_arrangement_lease(*arrangement_lease, *active, *environment, inventory);
            } else {
              clear_runtime_display_state();
              std::cerr << "Released a PLANK display arrangement after its X server disappeared\n";
            }
            arrangement_lease.reset();
          }
        } else if (!pending_display_request) {
          pending_display_request = *request;
          const auto canonical = !request->arrangement.empty() ?
            request->arrangement : legacy_arrangement(*request);
          if (arrangement_startup && !canonical.empty()) {
            write_transition("pending", "", canonical, request->account_uid);
          }
          // Allow the HTTPS worker to return its transition response before it
          // is stopped and GDM is restarted.
          display_request_deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds {750};
          std::clog << "Scheduled PLANK display transition from "
                    << (active->session_class == "greeter" ? "GDM" : "the active user desktop")
                    << '\n';
        }
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
            std::clog << "PLANK worker exited; scheduling restart\n";
            if (physical_display_lease && physical_display_lease->active &&
                physical_display_lease->session_id == worker.session_id) {
              physical_display_lease->active = false;
              physical_display_lease->deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds {30};
              std::cerr << "PLANK worker exited with an active display lease; allowing 30 seconds for recovery\n";
            }
            if (arrangement_lease && arrangement_lease->active &&
                arrangement_lease->session_id == worker.session_id) {
              arrangement_lease->active = false;
              arrangement_lease->deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds {30};
              std::cerr << "PLANK worker exited with an active display arrangement; allowing 30 seconds for recovery\n";
            }
            close(worker.control_descriptor);
            close(worker.pam_descriptor);
            worker = {};
            next_launch = std::chrono::steady_clock::now() + std::chrono::seconds {2};
          }
        }
      }
    }
  }

  if (physical_display_lease) {
    const auto selected = plank::session::active_seat0_graphical_session();
    const auto environment = selected &&
      selected->id == physical_display_lease->session_id ?
        plank::session::discover_environment(*selected) : std::nullopt;
    if (selected && environment) {
      restore_physical_lease(*physical_display_lease, *selected, *environment);
    } else {
      clear_runtime_display_state();
    }
  }
  if (arrangement_lease) {
    const auto selected = plank::session::active_seat0_graphical_session();
    const auto environment = selected &&
      selected->id == arrangement_lease->session_id ?
        plank::session::discover_environment(*selected) : std::nullopt;
    if (selected && environment) {
      restore_arrangement_lease(*arrangement_lease, *selected, *environment, inventory);
    } else {
      clear_runtime_display_state();
    }
  }
  clear_transition();
  stop_worker(worker);
  close(signal_fd);
  return 0;
}
