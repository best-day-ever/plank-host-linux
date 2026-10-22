/**
 * @file src/session/collaboration_ui.cpp
 * @brief Credential-checked local owner consent channel; no network authority or desktop secrets.
 */
#include "collaboration.h"
#include "session_context.h"
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace plank::collaboration {
  namespace {
    constexpr char socket_path[] = "/run/plank/collaboration.sock";
    /** @brief Resolve only an unlocked, supervisor-attested graphical user desktop. */
    std::optional<desktop_t> desktop() {
      const auto owner = session::unlocked_desktop_owner();
      if (!owner) return {};
      return desktop_t {*owner, session::desktop_generation()};
    }
  }
  struct ui_t::impl_t {
    int listener {-1};  ///< Root-owned Unix listener; the peer account authenticates every connection.
    int peer {-1};  ///< The current desktop owner's consent helper.
    std::optional<desktop_t> peer_desktop;  ///< Exact UID and generation authenticated when the helper connected.
    bool panel_open {};  ///< Acknowledged before the helper exposes sensitive controls.
    std::jthread thread;  ///< Owns all socket descriptors and heartbeat checks.
    impl_t(): thread {[this](std::stop_token stop) { run(stop); }} {}
    ~impl_t() { thread.request_stop(); thread.join(); }
    /** @brief Revoke authority when the owner helper closes or misses its heartbeat. */
    void disconnect() {
      if (peer >= 0) close(peer);
      peer = -1; panel_open = false; peer_desktop.reset();
      auto &state = registry();
      std::lock_guard lock {state.mutex};
      state.ui_connected = false;
      state.revoke_all();
    }
    /** @brief Poll bounded local packets and publish a participant heartbeat. */
    void run(std::stop_token stop) {
      listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
      if (listener < 0) return;
      sockaddr_un address {}; address.sun_family = AF_UNIX;
      std::strncpy(address.sun_path, socket_path, sizeof(address.sun_path) - 1);
      struct stat previous {};
      if (lstat(socket_path, &previous) == 0) {
        if (previous.st_uid != 0 || !S_ISSOCK(previous.st_mode)) { close(listener); return; }
        unlink(socket_path);
      }
      if (bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
          chmod(socket_path, 0666) != 0 || listen(listener, 4) != 0) {
        close(listener); listener = -1; return;
      }
      auto heartbeat = std::chrono::steady_clock::now();
      auto requested = heartbeat - std::chrono::seconds {15};
      while (!stop.stop_requested()) {
        const auto current = desktop();
        const auto now = std::chrono::steady_clock::now();
        pollfd descriptors[] {{listener, POLLIN, 0}, {peer, POLLIN, 0}};
        poll(descriptors, 2, 50);
        if (descriptors[0].revents & POLLIN) {
          const int candidate = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
          ucred credentials {}; socklen_t length = sizeof(credentials);
          if (candidate >= 0 && current && peer < 0 &&
              getsockopt(candidate, SOL_SOCKET, SO_PEERCRED, &credentials, &length) == 0 &&
              length == sizeof(credentials) && credentials.uid == current->owner) {
            peer = candidate; peer_desktop = current; heartbeat = now;
          } else if (candidate >= 0) close(candidate);
        }
        if (peer >= 0 && (!current || !peer_desktop || *current != *peer_desktop)) disconnect();
        if (peer >= 0 && (descriptors[1].revents & (POLLHUP | POLLERR))) disconnect();
        if (peer >= 0 && (descriptors[1].revents & POLLIN)) {
          std::array<char, 4097> packet {};
          const auto size = recv(peer, packet.data(), packet.size(), MSG_TRUNC | MSG_DONTWAIT);
          if (size <= 0 || size > 4096) { disconnect(); continue; }
          const auto body = nlohmann::json::parse(packet.data(), packet.data() + size, nullptr, false);
          if (!body.is_object() || !current) { disconnect(); continue; }
          heartbeat = now;
          auto &state = registry(); std::lock_guard lock {state.mutex};
          if (body.contains("panel_open") && body["panel_open"].is_boolean()) panel_open = body["panel_open"].get<bool>();
          if (body.contains("request_id") && body["request_id"].is_string() && body.contains("permission") && body["permission"].is_string()) {
            const auto permission = body["permission"].get<std::string>();
            const auto value = permission == "view" ? permission_t::view : permission == "control" ? permission_t::control :
                               permission == "deny" ? permission_t::denied : permission_t::revoked;
            state.decide(body["request_id"].get<std::string>(), current->owner, *current, value);
          }
        }
        if (peer >= 0 && (!current || now - heartbeat > std::chrono::seconds {3})) disconnect();
        bool pending = false;
        nlohmann::json snapshot {{"requests", nlohmann::json::array()}, {"panel_open", panel_open}};
        {
          auto &state = registry(); std::lock_guard lock {state.mutex};
          state.refresh(current ? &*current : nullptr, peer >= 0, now);
          state.suspend(panel_open);
          for (const auto &request : state.requests()) {
            if (!current || request->desktop != *current) continue;
            const auto permission = request->lease->permission.load();
            pending |= permission == permission_t::pending;
            if (permission == permission_t::pending || permission == permission_t::view || permission == permission_t::control) {
              snapshot["requests"].push_back({{"request_id", request->id}, {"guest_name", request->guest_name},
                                              {"state", permission_name(permission)}, {"connected", request->lease->claimed}});
            }
          }
        }
        if (pending && peer < 0 && current && now - requested >= std::chrono::seconds {10}) {
          session::request_collaboration_ui(); requested = now;
        }
        if (peer >= 0) {
          const auto data = snapshot.dump();
          const auto sent = send(peer, data.data(), data.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
          if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) disconnect();
        }
      }
      disconnect(); close(listener); unlink(socket_path);
    }
  };
  ui_t::ui_t(): impl_ {std::make_unique<impl_t>()} {}
  ui_t::~ui_t() = default;
}
