/**
 * @file src/session/collaboration.cpp
 * @brief Bounded collaboration consent and revocation state machine.
 */
#include "collaboration.h"
#include <algorithm>

namespace plank::collaboration {
  namespace {
    /** @brief Whether a request still occupies a guest slot. */
    bool live(permission_t permission) {
      return permission == permission_t::pending || permission == permission_t::view || permission == permission_t::control;
    }
    /** @brief Apply a permission change and release held guest input before returning. */
    void set_permission(const std::shared_ptr<lease_t> &lease, permission_t permission) {
      std::lock_guard lock {lease->mutex};
      const bool release = lease->permission == permission_t::control && permission != permission_t::control;
      lease->permission = permission;
      if (release && lease->release_input) lease->release_input();
      if (!live(permission) && lease->revoke_transport) {
        auto stop = std::move(lease->revoke_transport);
        stop();
      }
    }
  }
  const char *permission_name(permission_t permission) {
    switch (permission) {
      case permission_t::pending: return "pending";
      case permission_t::denied: return "denied";
      case permission_t::view: return "view";
      case permission_t::control: return "control";
      case permission_t::revoked: return "revoked";
      case permission_t::expired: return "expired";
    }
    return "revoked";
  }
  std::shared_ptr<request_t> registry_t::add(uid_t guest, std::string name, desktop_t desktop,
                                           std::string id, std::string grant,
                                           std::chrono::steady_clock::time_point now) {
    if (guest == desktop.owner || desktop.owner == 0 || desktop.generation == 0 || id.empty() || grant.empty()) return {};
    std::size_t active = 0;
    for (const auto &request : requests_) {
      if (!live(request->lease->permission)) continue;
      if (request->guest == guest && request->desktop == desktop) return request;
      ++active;
    }
    if (active >= 4) return {};
    if (requests_.size() >= 16) {
      std::erase_if(requests_, [](const auto &request) { return !live(request->lease->permission); });
    }
    auto request = std::make_shared<request_t>();
    request->id = std::move(id); request->grant = std::move(grant);
    request->guest = guest; request->guest_name = std::move(name); request->desktop = desktop;
    request->deadline = now + std::chrono::seconds {120};
    requests_.push_back(request);
    suspend(false);
    return request;
  }
  std::shared_ptr<request_t> registry_t::find(const std::string &id, uid_t account) {
    for (const auto &request : requests_) {
      if (request->id == id && (request->guest == account || request->desktop.owner == account)) return request;
    }
    return {};
  }
  bool registry_t::decide(const std::string &id, uid_t owner, desktop_t desktop, permission_t permission) {
    const auto request = find(id, owner);
    if (!request || request->desktop != desktop || desktop.owner != owner || !live(request->lease->permission) ||
        (permission != permission_t::view && permission != permission_t::control &&
         permission != permission_t::denied && permission != permission_t::revoked)) return false;
    set_permission(request->lease, permission);
    return true;
  }
  std::shared_ptr<request_t> registry_t::claim(const std::string &grant, uid_t guest, desktop_t desktop,
                                             std::chrono::steady_clock::time_point now) {
    for (const auto &request : requests_) {
      if (request->grant != grant || request->guest != guest || request->desktop != desktop || now >= request->deadline) continue;
      std::lock_guard lock {request->lease->mutex};
      if (request->lease->claimed || (request->lease->permission != permission_t::view && request->lease->permission != permission_t::control)) return {};
      request->lease->claimed = true;
      return request;
    }
    return {};
  }
  void registry_t::refresh(const desktop_t *desktop, bool ui_connected, std::chrono::steady_clock::time_point now) {
    this->ui_connected = ui_connected;
    for (const auto &request : requests_) {
      if (!live(request->lease->permission)) continue;
      if (!desktop || *desktop != request->desktop || (!ui_connected && request->lease->permission != permission_t::pending)) {
        set_permission(request->lease, permission_t::revoked);
      } else if (!request->lease->claimed && now >= request->deadline) {
        set_permission(request->lease, permission_t::expired);
      }
    }
  }
  void registry_t::suspend(bool panel_open) {
    const bool pending = std::any_of(requests_.begin(), requests_.end(), [](const auto &request) {
      return request->lease->permission == permission_t::pending;
    });
    for (const auto &request : requests_) {
      std::lock_guard lock {request->lease->mutex};
      const bool suspended = panel_open || pending;
      if (suspended && !request->lease->input_suspended && request->lease->release_input) request->lease->release_input();
      request->lease->input_suspended = suspended;
    }
  }
  void registry_t::revoke_all() {
    for (const auto &request : requests_) if (live(request->lease->permission)) set_permission(request->lease, permission_t::revoked);
  }
  void registry_t::ended(const std::shared_ptr<lease_t> &lease) {
    if (lease) set_permission(lease, permission_t::revoked);
  }
  registry_t &registry() {
    static registry_t instance;
    return instance;
  }
}
