/**
 * @file greeter_recovery.h
 * @brief Bounded recovery policy for a greeter without an X server.
 */
#pragma once

#include <chrono>
#include <string>
#include <string_view>

namespace plank::session {
  /**
   * @brief Tracks stalled greeter sessions and limits display-manager restarts.
   */
  class greeter_recovery_t {
  public:
    using clock = std::chrono::steady_clock;

    /**
     * @brief Observe the current desktop and decide whether to restart GDM.
     * @param session_id Active stalled greeter ID, or empty if none is active.
     * @param healthy_desktop A user desktop or usable greeter is active.
     * @param safe_to_restart No user session, stream lease, or qualification is active.
     * @param now Monotonic observation time.
     * @return True for at most two restarts per ten minutes, after a 20-second stall each.
     */
    bool observe(std::string_view session_id, bool healthy_desktop,
                 bool safe_to_restart, clock::time_point now) {
      if (healthy_desktop) {
        session_id_.clear();
        return false;
      }
      if (session_id.empty()) return false;
      if (session_id_ != session_id) {
        session_id_ = session_id;
        first_seen_ = now;
      }
      if (!safe_to_restart || now - first_seen_ < std::chrono::seconds {20}) {
        return false;
      }
      if (attempts_ > 0 && now - restart_window_start_ >= std::chrono::minutes {10}) {
        attempts_ = 0;
      }
      if (attempts_ >= 2) return false;
      if (attempts_ == 0) restart_window_start_ = now;
      ++attempts_;
      first_seen_ = now;
      return true;
    }

  private:
    std::string session_id_;
    clock::time_point first_seen_ {};
    clock::time_point restart_window_start_ {};
    unsigned attempts_ {};
  };
}  // namespace plank::session
