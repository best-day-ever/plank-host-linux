/**
 * @file greeter_recovery.h
 * @brief Bounded recovery policy for a greeter without an X server.
 */
#pragma once

#include <cerrno>
#include <chrono>
#include <string>
#include <string_view>

namespace plank::session {
  /** A logind session record that has already disappeared. */
  inline bool session_record_vanished(int status) {
    return status == -ENXIO || status == -ENOENT;
  }

  /**
   * @brief Decide whether a seat session prevents a GDM restart.
   * @param status Result of sd_session_get_class for this seat session.
   * @param session_class Class returned for a live session.
   * @return True for a user session or an error other than a vanished session.
   */
  inline bool seat_session_blocks_greeter_recovery(int status, std::string_view session_class) {
    if (status >= 0) return session_class == "user";
    return !session_record_vanished(status);
  }

  /**
   * @brief Protect live desktops while allowing an existing greeter's VT to activate.
   * @param class_status Result of querying the seat session class.
   * @param session_class Reported logind class.
   * @param state_status Result of querying session state.
   * @param state Reported logind state.
   * @param active Result of querying whether this session is active.
   * @return True unless this is a greeter, a vanished record, or an inactive closing user.
   *
   * Closing user records can linger after X exits. They still prohibit a GDM
   * restart above, but must not strand the new greeter in VT_WAITACTIVE.
   */
  inline bool seat_session_blocks_greeter_activation(
      int class_status, std::string_view session_class,
      int state_status, std::string_view state, int active) {
    if (session_record_vanished(class_status)) return false;
    if (class_status < 0 || state_status < 0 || active < 0) return true;
    if (session_class == "greeter") return false;
    return session_class != "user" || state != "closing" || active != 0;
  }

  /**
   * @brief Revalidate the exact greeter immediately before activating its VT.
   * @param expected Previously observed unique safe greeter session.
   * @param current Reads the current candidate, including all safety checks.
   * @param activate Performs the bounded logind activation.
   * @return True only when the same safe candidate was activated successfully.
   */
  template<class Current, class Activate>
  bool activate_greeter_if_current(std::string_view expected, Current current, Activate activate) {
    return !expected.empty() && current() == expected && activate(expected);
  }

  /** @brief Bound non-destructive VT activation independently for each stalled greeter. */
  class greeter_activation_t {
  public:
    using clock = std::chrono::steady_clock;

    /**
     * @brief Allow activation after a short stall, with one delayed retry.
     * @param candidate Unique safely inactive greeter, or empty when unsafe/healthy.
     * @param now Monotonic observation time.
     * @return True after three seconds, at most twice per continuous stall.
     *
     * A healthy or changed session resets the budget. Frequent legitimate
     * sign-outs must not exhaust the destructive-restart rate limit.
     */
    bool observe(std::string_view candidate, clock::time_point now) {
      if (candidate.empty()) {
        session_id_.clear();
        return false;
      }
      if (candidate != session_id_) {
        session_id_ = candidate;
        first_seen_ = now;
        attempts_ = 0;
      }
      if (now - first_seen_ < std::chrono::seconds {3} || attempts_ >= 2 ||
          (attempts_ > 0 && now - last_attempt_ < std::chrono::seconds {20})) return false;
      ++attempts_;
      last_attempt_ = now;
      return true;
    }

  private:
    std::string session_id_;
    clock::time_point first_seen_ {};
    clock::time_point last_attempt_ {};
    unsigned attempts_ {};
  };

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
