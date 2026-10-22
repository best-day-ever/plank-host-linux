/**
 * @file src/session/display_lifecycle.h
 * @brief Display transaction ownership and session-inventory publication.
 */
#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <utility>

namespace plank::display {
  /** The side effect a completed display transaction actually achieved. */
  enum class display_change_effect_t {
    unchanged,  ///< No replacement snapshot or display mutation occurred.
    applied,  ///< The requested geometry was verified.
    restored,  ///< The original snapshot was restored exactly.
    recovery_pending,  ///< A recorded snapshot still needs exact restoration.
  };

  /** Result of a recorded display change; a refusal is not a rollback. */
  struct display_change_result_t {
    std::string reason;  ///< Empty on success.
    display_change_effect_t effect {display_change_effect_t::unchanged};
  };

  /**
   * @brief Record before mutation, and preserve recovery authority until exact rollback.
   * @param record Writes the original snapshot; failure must not replace an existing record.
   * @param change Applies/verifies geometry and returns an empty string or a failure reason.
   * @param restore Restores geometry; returns true only after exact restoration clears its record.
   * @return Reason plus the actual ownership effect, including failures before mutation.
   */
  template<class Record, class Change, class Restore>
  display_change_result_t recorded_display_change(Record record, Change change, Restore restore) {
    if (!record()) return {"state_failed", display_change_effect_t::unchanged};
    auto reason = change();
    if (reason.empty()) return {{}, display_change_effect_t::applied};
    const bool exact = restore();
    return {std::move(reason), exact ? display_change_effect_t::restored :
                                      display_change_effect_t::recovery_pending};
  }

  /**
   * @brief Keep a failed rollback owned and retryable without treating it as an active stream.
   * @param lease Snapshot/owner to retain.
   * @param now Monotonic clock at failure.
   */
  template<class Lease>
  void retry_display_recovery(Lease &lease, std::chrono::steady_clock::time_point now) {
    lease.active = false;
    lease.deadline = now + std::chrono::seconds {30};
  }

  /**
   * @brief Reconcile ownership using transaction effects, never a reason-string guess.
   * @param owned Existing same-server lease, if any.
   * @param attempted Lease whose snapshot was recorded by this attempt.
   * @param effect Actual result of the transaction.
   * @param now Monotonic clock for a bounded recovery retry.
   */
  template<class Lease>
  void reconcile_display_change(std::optional<Lease> &owned, Lease attempted,
                                display_change_effect_t effect,
                                std::chrono::steady_clock::time_point now) {
    switch (effect) {
      case display_change_effect_t::unchanged:
        return;
      case display_change_effect_t::restored:
        owned.reset();
        return;
      case display_change_effect_t::recovery_pending:
        retry_display_recovery(attempted, now);
        break;
      case display_change_effect_t::applied:
        break;
    }
    owned = std::move(attempted);
  }

  /**
   * @brief Publish a fresh inventory before marking the session ready or launching its worker.
   * @param cached Last successfully published inventory.
   * @param ready_session X session that owns the published inventory.
   * @param session Current X session.
   * @param capture Returns an optional newly observed inventory.
   * @param publish Atomically publishes the observed inventory.
   * @return True only when both capture and publication succeeded for this session.
   */
  template<class Inventory, class Capture, class Publish>
  bool publish_session_inventory(std::optional<Inventory> &cached, std::string &ready_session,
                                 const std::string &session, Capture capture, Publish publish) {
    if (cached && ready_session == session) return true;
    auto observed = capture();
    if (!observed || !publish(*observed)) {
      cached.reset();
      ready_session.clear();
      return false;
    }
    cached = std::move(observed);
    ready_session = session;
    return true;
  }
}  // namespace plank::display
