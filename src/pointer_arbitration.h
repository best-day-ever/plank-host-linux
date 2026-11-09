/**
 * @file src/pointer_arbitration.h
 * @brief Short activity ownership of the desktop mouse without per-user pointer warps.
 */
#pragma once
#include <chrono>
#include <cstdint>

namespace input {
  /** @brief Serialize with the input-state mutex; denied input never renews ownership. */
  class pointer_arbitration_t {
  public:
    using clock = std::chrono::steady_clock;  ///< Monotonic activity clock.
    /** @brief Keep rapid movements together; another participant takes over after 250 ms idle. */
    bool accept(std::uint64_t connection, clock::time_point now) {
      if (!connection) return false;
      if (owner_ && owner_ != connection && (buttons_ || now - last_ < std::chrono::milliseconds {250})) return false;
      owner_ = connection; last_ = now;
      return true;
    }
    /** @brief Pin a drag until the same connection releases all its accepted buttons. */
    void button(std::uint64_t connection, unsigned button, bool pressed) {
      if (owner_ != connection || button < 1 || button > 5) return;
      const auto mask = std::uint32_t {1} << button;
      if (pressed) buttons_ |= mask;
      else buttons_ &= ~mask;
    }
    /** @brief Other participants cannot inject a new shortcut into an active drag. */
    bool dragging_elsewhere(std::uint64_t connection) const { return buttons_ && owner_ != connection; }
    /** @brief Disconnect, downgrade or input suspension immediately releases this connection's ownership. */
    void release(std::uint64_t connection) {
      if (owner_ == connection) { owner_ = 0; buttons_ = 0; }
    }
  private:
    std::uint64_t owner_ {};  ///< Opaque live input-context identity; connection counters are only per participant.
    std::uint32_t buttons_ {};  ///< Only accepted button downs pin ownership.
    clock::time_point last_ {};  ///< Last accepted movement, button press or scroll.
  };
}
