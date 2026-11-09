/**
 * @file src/platform/linux/nvfbc_capture_retry.h
 * @brief Keep a transient NVIDIA modeset from ending a desktop stream.
 */
#pragma once

#include <chrono>
#include <optional>
#include <string_view>

namespace nvfbc {
  /** @brief Bound capture creation retries without sleeping inside the driver call. */
  class capture_start_retry_t {
  public:
    /**
     * @brief Decide whether capture creation may wait for an active modeset.
     * @param reason Driver diagnostic for the failed capture creation.
     * @param now Monotonic time after the failed call.
     * @return True only for the known transient modeset within five seconds.
     */
    bool retry(std::string_view reason, std::chrono::steady_clock::time_point now) {
      if (reason.find("display server is in modeset") == std::string_view::npos) {
        return false;
      }
      if (!started_) {
        started_ = now;
      }
      return now - *started_ < std::chrono::seconds(5);
    }

    /** @brief Begin a new retry budget after capture creation succeeds. */
    void reset() {
      started_.reset();
    }

  private:
    std::optional<std::chrono::steady_clock::time_point> started_;  ///< First modeset failure, never extended by retries.
  };
}
