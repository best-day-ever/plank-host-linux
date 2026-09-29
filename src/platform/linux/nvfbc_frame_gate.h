/**
 * @file src/platform/linux/nvfbc_frame_gate.h
 * @brief Suppress duplicate driver frames while retaining the initial image.
 */
#pragma once

namespace nvfbc {
  /** @brief Track whether this capture session has published its first image. */
  class frame_gate_t {
  public:
    /** @brief Require a first image after a capture-session recreation. */
    void reset() {
      published_ = false;
    }

    /**
     * @brief Decide whether a successful driver grab needs copying and encoding.
     * @param is_new_frame Whether the driver reports changed display content.
     * @return True for the initial image or changed content, false for duplicates.
     */
    bool publish(bool is_new_frame) {
      if (published_ && !is_new_frame) {
        return false;
      }
      published_ = true;
      return true;
    }

  private:
    bool published_ = false;  ///< The current capture session has supplied an image.
  };
}
