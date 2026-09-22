/**
 * @file src/nvenc/nvenc_limits.h
 * @brief Encoder size limits recorded by the startup NVENC probe.
 */
#pragma once

#include <map>
#include <mutex>
#include <optional>

namespace nvenc {
  /**
   * @brief Largest frame one codec accepts (`NV_ENC_CAPS_WIDTH_MAX`/`HEIGHT_MAX`).
   */
  struct encoder_size_limit_t {
    int width {};  ///< Maximum encode width.
    int height {};  ///< Maximum encode height.
  };

  /**
   * @brief Process-wide table keyed by video format (0 H.264, 1 HEVC, 2 AV1).
   * @return The table and its lock.
   */
  inline std::pair<std::mutex &, std::map<int, encoder_size_limit_t> &> encoder_size_limit_table() {
    static std::mutex mutex;
    static std::map<int, encoder_size_limit_t> table;
    return {mutex, table};
  }

  /**
   * @brief Record the limits an encoder session reported for one video format.
   * @param video_format 0 H.264, 1 HEVC, 2 AV1.
   * @param width `NV_ENC_CAPS_WIDTH_MAX`.
   * @param height `NV_ENC_CAPS_HEIGHT_MAX`.
   */
  inline void record_encoder_size_limit(int video_format, int width, int height) {
    if (width <= 0 || height <= 0) return;
    auto [mutex, table] = encoder_size_limit_table();
    std::lock_guard lock {mutex};
    table[video_format] = {width, height};
  }

  /**
   * @brief Limits recorded for one video format.
   * @param video_format 0 H.264, 1 HEVC, 2 AV1.
   * @return The limits, or no value before the probe ran.
   */
  inline std::optional<encoder_size_limit_t> encoder_size_limit(int video_format) {
    auto [mutex, table] = encoder_size_limit_table();
    std::lock_guard lock {mutex};
    const auto found = table.find(video_format);
    return found == table.end() ? std::nullopt : std::optional {found->second};
  }
}  // namespace nvenc
