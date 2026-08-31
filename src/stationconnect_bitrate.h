/**
 * @file src/stationconnect_bitrate.h
 * @brief Validation for StationConnect active-session bitrate messages.
 */
#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>

#include "utility.h"

namespace stationconnect::bitrate {
  constexpr int minimum_kbps = 500;
  constexpr int maximum_kbps = 500000;

  /**
   * @brief Validate an encoder target supplied during native setup or by the control stream.
   */
  inline std::optional<int> validate_target(const std::int64_t bitrate_kbps) {
    if (bitrate_kbps < minimum_kbps || bitrate_kbps > maximum_kbps) {
      return std::nullopt;
    }
    return static_cast<int>(bitrate_kbps);
  }

  /**
   * @brief Decode and validate a little-endian bitrate control payload.
   */
  inline std::optional<int> decode_request(const std::string_view payload) {
    if (payload.size() != sizeof(std::uint32_t)) {
      return std::nullopt;
    }

    std::uint32_t encoded_bitrate;
    std::memcpy(&encoded_bitrate, payload.data(), sizeof(encoded_bitrate));
    return validate_target(util::endian::little(encoded_bitrate));
  }
}  // namespace stationconnect::bitrate
