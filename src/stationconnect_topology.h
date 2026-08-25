/**
 * @file src/stationconnect_topology.h
 * @brief Versioned StationConnect display-layout negotiation primitives.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace stationconnect::topology {
  constexpr std::uint32_t protocol_version = 3;
  constexpr std::uint32_t feature_output_topology = 0x1;
  constexpr std::uint32_t feature_selected_output = 0x2;
  constexpr std::uint32_t feature_unified_absolute_input = 0x4;
  constexpr std::uint32_t feature_scaled_span = 0x8;
  constexpr std::uint32_t feature_topology_generation = 0x10;
  constexpr std::uint32_t feature_host_layout_metadata = 0x20;
  constexpr std::uint32_t feature_composite_source_regions = 0x40;
  constexpr std::uint32_t feature_host_layout_binding = 0x80;
  constexpr std::uint32_t feature_independent_virtual_modes = 0x100;
  constexpr std::uint32_t feature_flags =
    feature_output_topology |
    feature_selected_output |
    feature_unified_absolute_input |
    feature_scaled_span |
    feature_topology_generation |
    feature_host_layout_metadata |
    feature_composite_source_regions |
    feature_host_layout_binding |
    feature_independent_virtual_modes;

  enum class layout_error {
    none,
    invalid_request,
    mismatch,
    unhealthy,
  };

  struct mode_size {
    int width;
    int height;
  };

  constexpr mode_size virtual_mode_size(std::string_view mode) {
    if (mode == "1024x2160") return {1024, 2160};
    if (mode == "1280x720") return {1280, 720};
    if (mode == "1280x1024") return {1280, 1024};
    if (mode == "1280x2160") return {1280, 2160};
    if (mode == "1920x1080") return {1920, 1080};
    if (mode == "1920x1200") return {1920, 1200};
    if (mode == "2560x1440") return {2560, 1440};
    if (mode == "2560x1600") return {2560, 1600};
    if (mode == "3440x1440") return {3440, 1440};
    if (mode == "3840x1600") return {3840, 1600};
    if (mode == "3840x2160") return {3840, 2160};
    if (mode == "4096x2160") return {4096, 2160};
    return {0, 0};
  }

  constexpr bool valid_layout(std::string_view layout) {
    return layout == "physical" ||
           layout == "single" ||
           layout == "dual-horizontal";
  }

  constexpr bool valid_virtual_mode(std::string_view mode) {
    const auto size = virtual_mode_size(mode);
    return size.width > 0 && size.height > 0;
  }

  constexpr layout_error validate_layout_binding(
    std::string_view requested_layout,
    std::string_view requested_mode_1,
    std::string_view requested_mode_2,
    std::string_view actual_layout,
    std::string_view actual_mode_1,
    std::string_view actual_mode_2,
    std::size_t output_count
  ) {
    if (!valid_layout(requested_layout) ||
        (requested_layout == "physical" &&
         (!requested_mode_1.empty() || !requested_mode_2.empty())) ||
        (requested_layout == "single" &&
         (!valid_virtual_mode(requested_mode_1) || !requested_mode_2.empty())) ||
        (requested_layout == "dual-horizontal" &&
         (!valid_virtual_mode(requested_mode_1) ||
          !valid_virtual_mode(requested_mode_2)))) {
      return layout_error::invalid_request;
    }
    if (requested_layout != actual_layout ||
        requested_mode_1 != actual_mode_1 ||
        requested_mode_2 != actual_mode_2) {
      return layout_error::mismatch;
    }
    if ((actual_layout == "single" && output_count != 1) ||
        (actual_layout == "dual-horizontal" && output_count != 2) ||
        (actual_layout == "physical" && output_count == 0)) {
      return layout_error::unhealthy;
    }
    return layout_error::none;
  }
}  // namespace stationconnect::topology
