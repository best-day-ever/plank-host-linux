/**
 * @file src/stationconnect_topology.h
 * @brief Versioned StationConnect display-layout negotiation primitives.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace stationconnect::topology {
  constexpr std::uint32_t protocol_version = 2;
  constexpr std::uint32_t feature_output_topology = 0x1;
  constexpr std::uint32_t feature_selected_output = 0x2;
  constexpr std::uint32_t feature_unified_absolute_input = 0x4;
  constexpr std::uint32_t feature_scaled_span = 0x8;
  constexpr std::uint32_t feature_topology_generation = 0x10;
  constexpr std::uint32_t feature_host_layout_metadata = 0x20;
  constexpr std::uint32_t feature_composite_source_regions = 0x40;
  constexpr std::uint32_t feature_host_layout_binding = 0x80;
  constexpr std::uint32_t feature_flags =
    feature_output_topology |
    feature_selected_output |
    feature_unified_absolute_input |
    feature_scaled_span |
    feature_topology_generation |
    feature_host_layout_metadata |
    feature_composite_source_regions |
    feature_host_layout_binding;

  enum class layout_error {
    none,
    invalid_request,
    mismatch,
    unhealthy,
  };

  constexpr bool valid_layout(std::string_view layout) {
    return layout == "physical" ||
           layout == "single" ||
           layout == "dual-horizontal";
  }

  constexpr bool valid_virtual_mode(std::string_view mode) {
    return mode == "1920x1080" || mode == "3840x2160";
  }

  constexpr layout_error validate_layout_binding(
    std::string_view requested_layout,
    std::string_view requested_mode,
    std::string_view actual_layout,
    std::string_view actual_mode,
    std::size_t output_count
  ) {
    if (!valid_layout(requested_layout) ||
        (requested_layout == "physical" ?
           !requested_mode.empty() :
           !valid_virtual_mode(requested_mode))) {
      return layout_error::invalid_request;
    }
    if (requested_layout != actual_layout || requested_mode != actual_mode) {
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
