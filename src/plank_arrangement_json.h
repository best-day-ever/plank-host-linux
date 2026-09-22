/**
 * @file src/plank_arrangement_json.h
 * @brief JSON shapes of `display_capabilities` and of a backing resolution.
 *
 * The capabilities shape is pinned by protocol/output-topology.md and by the
 * capability fixtures in tests/fixtures/protocol/display-arrangement-v1.json.
 */
#pragma once

#include "plank_arrangement.h"

#include <nlohmann/json.hpp>

namespace plank::arrangement {
  /**
   * @brief Serialise `display_capabilities`.
   * @param capabilities Host capabilities.
   * @return The JSON object published in the topology document.
   */
  inline nlohmann::json capabilities_json(const capabilities_t &capabilities) {
    nlohmann::json physical = nlohmann::json::array();
    for (const auto &output : capabilities.physical_outputs) {
      physical.push_back({
        {"id", output.id},
        {"name", output.name},
        {"display_name", output.display_name},
        {"edid_sha256", output.edid_sha256},
        {"preferred", output.preferred},
        {"modes", output.modes},
      });
    }
    nlohmann::json encoding = nlohmann::json::object();
    for (const auto &[mode, limit] : capabilities.encoding_limits) {
      encoding[mode] = {
        {"width", limit.width},
        {"height", limit.height},
        {"qualified_width", limit.qualified_width},
        {"qualified_height", limit.qualified_height},
      };
    }
    return {
      {"version", capabilities.version},
      {"fingerprint", capabilities.fingerprint},
      {"max_outputs", capabilities.max_outputs},
      {"virtual_heads", capabilities.virtual_heads},
      {"max_canvas", {
        {"width", capabilities.max_canvas_width},
        {"height", capabilities.max_canvas_height},
      }},
      {"packed_capture", capabilities.packed_capture},
      {"output_limits", {
        {"min_width", capabilities.output_limits.min_width},
        {"min_height", capabilities.output_limits.min_height},
        {"max_width", capabilities.output_limits.max_width},
        {"max_height", capabilities.output_limits.max_height},
        {"max_pixels", capabilities.output_limits.max_pixels},
      }},
      {"refresh_millihz", capabilities.refresh_millihz},
      {"physical_outputs", physical},
      {"encoding_limits", encoding},
    };
  }

  /**
   * @brief Read `display_capabilities`, strictly.
   * @param value A capabilities JSON object.
   * @return The capabilities, or no value when a field is missing or has the wrong type.
   */
  inline std::optional<capabilities_t> capabilities_from_json(const nlohmann::json &value) {
    try {
      capabilities_t capabilities;
      capabilities.version = value.at("version").get<int>();
      capabilities.fingerprint = value.at("fingerprint").get<std::string>();
      capabilities.max_outputs = value.at("max_outputs").get<int>();
      capabilities.virtual_heads = value.at("virtual_heads").get<int>();
      capabilities.max_canvas_width = value.at("max_canvas").at("width").get<int>();
      capabilities.max_canvas_height = value.at("max_canvas").at("height").get<int>();
      capabilities.packed_capture = value.at("packed_capture").get<bool>();
      const auto &limits = value.at("output_limits");
      capabilities.output_limits = {
        limits.at("min_width").get<int>(), limits.at("min_height").get<int>(),
        limits.at("max_width").get<int>(), limits.at("max_height").get<int>(),
        limits.at("max_pixels").get<std::int64_t>(),
      };
      capabilities.refresh_millihz = value.at("refresh_millihz").get<std::vector<int>>();
      for (const auto &output : value.at("physical_outputs")) {
        capabilities.physical_outputs.push_back({
          output.at("id").get<std::string>(),
          output.at("name").get<std::string>(),
          output.at("display_name").get<std::string>(),
          output.at("edid_sha256").get<std::string>(),
          output.at("preferred").get<std::string>(),
          output.at("modes").get<std::vector<std::string>>(),
        });
      }
      for (const auto &[mode, limit] : value.at("encoding_limits").items()) {
        capabilities.encoding_limits[mode] = {
          limit.at("width").get<int>(), limit.at("height").get<int>(),
          limit.at("qualified_width").get<int>(), limit.at("qualified_height").get<int>(),
        };
      }
      return capabilities;
    } catch (const nlohmann::json::exception &) {
      return std::nullopt;
    }
  }

  /**
   * @brief Serialise a backing resolution in the shared-vector result shape.
   * @param resolution A resolution from resolve().
   * @return `{outputs, hidden_physical, desktop}`.
   */
  inline nlohmann::json resolution_json(const resolution_t &resolution) {
    nlohmann::json outputs = nlohmann::json::array();
    for (const auto &output : resolution.outputs) {
      nlohmann::json item {{"backing", std::string {backing_name(output.backing)}}};
      if (output.backing == backing_t::virtual_output) {
        item["head"] = output.head;
        item["carrier"] = output.carrier;
      } else {
        item["output"] = output.output;
        item["mode"] = output.mode;
      }
      item["rect"] = {
        {"x", output.rect.x},
        {"y", output.rect.y},
        {"width", output.rect.width},
        {"height", output.rect.height},
      };
      outputs.push_back(std::move(item));
    }
    return {
      {"outputs", outputs},
      {"hidden_physical", resolution.hidden_physical},
      {"desktop", {{"width", resolution.desktop_width}, {"height", resolution.desktop_height}}},
    };
  }
}  // namespace plank::arrangement
