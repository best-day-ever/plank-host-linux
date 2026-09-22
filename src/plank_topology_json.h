/**
 * @file src/plank_topology_json.h
 * @brief The `GET /plank/topology` document, including the display-arrangement fields.
 *
 * Pinned by tests/protocol/output-topology-v13*.json. The arrangement fields
 * (feature 0x8000000) are added only when the host advertises the bit, and the
 * legacy fields keep their schema-13 meaning during an arrangement lease.
 */
#pragma once

#include "plank_arrangement.h"
#include "plank_arrangement_json.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace plank::topology {
  /**
   * @brief One live output, already sorted by desktop position.
   */
  struct document_output_t {
    std::string id;  ///< Opaque output ID, `x11:<connector>`.
    std::string name;  ///< Connector name.
    int x {};  ///< Desktop X.
    int y {};  ///< Desktop Y.
    int width {};  ///< Width.
    int height {};  ///< Height.
    int rotation {};  ///< Clockwise rotation.
    int refresh_millihz {};  ///< Refresh rate, 0 when unknown.
    bool primary {};  ///< Primary output.
  };

  /**
   * @brief The legacy (schema-13) layout view.
   */
  struct document_layout_t {
    std::string kind;  ///< `physical`, `single` or `dual-horizontal`.
    bool virtual_layout {};  ///< `layout.virtual`.
    std::vector<std::string> virtual_modes;  ///< `layout.virtual_modes`.
    std::string startup_kind;  ///< `layout.startup_kind`.
    std::vector<std::string> allowed_kinds;  ///< `layout.allowed_kinds`.
  };

  /**
   * @brief Display-arrangement additions (feature 0x8000000).
   */
  struct arrangement_view_t {
    std::string startup_policy;  ///< `physical`, `virtual` or `hybrid`.
    std::string request;  ///< Live canonical arrangement, or empty.
    std::string state {"idle"};  ///< `idle`, `pending`, `applied` or `failed`.
    std::string reason;  ///< Transition reason, or empty.
    std::map<std::string, std::pair<std::string, int>> outputs;  ///< Output ID -> {backing, arrangement index}.
    plank::arrangement::capabilities_t capabilities;  ///< `display_capabilities`.
    bool lease {};  ///< An arrangement lease is live: publish `capture_size` and `capture_rect`.
    /**
     * Packed capture: `capture_size` and each output's `capture_rect`. Without
     * it the capture is the desktop and `capture_rect` equals `source_rect`.
     */
    std::optional<std::pair<int, int>> capture_size;
    std::map<std::string, plank::arrangement::rect_t> capture_rects;  ///< Output ID -> capture rectangle.
  };

  /**
   * @brief Build the topology document.
   *
   * @param schema_version Protocol version.
   * @param features Advertised feature bits.
   * @param outputs Live outputs sorted by x, y, id.
   * @param layout Legacy layout view.
   * @param arrangement Arrangement additions, only when the bit is advertised.
   * @param generation Topology generation.
   * @return The JSON document.
   */
  inline nlohmann::json topology_document(
    std::uint32_t schema_version,
    std::uint32_t features,
    const std::vector<document_output_t> &outputs,
    const document_layout_t &layout,
    const std::optional<arrangement_view_t> &arrangement,
    const std::string &generation
  ) {
    int min_x = 0;
    int min_y = 0;
    int max_x = 0;
    int max_y = 0;
    bool first = true;
    for (const auto &output : outputs) {
      if (first) {
        min_x = output.x;
        min_y = output.y;
        max_x = output.x + output.width;
        max_y = output.y + output.height;
        first = false;
      } else {
        min_x = std::min(min_x, output.x);
        min_y = std::min(min_y, output.y);
        max_x = std::max(max_x, output.x + output.width);
        max_y = std::max(max_y, output.y + output.height);
      }
    }
    nlohmann::json layout_json {
      {"kind", layout.kind},
      {"virtual", layout.virtual_layout},
      {"virtual_modes", layout.virtual_modes},
      {"output_count", outputs.size()},
      {"startup_kind", layout.startup_kind},
      {"allowed_kinds", layout.allowed_kinds},
    };
    if (arrangement) {
      layout_json["startup_policy"] = arrangement->startup_policy;
      layout_json["arrangement"] = {
        {"request", arrangement->request},
        {"transition", {{"state", arrangement->state}, {"reason", arrangement->reason}}},
      };
    }
    nlohmann::json body {
      {"schema_version", schema_version},
      {"feature_flags", features},
      {"layout", layout_json},
      {"outputs", nlohmann::json::array()},
    };
    for (std::size_t index = 0; index < outputs.size(); ++index) {
      const auto &output = outputs[index];
      const std::string configured_mode = !layout.virtual_layout ? std::string {} :
        index < layout.virtual_modes.size() ? layout.virtual_modes[index] :
                                              std::string {};
      nlohmann::json item {
        {"id", output.id},
        {"name", output.name},
        {"x", output.x},
        {"y", output.y},
        {"width", output.width},
        {"height", output.height},
        {"rotation", output.rotation},
        {"refresh_millihz", output.refresh_millihz},
        {"primary", output.primary},
        {"virtual", layout.virtual_layout},
        {"configured_mode", configured_mode},
        {"source_rect", {
          {"x", output.x - min_x},
          {"y", output.y - min_y},
          {"width", output.width},
          {"height", output.height},
        }},
      };
      if (arrangement && arrangement->lease) {
        // `source_rect` keeps its schema-13 meaning (inside the desktop, which
        // older parsers require); the encoded position is `capture_rect`.
        item["capture_rect"] = item["source_rect"];
        if (const auto packed = arrangement->capture_rects.find(output.id);
            arrangement->capture_size && packed != arrangement->capture_rects.end()) {
          item["capture_rect"] = {
            {"x", packed->second.x},
            {"y", packed->second.y},
            {"width", packed->second.width},
            {"height", packed->second.height},
          };
        }
      }
      if (arrangement) {
        const auto found = arrangement->outputs.find(output.id);
        item["backing"] = found == arrangement->outputs.end() ? std::string {"physical"} :
                                                                 found->second.first;
        item["arrangement_index"] = found == arrangement->outputs.end() ? -1 : found->second.second;
      }
      body["outputs"].push_back(std::move(item));
    }
    body["desktop"] = {
      {"x", min_x}, {"y", min_y}, {"width", max_x - min_x}, {"height", max_y - min_y},
    };
    body["generation"] = generation;
    if (arrangement && arrangement->lease) {
      // Not `capture`: that key marks the macOS fixed-capture document, and
      // older clients route any document containing it to that parser.
      const auto capture = arrangement->capture_size.value_or(std::pair {max_x - min_x, max_y - min_y});
      body["capture_size"] = {{"width", capture.first}, {"height", capture.second}};
    }
    if (arrangement) {
      body["display_capabilities"] = plank::arrangement::capabilities_json(arrangement->capabilities);
    }
    return body;
  }
}  // namespace plank::topology
