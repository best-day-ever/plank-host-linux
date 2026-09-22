/**
 * @file src/session/display_metamode.cpp
 * @brief Pure NVIDIA MetaMode parsing and temporary physical-layout planning.
 */
#include "display_metamode.h"

#include "../plank_topology.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <regex>
#include <tuple>

namespace plank::display {
  namespace {
    std::string_view trim_view(std::string_view value) {
      constexpr std::string_view whitespace = " \t\r\n";
      const auto first = value.find_first_not_of(whitespace);
      if (first == std::string_view::npos) return {};
      const auto last = value.find_last_not_of(whitespace);
      return value.substr(first, last - first + 1);
    }

    std::optional<int> parse_int(std::string_view value, int minimum) {
      int parsed {};
      const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
      if (value.empty() || result.ec != std::errc {} ||
          result.ptr != value.data() + value.size() || parsed < minimum) {
        return std::nullopt;
      }
      return parsed;
    }

    std::string_view match_view(const std::csub_match &match) {
      return {match.first, static_cast<std::size_t>(match.second - match.first)};
    }
  }  // namespace

  std::optional<physical_snapshot_t> parse_current_metamode(std::string_view response) {
    constexpr std::size_t maximum_assignment_size = 32U * 1024U;
    const auto separator = response.find("::");
    if (separator == std::string_view::npos) return std::nullopt;
    const auto assignment_view = trim_view(response.substr(separator + 2));
    if (assignment_view.empty() || assignment_view.size() > maximum_assignment_size) {
      return std::nullopt;
    }
    for (const unsigned char character : assignment_view) {
      if (character < 0x20 || character > 0x7e) return std::nullopt;
    }

    std::vector<std::string_view> clauses;
    std::size_t start = 0;
    int brace_depth = 0;
    for (std::size_t index = 0; index <= assignment_view.size(); ++index) {
      const char character = index < assignment_view.size() ? assignment_view[index] : ',';
      if (character == '{') ++brace_depth;
      else if (character == '}') --brace_depth;
      if (brace_depth < 0) return std::nullopt;
      if (character == ',' && brace_depth == 0) {
        clauses.push_back(trim_view(assignment_view.substr(start, index - start)));
        start = index + 1;
      }
    }
    if (brace_depth != 0 || clauses.empty()) return std::nullopt;

    static const std::regex output_name {R"(^[A-Za-z0-9_-]+$)"};
    static const std::regex viewport_out {
      R"(ViewPortOut=([0-9]+)x([0-9]+)\+[0-9]+\+[0-9]+)"
    };
    static const std::regex logical_position {
      R"(@[0-9]+x[0-9]+ \+([0-9]+)\+([0-9]+))"
    };
    physical_snapshot_t snapshot;
    snapshot.assignment = std::string {assignment_view};
    for (const auto clause : clauses) {
      const auto colon = clause.find(':');
      if (colon == std::string_view::npos) return std::nullopt;
      const std::string name {trim_view(clause.substr(0, colon))};
      const auto body = trim_view(clause.substr(colon + 1));
      if (!std::regex_match(name, output_name)) return std::nullopt;
      if (body == "NULL") {
        snapshot.null_outputs.push_back(name);
        continue;
      }
      const auto mode_end = body.find_first_of(" \t");
      if (mode_end == std::string_view::npos) return std::nullopt;
      const std::string mode {body.substr(0, mode_end)};
      if (!std::regex_match(mode, output_name)) return std::nullopt;
      std::cmatch viewport_match;
      std::cmatch position_match;
      if (!std::regex_search(body.data(), body.data() + body.size(), viewport_match, viewport_out) ||
          !std::regex_search(body.data(), body.data() + body.size(), position_match, logical_position)) {
        return std::nullopt;
      }
      const auto width = parse_int(match_view(viewport_match[1]), 1);
      const auto height = parse_int(match_view(viewport_match[2]), 1);
      // The leftmost and topmost outputs legitimately begin at zero.
      const auto x = parse_int(match_view(position_match[1]), 0);
      const auto y = parse_int(match_view(position_match[2]), 0);
      if (!width || !height || !x || !y) return std::nullopt;
      snapshot.outputs.push_back({name, mode, *width, *height, *x, *y});
    }
    if (snapshot.outputs.empty()) return std::nullopt;
    std::sort(snapshot.outputs.begin(), snapshot.outputs.end(), [](const auto &left,
                                                                  const auto &right) {
      return std::tie(left.x, left.name) < std::tie(right.x, right.name);
    });
    return snapshot;
  }

  std::size_t temporary_layout_outputs(std::string_view layout) {
    if (layout == "single") return 1U;
    if (layout == "dual-horizontal") return 2U;
    return 0U;
  }

  std::optional<std::string> temporary_metamode(
    const physical_snapshot_t &snapshot,
    std::string_view layout,
    std::string_view mode_1,
    std::string_view mode_2
  ) {
    const std::size_t required_outputs = temporary_layout_outputs(layout);
    if (required_outputs == 0U || snapshot.outputs.size() < required_outputs) {
      return std::nullopt;
    }
    const std::array<std::string_view, 2> modes {mode_1, mode_2};
    std::string assignment;
    int x = 0;
    for (std::size_t index = 0; index < required_outputs; ++index) {
      const auto requested = plank::topology::virtual_mode_size(modes[index]);
      const auto &physical = snapshot.outputs[index];
      if (requested.width <= 0 || requested.height <= 0) return std::nullopt;
      if (!assignment.empty()) assignment += ", ";
      assignment += physical.name + ": " + physical.mode + " @" +
        std::to_string(requested.width) + "x" + std::to_string(requested.height) +
        " +" + std::to_string(x) + "+0 {ViewPortIn=" +
        std::to_string(requested.width) + "x" + std::to_string(requested.height) +
        ", ViewPortOut=" + std::to_string(physical.native_width) + "x" +
        std::to_string(physical.native_height) + "+0+0}";
      x += requested.width;
    }
    return assignment;
  }

  std::string safe_physical_metamode(const physical_snapshot_t &snapshot) {
    if (snapshot.outputs.empty()) return {};
    const auto &output = snapshot.outputs.front();
    return output.name + ": " + output.mode + " @" +
      std::to_string(output.native_width) + "x" +
      std::to_string(output.native_height) + " +0+0 {ViewPortIn=" +
      std::to_string(output.native_width) + "x" +
      std::to_string(output.native_height) + ", ViewPortOut=" +
      std::to_string(output.native_width) + "x" +
      std::to_string(output.native_height) + "+0+0}";
  }

  std::optional<lease_plan_t> plan_physical_lease(
    const physical_snapshot_t *retained,
    const std::optional<physical_snapshot_t> &captured,
    std::string_view layout,
    std::string_view mode_1,
    std::string_view mode_2
  ) {
    if (retained == nullptr && !captured) return std::nullopt;
    const auto &snapshot = retained != nullptr ? *retained : *captured;
    auto temporary = temporary_metamode(snapshot, layout, mode_1, mode_2);
    if (!temporary) return std::nullopt;
    return lease_plan_t {snapshot, std::move(*temporary)};
  }
}  // namespace plank::display
