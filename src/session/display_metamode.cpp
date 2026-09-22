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

  std::string physical_mode_token(std::string_view mode) {
    return std::string {mode};
  }

  std::optional<arrangement_plan_t> plan_arrangement(
    const plank::arrangement::resolution_t &resolution,
    const inventory_t &inventory,
    std::string &reason
  ) {
    namespace arrangement = plank::arrangement;
    arrangement_plan_t plan;
    plan.width = resolution.desktop_width;
    plan.height = resolution.desktop_height;
    for (const auto &output : inventory.physical) {
      plan.outputs.push_back({output.device.randr, output.device.dpy, true, "off", {}, -1, {}});
    }
    const auto heads = std::min<std::size_t>(
      static_cast<std::size_t>(std::max(inventory.virtual_heads, 0)), inventory.virtual_candidates.size()
    );
    for (std::size_t head = 0; head < heads; ++head) {
      const auto &device = inventory.virtual_candidates[head].device;
      plan.outputs.push_back({device.randr, device.dpy, false, "off", {}, -1, {}});
    }
    if (resolution.outputs.size() > arrangement::maximum_entries) {
      reason = std::string {arrangement::error_code(arrangement::error_t::too_many_displays)};
      return std::nullopt;
    }
    std::vector<std::string> lit;
    for (const auto &output : resolution.outputs) {
      arrangement_output_plan_t *target = nullptr;
      std::string carrier;
      if (output.backing == arrangement::backing_t::virtual_output) {
        if (output.head < 1 || static_cast<std::size_t>(output.head) > heads) {
          reason = std::string {arrangement::error_code(arrangement::error_t::no_virtual_output)};
          return std::nullopt;
        }
        target = &plan.outputs[inventory.physical.size() + static_cast<std::size_t>(output.head) - 1];
        carrier = output.carrier;
      } else {
        const auto randr = randr_name_from_id(output.output);
        for (std::size_t index = 0; index < inventory.physical.size(); ++index) {
          if (plan.outputs[index].randr == randr) target = &plan.outputs[index];
        }
        if (target == nullptr) {
          reason = std::string {arrangement::error_code(arrangement::error_t::no_physical_output)};
          return std::nullopt;
        }
        carrier = output.backing == arrangement::backing_t::physical ?
                    physical_mode_token(output.mode) : output.mode;
      }
      const auto carrier_size = arrangement::parse_mode_name(carrier);
      if (target->backing != "off" || !carrier_size) {
        reason = std::string {arrangement::error_code(arrangement::error_t::too_many_displays)};
        return std::nullopt;
      }
      // Hardware probe P4: ViewPortIn downscales up to 2:1 per axis.
      if (arrangement::downscale_factor(output.rect.width, output.rect.height, carrier) >
          static_cast<double>(maximum_downscale)) {
        reason = std::string {arrangement::error_code(arrangement::error_t::output_too_large)};
        return std::nullopt;
      }
      target->backing = std::string {arrangement::backing_name(output.backing)};
      target->mode = carrier;
      target->index = static_cast<int>(output.index);
      target->rect = output.rect;
      const auto size = arrangement::mode_name(output.rect.width, output.rect.height);
      lit.push_back(target->dpy + ": " + carrier + " @" + size + " +" + std::to_string(output.rect.x) +
                    "+" + std::to_string(output.rect.y) + " {ViewPortIn=" + size +
                    ", ViewPortOut=" + carrier + "+0+0}");
      if (output.index == 0) plan.primary = target->randr;
    }
    // Hardware probe P13: a fifth head is silently dropped, so never ask for one.
    if (lit.size() > arrangement::maximum_entries || plan.primary.empty()) {
      reason = std::string {arrangement::error_code(arrangement::error_t::too_many_displays)};
      return std::nullopt;
    }
    for (const auto &output : plan.outputs) {
      if (output.backing == "off") lit.push_back(output.dpy + ": NULL");
    }
    for (const auto &clause : lit) {
      if (!plan.metamode.empty()) plan.metamode += ", ";
      plan.metamode += clause;
    }
    return plan;
  }

  std::vector<std::string> visibility_arguments(const arrangement_plan_t &plan, bool hide_physical) {
    std::vector<std::string> arguments;
    for (const auto &output : plan.outputs) {
      if (output.backing != "off") {
        arguments.insert(arguments.end(), {"--output", output.randr, "--set", "non-desktop", "0"});
      } else if (!output.physical || hide_physical) {
        arguments.insert(arguments.end(), {"--output", output.randr, "--off", "--set", "non-desktop", "1"});
      }
    }
    return arguments;
  }

  bool arrangement_live(const randr_screen_t &screen, const arrangement_plan_t &plan) {
    if (screen.width != plan.width || screen.height != plan.height) return false;
    for (const auto &output : plan.outputs) {
      const auto live = std::find_if(screen.outputs.begin(), screen.outputs.end(),
                                     [&](const auto &candidate) { return candidate.name == output.randr; });
      if (output.backing == "off") {
        if (live != screen.outputs.end() && live->enabled) return false;
        continue;
      }
      if (live == screen.outputs.end() || !live->enabled || live->x != output.rect.x ||
          live->y != output.rect.y || live->width != output.rect.width ||
          live->height != output.rect.height || (output.index == 0 && !live->primary)) {
        return false;
      }
    }
    return true;
  }

  std::string rest_metamode(const inventory_t &inventory) {
    if (inventory.physical.empty()) return {};
    return inventory.physical.front().device.dpy + ": nvidia-auto-select +0+0";
  }

  std::string boot_metamode(const inventory_t &inventory) {
    std::string metamode;
    int x = 0;
    for (const auto &output : inventory.physical) {
      if (!metamode.empty()) metamode += ", ";
      metamode += output.device.dpy + ": nvidia-auto-select +" + std::to_string(x) + "+0";
      const auto size = plank::arrangement::parse_mode_name(output.preferred);
      x += size ? size->first : 1920;
    }
    const auto heads = std::min<std::size_t>(
      static_cast<std::size_t>(std::max(inventory.virtual_heads, 0)), inventory.virtual_candidates.size()
    );
    for (std::size_t head = 0; head < heads; ++head) {
      if (!metamode.empty()) metamode += ", ";
      metamode += inventory.virtual_candidates[head].device.dpy + ": NULL";
    }
    return metamode;
  }

  std::vector<std::string> hide_virtual_head_arguments(const inventory_t &inventory) {
    std::vector<std::string> arguments;
    const auto heads = std::min<std::size_t>(
      static_cast<std::size_t>(std::max(inventory.virtual_heads, 0)), inventory.virtual_candidates.size()
    );
    for (std::size_t head = 0; head < heads; ++head) {
      arguments.insert(arguments.end(), {
        "--output", inventory.virtual_candidates[head].device.randr, "--off", "--set", "non-desktop", "1"
      });
    }
    return arguments;
  }

  bool rest_needed(
    const physical_snapshot_t &current, const inventory_t &inventory, bool require_all_physical
  ) {
    const auto lit = [&](std::string_view dpy) {
      return std::any_of(current.outputs.begin(), current.outputs.end(),
                         [&](const auto &output) { return output.name == dpy; });
    };
    const auto heads = std::min<std::size_t>(
      static_cast<std::size_t>(std::max(inventory.virtual_heads, 0)), inventory.virtual_candidates.size()
    );
    for (std::size_t head = 0; head < heads; ++head) {
      if (lit(inventory.virtual_candidates[head].device.dpy)) return true;
    }
    if (require_all_physical) {
      for (const auto &output : inventory.physical) {
        if (!lit(output.device.dpy)) return true;
      }
    }
    int minimum_x = current.outputs.empty() ? 0 : current.outputs.front().x;
    int minimum_y = current.outputs.empty() ? 0 : current.outputs.front().y;
    for (const auto &output : current.outputs) {
      minimum_x = std::min(minimum_x, output.x);
      minimum_y = std::min(minimum_y, output.y);
    }
    return minimum_x != 0 || minimum_y != 0;
  }
}  // namespace plank::display
