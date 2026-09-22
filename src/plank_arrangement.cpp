/**
 * @file src/plank_arrangement.cpp
 * @brief Pure display-arrangement grammar, validation and backing rule (feature 0x8000000).
 */
#include "plank_arrangement.h"

#include "plank_topology.h"

#include <algorithm>
#include <charconv>
#include <limits>

namespace plank::arrangement {
  namespace {
    constexpr std::string_view version_prefix = "1:";

    /** Read one decimal number; values beyond int saturate (they can never be canonical). */
    bool read_number(std::string_view text, std::size_t &cursor, int &value) {
      const auto start = cursor;
      std::int64_t parsed = 0;
      while (cursor < text.size() && text[cursor] >= '0' && text[cursor] <= '9') {
        parsed = std::min<std::int64_t>(
          parsed * 10 + (text[cursor] - '0'), std::numeric_limits<int>::max()
        );
        ++cursor;
      }
      value = static_cast<int>(parsed);
      return cursor > start;
    }

    bool read_literal(std::string_view text, std::size_t &cursor, char literal) {
      if (cursor >= text.size() || text[cursor] != literal) return false;
      ++cursor;
      return true;
    }

    std::optional<entry_t> parse_entry(std::string_view text) {
      entry_t entry;
      std::size_t cursor = 0;
      if (!read_number(text, cursor, entry.rect.width) || !read_literal(text, cursor, 'x') ||
          !read_number(text, cursor, entry.rect.height) || !read_literal(text, cursor, '+') ||
          !read_number(text, cursor, entry.rect.x) || !read_literal(text, cursor, '+') ||
          !read_number(text, cursor, entry.rect.y) || !read_literal(text, cursor, ':')) {
        return std::nullopt;
      }
      const auto preference = text.substr(cursor);
      if (preference == "auto") entry.preference = preference_t::automatic;
      else if (preference == "physical") entry.preference = preference_t::physical;
      else if (preference == "virtual") entry.preference = preference_t::virtual_output;
      else return std::nullopt;
      return entry;
    }

    bool odd(int value) {
      return (value & 1) != 0;
    }

    bool overlaps(const rect_t &left, const rect_t &right) {
      const auto l_right = static_cast<std::int64_t>(left.x) + left.width;
      const auto l_bottom = static_cast<std::int64_t>(left.y) + left.height;
      const auto r_right = static_cast<std::int64_t>(right.x) + right.width;
      const auto r_bottom = static_cast<std::int64_t>(right.y) + right.height;
      return left.x < r_right && right.x < l_right && left.y < r_bottom && right.y < l_bottom;
    }

    /** A ratio `numerator / denominator` with exact comparison. */
    struct ratio_t {
      std::int64_t numerator {};
      std::int64_t denominator {1};
    };

    bool operator<(const ratio_t &left, const ratio_t &right) {
      return left.numerator * right.denominator < right.numerator * left.denominator;
    }

    bool operator==(const ratio_t &left, const ratio_t &right) {
      return left.numerator * right.denominator == right.numerator * left.denominator;
    }

    /** `max(width / carrier_width, height / carrier_height)`. */
    ratio_t downscale_ratio(int width, int height, int carrier_width, int carrier_height) {
      // width/cw >= height/ch  <=>  width*ch >= height*cw
      if (static_cast<std::int64_t>(width) * carrier_height >=
          static_cast<std::int64_t>(height) * carrier_width) {
        return {width, carrier_width};
      }
      return {height, carrier_height};
    }
  }  // namespace

  std::string_view error_code(error_t error) {
    switch (error) {
      case error_t::none: return "";
      case error_t::malformed: return "malformed";
      case error_t::not_canonical: return "not_canonical";
      case error_t::odd_value: return "odd_value";
      case error_t::origin_not_zero: return "origin_not_zero";
      case error_t::overlap: return "overlap";
      case error_t::output_too_small: return "output_too_small";
      case error_t::output_too_large: return "output_too_large";
      case error_t::canvas_too_large: return "canvas_too_large";
      case error_t::too_many_displays: return "too_many_displays";
      case error_t::no_physical_output: return "no_physical_output";
      case error_t::no_virtual_output: return "no_virtual_output";
      case error_t::not_negotiated: return "not_negotiated";
    }
    return "malformed";
  }

  std::string_view backing_name(backing_t backing) {
    switch (backing) {
      case backing_t::physical: return "physical";
      case backing_t::physical_viewport: return "physical-viewport";
      case backing_t::virtual_output: return "virtual";
    }
    return "virtual";
  }

  std::string_view preference_name(preference_t preference) {
    switch (preference) {
      case preference_t::automatic: return "auto";
      case preference_t::physical: return "physical";
      case preference_t::virtual_output: return "virtual";
    }
    return "auto";
  }

  std::string mode_name(int width, int height) {
    return std::to_string(width) + "x" + std::to_string(height);
  }

  std::optional<std::pair<int, int>> parse_mode_name(std::string_view mode) {
    const auto separator = mode.find('x');
    if (separator == std::string_view::npos) return std::nullopt;
    int width {};
    int height {};
    const auto width_text = mode.substr(0, separator);
    const auto height_text = mode.substr(separator + 1);
    const auto width_result = std::from_chars(
      width_text.data(), width_text.data() + width_text.size(), width
    );
    const auto height_result = std::from_chars(
      height_text.data(), height_text.data() + height_text.size(), height
    );
    if (width_text.empty() || height_text.empty() ||
        width_result.ec != std::errc {} || height_result.ec != std::errc {} ||
        width_result.ptr != width_text.data() + width_text.size() ||
        height_result.ptr != height_text.data() + height_text.size() ||
        width <= 0 || height <= 0) {
      return std::nullopt;
    }
    return std::pair {width, height};
  }

  parse_result_t parse(std::string_view text) {
    // 1. Length.
    if (text.size() > maximum_request_size) return {std::nullopt, error_t::malformed};
    // 2. Grammar.
    if (!text.starts_with(version_prefix)) return {std::nullopt, error_t::malformed};
    request_t request;
    auto rest = text.substr(version_prefix.size());
    while (true) {
      const auto comma = rest.find(',');
      const auto entry = parse_entry(rest.substr(0, comma));
      if (!entry) return {std::nullopt, error_t::malformed};
      request.entries.push_back(*entry);
      if (comma == std::string_view::npos) break;
      rest = rest.substr(comma + 1);
    }
    // 3. More than four entries.
    if (request.entries.size() > maximum_entries) {
      return {std::nullopt, error_t::too_many_displays};
    }
    // 4. Canonical form.
    if (serialize(request) != text) return {std::nullopt, error_t::not_canonical};
    // 5. Odd values.
    for (const auto &entry : request.entries) {
      if (odd(entry.rect.width) || odd(entry.rect.height) || odd(entry.rect.x) ||
          odd(entry.rect.y)) {
        return {std::nullopt, error_t::odd_value};
      }
    }
    // 6. Origin.
    int minimum_x = std::numeric_limits<int>::max();
    int minimum_y = std::numeric_limits<int>::max();
    for (const auto &entry : request.entries) {
      minimum_x = std::min(minimum_x, entry.rect.x);
      minimum_y = std::min(minimum_y, entry.rect.y);
    }
    if (minimum_x != 0 || minimum_y != 0) return {std::nullopt, error_t::origin_not_zero};
    return {std::move(request), error_t::none};
  }

  std::string serialize(const request_t &request) {
    std::string text {version_prefix};
    for (std::size_t index = 0; index < request.entries.size(); ++index) {
      const auto &entry = request.entries[index];
      if (index > 0) text += ',';
      text += mode_name(entry.rect.width, entry.rect.height) + "+" +
              std::to_string(entry.rect.x) + "+" + std::to_string(entry.rect.y) + ":" +
              std::string {preference_name(entry.preference)};
    }
    return text;
  }

  rect_t desktop_bounds(const request_t &request) {
    std::int64_t right = 0;
    std::int64_t bottom = 0;
    for (const auto &entry : request.entries) {
      right = std::max<std::int64_t>(right, static_cast<std::int64_t>(entry.rect.x) + entry.rect.width);
      bottom = std::max<std::int64_t>(bottom, static_cast<std::int64_t>(entry.rect.y) + entry.rect.height);
    }
    constexpr std::int64_t cap = std::numeric_limits<int>::max();
    return {0, 0, static_cast<int>(std::min(right, cap)), static_cast<int>(std::min(bottom, cap))};
  }

  error_t validate(const request_t &request, const capabilities_t &capabilities) {
    const auto &limits = capabilities.output_limits;
    // 7. Per-entry limits, in entry order.
    for (const auto &entry : request.entries) {
      const auto &rect = entry.rect;
      if (rect.width < limits.min_width || rect.height < limits.min_height) {
        return error_t::output_too_small;
      }
      if (rect.width > limits.max_width || rect.height > limits.max_height ||
          static_cast<std::int64_t>(rect.width) * rect.height > limits.max_pixels) {
        return error_t::output_too_large;
      }
    }
    // 8. Overlap.
    for (std::size_t left = 0; left < request.entries.size(); ++left) {
      for (std::size_t right = left + 1; right < request.entries.size(); ++right) {
        if (overlaps(request.entries[left].rect, request.entries[right].rect)) {
          return error_t::overlap;
        }
      }
    }
    // 9. Canvas.
    const auto bounds = desktop_bounds(request);
    if (bounds.width > capabilities.max_canvas_width ||
        bounds.height > capabilities.max_canvas_height) {
      return error_t::canvas_too_large;
    }
    // 10. More entries than max_outputs.
    if (request.entries.size() > static_cast<std::size_t>(std::max(capabilities.max_outputs, 0))) {
      return error_t::too_many_displays;
    }
    return error_t::none;
  }

  std::string carrier_for(int width, int height) {
    const auto &pool = plank::topology::virtual_mode_pool;
    for (const auto mode : pool) {
      const auto size = plank::topology::virtual_mode_size(mode);
      if (size.width == width && size.height == height) return std::string {mode};
    }
    std::string_view covering;
    std::int64_t covering_area = 0;
    for (const auto mode : pool) {
      const auto size = plank::topology::virtual_mode_size(mode);
      const auto area = static_cast<std::int64_t>(size.width) * size.height;
      if (size.width >= width && size.height >= height &&
          (covering.empty() || area < covering_area)) {
        covering = mode;
        covering_area = area;
      }
    }
    if (!covering.empty()) return std::string {covering};
    std::string_view best;
    ratio_t best_ratio;
    std::int64_t best_area = 0;
    for (const auto mode : pool) {
      const auto size = plank::topology::virtual_mode_size(mode);
      const auto ratio = downscale_ratio(width, height, size.width, size.height);
      const auto area = static_cast<std::int64_t>(size.width) * size.height;
      if (best.empty() || ratio < best_ratio || (ratio == best_ratio && area > best_area)) {
        best = mode;
        best_ratio = ratio;
        best_area = area;
      }
    }
    return std::string {best};
  }

  double downscale_factor(int width, int height, std::string_view carrier) {
    const auto size = parse_mode_name(carrier);
    if (!size || width <= 0 || height <= 0) return 0.0;
    const auto ratio = downscale_ratio(width, height, size->first, size->second);
    return static_cast<double>(ratio.numerator) / static_cast<double>(ratio.denominator);
  }

  resolve_result_t resolve(const request_t &request, const capabilities_t &capabilities) {
    const auto &physical = capabilities.physical_outputs;
    std::vector<bool> physical_used(physical.size(), false);
    std::vector<std::optional<resolved_output_t>> assigned(request.entries.size());
    const auto make = [&](std::size_t index, backing_t backing) {
      resolved_output_t output;
      output.index = index;
      output.backing = backing;
      output.rect = request.entries[index].rect;
      return output;
    };

    // 1. Exact physical modes.
    for (std::size_t index = 0; index < request.entries.size(); ++index) {
      const auto &entry = request.entries[index];
      if (entry.preference == preference_t::virtual_output) continue;
      const auto wanted = mode_name(entry.rect.width, entry.rect.height);
      for (std::size_t candidate = 0; candidate < physical.size(); ++candidate) {
        if (physical_used[candidate]) continue;
        const auto &modes = physical[candidate].modes;
        if (std::find(modes.begin(), modes.end(), wanted) == modes.end()) continue;
        auto output = make(index, backing_t::physical);
        output.output = physical[candidate].id;
        output.mode = wanted;
        assigned[index] = std::move(output);
        physical_used[candidate] = true;
        break;
      }
    }
    // 2. Virtual heads.
    int next_head = 1;
    for (std::size_t index = 0; index < request.entries.size(); ++index) {
      const auto &entry = request.entries[index];
      if (assigned[index] || entry.preference == preference_t::physical) continue;
      if (next_head > capabilities.virtual_heads) break;
      auto output = make(index, backing_t::virtual_output);
      output.head = next_head++;
      output.carrier = carrier_for(entry.rect.width, entry.rect.height);
      assigned[index] = std::move(output);
    }
    // 3. Physical viewports over the preferred mode.
    for (std::size_t index = 0; index < request.entries.size(); ++index) {
      const auto &entry = request.entries[index];
      if (assigned[index] || entry.preference == preference_t::virtual_output) continue;
      for (std::size_t candidate = 0; candidate < physical.size(); ++candidate) {
        if (physical_used[candidate] || physical[candidate].preferred.empty()) continue;
        auto output = make(index, backing_t::physical_viewport);
        output.output = physical[candidate].id;
        output.mode = physical[candidate].preferred;
        assigned[index] = std::move(output);
        physical_used[candidate] = true;
        break;
      }
    }
    // 4. Anything left fails the request.
    resolution_t resolution;
    for (std::size_t index = 0; index < request.entries.size(); ++index) {
      if (!assigned[index]) {
        switch (request.entries[index].preference) {
          case preference_t::physical: return {std::nullopt, error_t::no_physical_output};
          case preference_t::virtual_output: return {std::nullopt, error_t::no_virtual_output};
          case preference_t::automatic: return {std::nullopt, error_t::too_many_displays};
        }
      }
      resolution.outputs.push_back(std::move(*assigned[index]));
    }
    // 5. Unassigned physical outputs are switched off.
    for (std::size_t candidate = 0; candidate < physical.size(); ++candidate) {
      if (!physical_used[candidate]) resolution.hidden_physical.push_back(physical[candidate].id);
    }
    const auto bounds = desktop_bounds(request);
    resolution.desktop_width = bounds.width;
    resolution.desktop_height = bounds.height;
    return {std::move(resolution), error_t::none};
  }

  resolve_result_t evaluate(std::string_view text, const capabilities_t &capabilities) {
    const auto parsed = parse(text);
    if (!parsed.request) return {std::nullopt, parsed.error};
    if (const auto error = validate(*parsed.request, capabilities); error != error_t::none) {
      return {std::nullopt, error};
    }
    return resolve(*parsed.request, capabilities);
  }

  capture_result_t pack(const request_t &request, int limit_width, int limit_height) {
    const auto bounds = desktop_bounds(request);
    capture_plan_t plan;
    if (bounds.width <= limit_width && bounds.height <= limit_height) {
      plan.width = bounds.width;
      plan.height = bounds.height;
      for (const auto &entry : request.entries) plan.source_rects.push_back(entry.rect);
      return {std::move(plan), error_t::none};
    }
    plan.packed = true;
    std::int64_t row_y = 0;
    std::int64_t row_x = 0;
    std::int64_t row_height = 0;
    std::int64_t width = 0;
    for (const auto &entry : request.entries) {
      const auto &rect = entry.rect;
      if (rect.width > limit_width) return {std::nullopt, error_t::canvas_too_large};
      if (row_x > 0 && row_x + rect.width > limit_width) {
        row_y += row_height;
        row_x = 0;
        row_height = 0;
      }
      plan.source_rects.push_back({
        static_cast<int>(row_x), static_cast<int>(row_y), rect.width, rect.height,
      });
      row_x += rect.width;
      row_height = std::max<std::int64_t>(row_height, rect.height);
      width = std::max(width, row_x);
    }
    const auto height = row_y + row_height;
    if (height > limit_height) return {std::nullopt, error_t::canvas_too_large};
    plan.width = static_cast<int>(width);
    plan.height = static_cast<int>(height);
    return {std::move(plan), error_t::none};
  }

  capture_result_t plan_capture(
    const request_t &request, const capabilities_t &capabilities, std::string_view encoding_mode
  ) {
    const auto limit = capabilities.encoding_limits.find(std::string {encoding_mode});
    if (limit == capabilities.encoding_limits.end()) {
      return pack(request, std::numeric_limits<int>::max(), std::numeric_limits<int>::max());
    }
    auto result = pack(request, limit->second.width, limit->second.height);
    if (!capabilities.packed_capture && result.plan && result.plan->packed) {
      return {std::nullopt, error_t::canvas_too_large};
    }
    return result;
  }

  std::vector<capture_region_t> capture_regions(const request_t &request, const capture_plan_t &plan) {
    std::vector<capture_region_t> regions;
    if (!plan.packed) return regions;
    for (std::size_t index = 0; index < request.entries.size() && index < plan.source_rects.size(); ++index) {
      regions.push_back({request.entries[index].rect, plan.source_rects[index]});
    }
    return regions;
  }

  std::pair<int, int> desktop_to_capture(const std::vector<capture_region_t> &regions, int x, int y) {
    const capture_region_t *best = nullptr;
    std::int64_t best_distance = std::numeric_limits<std::int64_t>::max();
    std::int64_t best_x = x;
    std::int64_t best_y = y;
    for (const auto &region : regions) {
      const auto &rect = region.desktop;
      if (rect.width <= 0 || rect.height <= 0) continue;
      const auto clamped_x = std::clamp<std::int64_t>(x, rect.x, static_cast<std::int64_t>(rect.x) + rect.width - 1);
      const auto clamped_y = std::clamp<std::int64_t>(y, rect.y, static_cast<std::int64_t>(rect.y) + rect.height - 1);
      const auto distance = (clamped_x - x) * (clamped_x - x) + (clamped_y - y) * (clamped_y - y);
      if (distance < best_distance) {
        best = &region;
        best_distance = distance;
        best_x = clamped_x;
        best_y = clamped_y;
      }
    }
    if (best == nullptr) return {x, y};
    return {
      static_cast<int>(best->capture.x + (best_x - best->desktop.x)),
      static_cast<int>(best->capture.y + (best_y - best->desktop.y)),
    };
  }

  std::optional<request_t> from_legacy(
    std::string_view layout, std::string_view mode_1, std::string_view mode_2
  ) {
    if (!plank::topology::valid_virtual_layout_modes(layout, mode_1, mode_2)) return std::nullopt;
    const auto first = plank::topology::virtual_mode_size(mode_1);
    request_t request;
    request.entries.push_back({{0, 0, first.width, first.height}, preference_t::automatic});
    if (layout == "dual-horizontal") {
      const auto second = plank::topology::virtual_mode_size(mode_2);
      request.entries.push_back(
        {{first.width, 0, second.width, second.height}, preference_t::automatic}
      );
    }
    return request;
  }
}  // namespace plank::arrangement
