/**
 * @file src/plank_arrangement.h
 * @brief Pure display-arrangement grammar, validation and backing rule (feature 0x8000000).
 *
 * The contract lives in protocol/output-topology.md, "Display arrangement
 * extension", and is pinned by tests/protocol/display-arrangement-v1.json
 * (a byte-identical copy lives in tests/fixtures/protocol). The host is the
 * authority: clients port resolve() only to preview a layout.
 */
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace plank::arrangement {
  inline constexpr std::size_t maximum_request_size = 160;  ///< Whole request string, in bytes.
  inline constexpr std::size_t maximum_entries = 4;  ///< GPU head budget.
  inline constexpr int capabilities_version = 1;  ///< `display_capabilities.version`.

  /**
   * @brief Where a client wants an entry to be shown.
   */
  enum class preference_t {
    automatic,  ///< `auto`: physical exact mode first, else virtual, else physical viewport.
    physical,  ///< `physical`: a physical output only.
    virtual_output,  ///< `virtual`: a virtual head only.
  };

  /**
   * @brief How the host presents one entry.
   */
  enum class backing_t {
    physical,  ///< A physical output at an exact mode, no scaling.
    physical_viewport,  ///< A physical output's preferred mode with ViewPortIn at the entry size.
    virtual_output,  ///< A virtual head with a pool carrier timing and ViewPortIn at the entry size.
  };

  /**
   * @brief Error codes returned in `PlankDisplayArrangementError`.
   */
  enum class error_t {
    none,  ///< No error.
    malformed,  ///< Not in the grammar, or too long.
    not_canonical,  ///< Parsed, but not byte-identical to its canonical form.
    odd_value,  ///< A width, height or offset is odd.
    origin_not_zero,  ///< The smallest X or Y is not 0.
    overlap,  ///< Two outputs overlap.
    output_too_small,  ///< An output is below `output_limits`.
    output_too_large,  ///< An output exceeds `output_limits`.
    canvas_too_large,  ///< The desktop bounding box exceeds `max_canvas`.
    too_many_displays,  ///< Too many entries, or no output left for an `auto` entry.
    no_physical_output,  ///< A `physical` entry found no free physical output.
    no_virtual_output,  ///< A `virtual` entry found no free virtual head.
    not_negotiated,  ///< The launch did not negotiate feature 0x8000000.
  };

  /**
   * @brief Desktop rectangle in pixels.
   */
  struct rect_t {
    int x {};  ///< Left edge.
    int y {};  ///< Top edge.
    int width {};  ///< Width.
    int height {};  ///< Height.
  };

  /**
   * @brief One requested output.
   */
  struct entry_t {
    rect_t rect;  ///< Requested size and desktop position.
    preference_t preference {preference_t::automatic};  ///< Requested backing preference.
  };

  /**
   * @brief A parsed arrangement request; entry 0 is the primary output.
   */
  struct request_t {
    std::vector<entry_t> entries;  ///< Entries in request order.
  };

  /**
   * @brief Per-output size limits published in `output_limits`.
   */
  struct output_limits_t {
    int min_width {640};  ///< Smallest output width.
    int min_height {480};  ///< Smallest output height.
    int max_width {8192};  ///< Largest output width.
    int max_height {8192};  ///< Largest output height.
    std::int64_t max_pixels {33177600};  ///< Largest output area.
  };

  /**
   * @brief One connected non-PLANK output in `physical_outputs`.
   */
  struct physical_output_t {
    std::string id;  ///< Opaque output ID, `x11:<connector>`.
    std::string name;  ///< RandR connector name.
    std::string display_name;  ///< Human-readable monitor name.
    std::string edid_sha256;  ///< Lower-case hex SHA-256 of the EDID, or empty.
    std::string preferred;  ///< Preferred mode, `WxH`.
    std::vector<std::string> modes;  ///< 60 Hz progressive modes, area then width descending.
  };

  /**
   * @brief One encoding mode's size limits in `encoding_limits`.
   */
  struct encoding_limit_t {
    int width {};  ///< Encoder maximum width.
    int height {};  ///< Encoder maximum height.
    int qualified_width {};  ///< Width qualified in real time.
    int qualified_height {};  ///< Height qualified in real time.
  };

  /**
   * @brief `display_capabilities`, the host side of the backing rule.
   */
  struct capabilities_t {
    int version {capabilities_version};  ///< Capabilities schema version.
    std::string fingerprint;  ///< Opaque; changes whenever anything below changes.
    int max_outputs {};  ///< Head budget, at most 4.
    int virtual_heads {};  ///< Virtual heads reserved at boot.
    int max_canvas_width {8192};  ///< Largest desktop bounding-box width.
    int max_canvas_height {8192};  ///< Largest desktop bounding-box height.
    bool packed_capture {};  ///< Whether capture may pack outputs (always false for now).
    output_limits_t output_limits;  ///< Per-output limits.
    std::vector<int> refresh_millihz {60000};  ///< Offered refresh rates.
    std::vector<physical_output_t> physical_outputs;  ///< Connected physical outputs.
    std::map<std::string, encoding_limit_t> encoding_limits;  ///< Limits per encoding mode.
  };

  /**
   * @brief How the host presents one entry after the backing rule.
   */
  struct resolved_output_t {
    std::size_t index {};  ///< Entry number in the request.
    backing_t backing {backing_t::virtual_output};  ///< Chosen backing.
    int head {};  ///< 1-based virtual head (virtual backing only).
    std::string output;  ///< Physical output ID (physical backings only).
    std::string mode;  ///< Driven physical mode, `WxH` (physical backings only).
    std::string carrier;  ///< Pool carrier timing, `WxH` (virtual backing only).
    rect_t rect;  ///< Desktop rectangle.
  };

  /**
   * @brief The complete backing decision for a request.
   */
  struct resolution_t {
    std::vector<resolved_output_t> outputs;  ///< In request order.
    std::vector<std::string> hidden_physical;  ///< Physical output IDs switched off for the lease.
    int desktop_width {};  ///< Bounding-box width.
    int desktop_height {};  ///< Bounding-box height.
  };

  /**
   * @brief Outcome of parsing: a request or an error, never both.
   */
  struct parse_result_t {
    std::optional<request_t> request;  ///< The request when `error` is none.
    error_t error {error_t::none};  ///< The first failing check.
  };

  /**
   * @brief Outcome of the complete check sequence.
   */
  struct resolve_result_t {
    std::optional<resolution_t> resolution;  ///< The resolution when `error` is none.
    error_t error {error_t::none};  ///< The first failing check.
  };

  /** @brief The wire code for an error, for example `too_many_displays`; empty for none. */
  std::string_view error_code(error_t error);

  /** @brief The wire name of a backing: `physical`, `physical-viewport` or `virtual`. */
  std::string_view backing_name(backing_t backing);

  /** @brief The wire name of a preference: `auto`, `physical` or `virtual`. */
  std::string_view preference_name(preference_t preference);

  /**
   * @brief Checks 1-6: length, grammar, entry count, canonical form, odd values, origin.
   *
   * @param text Request exactly as received.
   * @return The request, or the first failing check.
   */
  parse_result_t parse(std::string_view text);

  /** @brief Canonical serialisation, the only form carried anywhere. */
  std::string serialize(const request_t &request);

  /**
   * @brief Checks 7-10: per-entry limits, overlap, canvas, output count.
   *
   * @param request A parsed request.
   * @param capabilities Host capabilities.
   * @return The first failing check, or none.
   */
  error_t validate(const request_t &request, const capabilities_t &capabilities);

  /**
   * @brief Check 11: the backing rule.
   *
   * @param request A validated request.
   * @param capabilities Host capabilities.
   * @return The backing of every entry, or the failing entry's error.
   */
  resolve_result_t resolve(const request_t &request, const capabilities_t &capabilities);

  /**
   * @brief Every check in contract order, from the raw string to a resolution.
   *
   * @param text Request exactly as received.
   * @param capabilities Host capabilities.
   * @return The resolution, or the first failing check.
   */
  resolve_result_t evaluate(std::string_view text, const capabilities_t &capabilities);

  /**
   * @brief Carrier timing from the virtual EDID pool for an output of `width`x`height`.
   *
   * The exact pool mode; otherwise the smallest-area mode that covers the
   * size; otherwise the smallest `max(W/cw, H/ch)`, ties to the larger area,
   * then pool order.
   */
  std::string carrier_for(int width, int height);

  /**
   * @brief Largest per-axis downscale of an output over its carrier or viewport mode.
   *
   * @return `max(width/carrier_width, height/carrier_height)`, or 0 for invalid input.
   */
  double downscale_factor(int width, int height, std::string_view carrier);

  /**
   * @brief The equivalent `auto` arrangement for a legacy host layout.
   *
   * `single` is one output at `+0+0`; `dual-horizontal` places the second output
   * to the right of the first. Both outputs are top-aligned.
   *
   * @return The request, or no value for another layout or an unknown mode.
   */
  std::optional<request_t> from_legacy(
    std::string_view layout, std::string_view mode_1, std::string_view mode_2
  );

  /** @brief Bounding box of the request's rectangles (origin assumed at 0,0). */
  rect_t desktop_bounds(const request_t &request);

  /** @brief `WxH`. */
  std::string mode_name(int width, int height);

  /** @brief Parse `WxH` with positive decimal values; no value when malformed. */
  std::optional<std::pair<int, int>> parse_mode_name(std::string_view mode);
}  // namespace plank::arrangement
