/**
 * @file src/session/display_qualify.h
 * @brief Command line and report of the supervisor's display qualification modes.
 *
 * `plank-host-supervisor --qualify-arrangement REQUEST` applies one display
 * arrangement to the active seat0 X server with the lease transaction the
 * supervisor uses for clients, holds it, restores it and reports both steps.
 * `--print-inventory` prints the display inventory and the derived
 * `display_capabilities`. Both are root-only hardware qualification tools.
 */
#pragma once

#include "display_inventory.h"
#include "display_metamode.h"
#include "session_context.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace plank::display {
  inline constexpr int default_hold_seconds = 10;  ///< Hold time when `--hold` is omitted.
  inline constexpr int maximum_hold_seconds = 3600;  ///< Longest accepted `--hold`.

  /**
   * @brief Exit codes of the qualification modes.
   */
  enum qualification_exit_t : int {
    qualification_passed = 0,  ///< Applied, verified, restored and verified.
    qualification_failed = 1,  ///< Apply, verify or restore failed (the display was restored or recovered).
    qualification_usage = 2,  ///< Invalid command line.
    qualification_refused = 3,  ///< Preconditions not met; nothing was changed.
    qualification_rejected = 4,  ///< The host cannot present the arrangement; nothing was changed.
  };

  /**
   * @brief Parsed supervisor command line.
   */
  struct supervisor_options_t {
    /**
     * @brief What the binary does.
     */
    enum class run_mode_t {
      supervise,  ///< The boot-time supervisor (default).
      qualify,  ///< `--qualify-arrangement`.
      print_inventory,  ///< `--print-inventory`.
    } mode {run_mode_t::supervise};
    std::string worker {"/usr/bin/plank-host"};  ///< `--worker` (supervise only).
    std::string request;  ///< Canonical arrangement (qualify only).
    int hold_seconds {default_hold_seconds};  ///< `--hold` (qualify only).
    bool json {};  ///< `--json` (qualify and print-inventory).
    std::string capture_mode;  ///< `--capture MODE`: run the media worker's capture probe during the hold.
    int capture_frames {120};  ///< `--capture-frames` (with `--capture`).
    std::string capture_output {"/var/tmp/plank-capture-probe"};  ///< `--capture-output` (with `--capture`).
  };

  /**
   * @brief Outcome of command-line parsing.
   */
  struct supervisor_options_result_t {
    std::optional<supervisor_options_t> options;  ///< The options, when valid.
    std::string error;  ///< Why the command line is invalid.
  };

  /**
   * @brief Parse the supervisor's arguments (without the program name).
   *
   * The qualification request must be a canonical arrangement; its host checks
   * happen later against the live inventory. Options that do not belong to
   * the selected mode, repeated options and unknown arguments are refused.
   */
  supervisor_options_result_t parse_supervisor_options(const std::vector<std::string_view> &arguments);

  /** @brief The usage text for all modes. */
  std::string supervisor_usage(std::string_view program);

  /**
   * @brief What a qualification run may not disturb.
   */
  struct qualification_preconditions_t {
    bool root {};  ///< Effective UID 0.
    std::string startup_policy;  ///< `physical`, `virtual`, `hybrid` or `invalid`.
    bool display_state_present {};  ///< /run/plank/host/display-state exists (any lease).
    std::optional<plank::session::display_transition_t> transition;  ///< Published transition, if any.
    std::int64_t now {};  ///< Wall-clock seconds.
    bool qualification_live {};  ///< Another qualification holds the qualification lock.
  };

  /**
   * @brief Why qualification must not run now, or an empty string.
   *
   * Refused when not root, under the virtual (or an invalid) policy, while
   * any PLANK display lease exists, while a transition is pending, or while
   * another qualification runs. `--print-inventory` changes nothing and only
   * needs root.
   */
  std::string qualification_refusal(const qualification_preconditions_t &preconditions);

  /** @brief The inventory as JSON (the cache's fields). */
  nlohmann::json inventory_json(const inventory_t &inventory);

  /** @brief A plan and its visibility arguments as JSON. */
  nlohmann::json plan_json(const arrangement_plan_t &plan, const std::vector<std::string> &visibility);

  /** @brief A live xrandr state as JSON: screen size and every output's rectangle and visibility. */
  nlohmann::json screen_json(const randr_screen_t &screen);

  /** @brief A short human-readable rendering of a qualification or inventory report. */
  std::string report_text(const nlohmann::json &report);
}  // namespace plank::display
