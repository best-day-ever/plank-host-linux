/**
 * @file src/session/display_metamode.h
 * @brief Pure NVIDIA MetaMode parsing and temporary physical-layout planning.
 *
 * The root supervisor captures `nvidia-settings --query CurrentMetaMode` before
 * it changes a physical-startup X server and restores that exact string at
 * the end of the lease. Everything here is side-effect free so the parser and
 * the layout planner can be unit tested without an X server.
 */
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace plank::display {
  /**
   * @brief One lit scanout parsed from a CurrentMetaMode clause.
   */
  struct physical_output_t {
    std::string name;  ///< NVIDIA display-device name, for example `DPY-5`.
    std::string mode;  ///< Mode token exactly as reported, for example `1920x1080_60`.
    int native_width {};  ///< ViewPortOut width: the scanout's native pixel width.
    int native_height {};  ///< ViewPortOut height: the scanout's native pixel height.
    int x {};  ///< Logical desktop X offset.
    int y {};  ///< Logical desktop Y offset.
  };

  /**
   * @brief Authoritative rollback record for a physical-display lease.
   */
  struct physical_snapshot_t {
    std::string assignment;  ///< The exact MetaMode text, restored byte for byte.
    std::vector<physical_output_t> outputs;  ///< Lit outputs, ordered left to right.
    std::vector<std::string> null_outputs;  ///< Display devices the MetaMode switches off (`NULL`).
  };

  /**
   * @brief Temporary layout for one lease: the retained snapshot and the MetaMode to assign.
   */
  struct lease_plan_t {
    physical_snapshot_t snapshot;  ///< Snapshot restored when the lease ends.
    std::string temporary;  ///< MetaMode applied for the lease.
  };

  /**
   * @brief Parse a terse `CurrentMetaMode` query response.
   *
   * Accepts `... :: <clause>[, <clause>...]` where each clause is
   * `<name>: NULL` or `<name>: <mode> @WxH +X+Y {..., ViewPortOut=WxH+X+Y}`.
   *
   * @param response Complete query output.
   * @return The snapshot, or no value when the response is malformed or lights no output.
   */
  std::optional<physical_snapshot_t> parse_current_metamode(std::string_view response);

  /**
   * @brief Number of physical scanouts a legacy temporary layout needs.
   *
   * @param layout `single` or `dual-horizontal`.
   * @return 1 or 2, or 0 for any other layout.
   */
  std::size_t temporary_layout_outputs(std::string_view layout);

  /**
   * @brief Build the temporary MetaMode that presents a legacy layout on physical scanouts.
   *
   * Each requested output reuses one lit scanout left to right: its native
   * `ViewPortOut` is kept and the requested size becomes `ViewPortIn`.
   *
   * @param snapshot Pre-lease snapshot.
   * @param layout `single` or `dual-horizontal`.
   * @param mode_1 First qualified virtual mode.
   * @param mode_2 Second qualified virtual mode (dual only).
   * @return The MetaMode, or no value when the snapshot has too few outputs or a mode is unknown.
   */
  std::optional<std::string> temporary_metamode(
    const physical_snapshot_t &snapshot,
    std::string_view layout,
    std::string_view mode_1,
    std::string_view mode_2
  );

  /**
   * @brief Minimal recovery MetaMode: the first lit output at its native size at `+0+0`.
   *
   * @param snapshot Snapshot to recover from.
   * @return The MetaMode, or an empty string when the snapshot lights nothing.
   */
  std::string safe_physical_metamode(const physical_snapshot_t &snapshot);

  /**
   * @brief Plan a physical-display lease, keeping the original snapshot on re-acquire.
   *
   * A second acquire on the same X server would otherwise snapshot the
   * temporary MetaMode of the first lease and restore that at the end.
   *
   * @param retained Snapshot of an existing lease on the same X server, or null.
   * @param captured Snapshot captured now (ignored when `retained` is set).
   * @param layout Requested legacy layout.
   * @param mode_1 First requested mode.
   * @param mode_2 Second requested mode (dual only).
   * @return The snapshot to keep and the MetaMode to apply, or no value when infeasible.
   */
  std::optional<lease_plan_t> plan_physical_lease(
    const physical_snapshot_t *retained,
    const std::optional<physical_snapshot_t> &captured,
    std::string_view layout,
    std::string_view mode_1,
    std::string_view mode_2
  );
}  // namespace plank::display
