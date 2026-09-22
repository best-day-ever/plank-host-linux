/**
 * @file src/session/display_inventory.h
 * @brief Display inventory: physical outputs, virtual-head candidates and capabilities.
 *
 * After each X server start the root supervisor reads
 * `nvidia-settings -q dpys --verbose` (DFP, DPY, RandR and connector names) and
 * `xrandr --verbose --prop` (connection, EDID, signal format, modes), adds the
 * GPU PCI bus ID and the driver version, and writes the result to
 * /var/lib/plank/display-inventory as `key=value` lines. The boot-time display
 * preparation reads that cache for the `hybrid` policy and the media worker
 * builds `display_capabilities` from it. Everything here is pure.
 */
#pragma once

#include "../plank_arrangement.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace plank::display {
  inline constexpr std::string_view inventory_path = "/var/lib/plank/display-inventory";  ///< Root-owned cache.
  inline constexpr int inventory_version = 1;  ///< Cache format version.
  inline constexpr std::size_t maximum_virtual_heads = 3;  ///< Virtual heads beside one physical output.
  inline constexpr int maximum_downscale = 2;  ///< Largest ViewPortIn downscale per axis (hardware probe P4).

  /**
   * @brief One NVIDIA display device and its names.
   */
  struct display_device_t {
    std::string dfp;  ///< `DFP-N`, the Xorg configuration name.
    std::string dpy;  ///< `DPY-N`, the name used in MetaModes.
    std::string randr;  ///< RandR output name, for example `HDMI-0`. Never derived from `N`.
    std::string connector;  ///< `Connector-N`: DFPs sharing a connector are one physical port.
  };

  /**
   * @brief One RandR mode of an output.
   */
  struct randr_mode_t {
    std::string name;  ///< Mode name, for example `3840x2160`.
    int width {};  ///< Active width.
    int height {};  ///< Active height.
    int refresh_millihz {};  ///< Refresh computed from the pixel clock and totals.
    bool interlaced {};  ///< `Interlace` flag.
    bool doublescan {};  ///< `DoubleScan` flag.
    bool preferred {};  ///< `+preferred`.
    bool current {};  ///< `*current`.
  };

  /**
   * @brief One RandR output from `xrandr --verbose --prop`.
   */
  struct randr_output_t {
    std::string name;  ///< Output name.
    bool connected {};  ///< Reported `connected`.
    bool enabled {};  ///< Has a CRTC geometry.
    bool primary {};  ///< Reported `primary`.
    int x {};  ///< Desktop X when enabled.
    int y {};  ///< Desktop Y when enabled.
    int width {};  ///< Active width when enabled.
    int height {};  ///< Active height when enabled.
    std::string edid;  ///< Raw EDID bytes, empty when absent.
    std::string signal_format;  ///< `SignalFormat`, for example `DisplayPort` or `TMDS`.
    std::string connector_type;  ///< `ConnectorType`, for example `Panel` or `HDMI`.
    std::optional<bool> non_desktop;  ///< `non-desktop` property when present.
    std::vector<randr_mode_t> modes;  ///< Listed modes.
  };

  /**
   * @brief `xrandr --verbose` screen and outputs.
   */
  struct randr_screen_t {
    int width {};  ///< Current screen width.
    int height {};  ///< Current screen height.
    std::vector<randr_output_t> outputs;  ///< Outputs in listed order.
  };

  /**
   * @brief One output recorded in the inventory.
   */
  struct inventory_output_t {
    display_device_t device;  ///< NVIDIA names.
    std::string display_name;  ///< Monitor name (physical outputs).
    std::string edid_sha256;  ///< EDID hash (physical outputs), or empty.
    std::string preferred;  ///< Preferred 60 Hz mode (physical outputs).
    std::vector<std::string> modes;  ///< 60 Hz progressive modes, area then width descending.
  };

  /**
   * @brief The cached display inventory.
   */
  struct inventory_t {
    int version {inventory_version};  ///< Format version.
    std::string fingerprint;  ///< SHA-256 over the hardware facts (GPU, driver, outputs, candidates).
    std::string gpu_bus_id;  ///< `PCI:bus:device:function`, decimal, as Xorg's BusID.
    std::string driver_version;  ///< NVIDIA kernel module version.
    std::string startup_policy;  ///< `physical`, `virtual` or `hybrid` when the inventory was taken.
    int screen_virtual_width {};  ///< Boot-time X screen `Virtual` width, 0 when unknown.
    int screen_virtual_height {};  ///< Boot-time X screen `Virtual` height, 0 when unknown.
    std::vector<inventory_output_t> physical;  ///< Connected non-PLANK outputs, DFP order.
    std::vector<inventory_output_t> virtual_candidates;  ///< Free DisplayPort DFPs, one per connector.
    int virtual_heads {};  ///< Candidates the running X screen reserved as virtual heads.
  };

  /**
   * @brief What the PLANK hybrid Xorg overlay reserved at boot.
   */
  struct overlay_facts_t {
    std::string fingerprint;  ///< Inventory fingerprint the overlay was generated from.
    std::vector<std::string> virtual_dfps;  ///< DFPs carrying a PLANK virtual EDID, in head order.
    int virtual_width {};  ///< `Virtual` width.
    int virtual_height {};  ///< `Virtual` height.
  };

  /** @brief Lower-case hex SHA-256 of `bytes`. */
  std::string sha256_hex(std::string_view bytes);

  /** @brief Parse `nvidia-settings -q dpys --verbose`; devices without DFP/DPY/RandR names are skipped. */
  std::vector<display_device_t> parse_display_devices(std::string_view text);

  /** @brief Parse `xrandr --verbose --prop`; no value when no output is listed. */
  std::optional<randr_screen_t> parse_randr_verbose(std::string_view text);

  /** @brief Three-letter EDID manufacturer ID (`PLK` for PLANK virtual displays), or empty. */
  std::string edid_manufacturer(std::string_view edid);

  /** @brief Monitor name from the EDID's 0xFC descriptor, or empty. */
  std::string edid_monitor_name(std::string_view edid);

  /** @brief Whether a refresh rate is inside the 59.9-60.1 Hz window. */
  bool sixty_hertz(int refresh_millihz);

  /**
   * @brief Distinct 60 Hz progressive mode names that meet the minimum size.
   *
   * Sorted by area, then width, both descending.
   */
  std::vector<std::string> sixty_hertz_modes(
    const randr_output_t &output, int minimum_width, int minimum_height
  );

  /**
   * @brief Classify outputs and pick virtual-head candidates.
   *
   * A connected output whose EDID manufacturer is `PLK` is virtual; every
   * other connected output is physical. Candidates are DisplayPort DFPs on
   * connectors no physical output uses, one per connector, at most three.
   *
   * @return The inventory with its fingerprint, or no value when the inputs do not match.
   */
  std::optional<inventory_t> build_inventory(
    const std::vector<display_device_t> &devices,
    const randr_screen_t &screen,
    std::string_view gpu_bus_id,
    std::string_view driver_version,
    std::string_view startup_policy,
    const std::optional<overlay_facts_t> &overlay
  );

  /** @brief Serialise the inventory as the cache's `key=value` lines. */
  std::string inventory_message(const inventory_t &inventory);

  /** @brief Parse the cache strictly, including its fingerprint. */
  std::optional<inventory_t> parse_inventory(std::string_view text);

  /** @brief Read the root-owned 0600 cache. */
  std::optional<inventory_t> read_inventory(std::string_view path = inventory_path);

  /** @brief Read what a PLANK hybrid overlay reserved; no value for other overlays. */
  std::optional<overlay_facts_t> parse_overlay_facts(std::string_view overlay);

  /** @brief `PCI:bus:device:function` (decimal) from a sysfs PCI address `0000:01:00.0`. */
  std::optional<std::string> xorg_bus_id(std::string_view pci_address);

  /**
   * @brief Build `display_capabilities`.
   *
   * @param inventory A valid inventory.
   * @param encoding_limits Probed per-mode encoder limits (may be empty).
   * @return Capabilities with a fingerprint over every published field.
   */
  plank::arrangement::capabilities_t capabilities_from_inventory(
    const inventory_t &inventory,
    const std::map<std::string, plank::arrangement::encoding_limit_t> &encoding_limits
  );

  /** @brief RandR output name for a capabilities output ID `x11:<name>`. */
  std::string randr_name_from_id(std::string_view id);
}  // namespace plank::display
