/**
 * @file tests/unit/test_display_inventory.cpp
 * @brief Display inventory parsing, classification, cache format and capabilities.
 *
 * Fixtures: tests/fixtures/display/nvidia-dpys-laptop.txt and xrandr-laptop.txt
 * come from a laptop workstation (RTX A5000 Laptop, one panel). xrandr-hybrid.txt
 * is the same GPU with the fleet HDMI dummy plug (hdmi-dummy-uhd60.edid, whose
 * real mode list it reproduces) and three PLANK virtual heads, two of them hidden.
 */
#include "src/plank_arrangement.h"
#include "src/plank_arrangement_json.h"
#include "src/session/display_inventory.h"

#include <fstream>
#include <iterator>
#include <string>

#include <gtest/gtest.h>

namespace display = plank::display;
namespace arrangement = plank::arrangement;

namespace {
  std::string fixture(std::string_view name) {
    std::ifstream input {std::string {SUNSHINE_SOURCE_DIR} + "/tests/fixtures/" + std::string {name},
                         std::ios::binary};
    return {std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {}};
  }

  const nlohmann::json &fleet_capabilities() {
    static const auto document = nlohmann::json::parse(
      fixture("protocol/display-arrangement-v1.json")
    );
    return document.at("capabilities").at("fleet-hybrid");
  }

  std::vector<display::display_device_t> devices() {
    return display::parse_display_devices(fixture("display/nvidia-dpys-laptop.txt"));
  }

  display::randr_screen_t screen(std::string_view name) {
    const auto parsed = display::parse_randr_verbose(fixture(name));
    EXPECT_TRUE(parsed) << name;
    return parsed.value_or(display::randr_screen_t {});
  }

  display::overlay_facts_t overlay_for(const display::inventory_t &inventory, int heads) {
    display::overlay_facts_t facts {inventory.fingerprint, {}, 16384, 4608};
    for (int index = 0; index < heads; ++index) {
      facts.virtual_dfps.push_back(inventory.virtual_candidates[static_cast<std::size_t>(index)].device.dfp);
    }
    return facts;
  }

  /** The fleet shape: the dummy plug is the only physical output. */
  display::inventory_t fleet_inventory() {
    auto fleet_devices = devices();
    std::erase_if(fleet_devices, [](const auto &device) { return device.dfp == "DFP-5"; });
    const auto base = display::build_inventory(
      fleet_devices, screen("display/xrandr-hybrid.txt"), "PCI:1:0:0", "580.159.04", "hybrid",
      std::nullopt
    );
    EXPECT_TRUE(base);
    const auto inventory = display::build_inventory(
      fleet_devices, screen("display/xrandr-hybrid.txt"), "PCI:1:0:0", "580.159.04", "hybrid",
      overlay_for(*base, 3)
    );
    EXPECT_TRUE(inventory);
    return *inventory;
  }

  std::map<std::string, arrangement::encoding_limit_t> nvenc_limits() {
    return {
      {"hevc-10-444-nvenc", {8192, 8192, 7680, 4320}},
      {"h264-8-444-nvenc", {4096, 4096, 4096, 2160}},
    };
  }
}  // namespace

TEST(DisplayInventory, HashesWithSha256) {
  EXPECT_EQ(display::sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  EXPECT_EQ(display::sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  EXPECT_EQ(display::sha256_hex(std::string(1000, 'a')),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
  const auto edid = fixture("display/hdmi-dummy-uhd60.edid");
  ASSERT_EQ(edid.size(), 256U);
  EXPECT_EQ(display::sha256_hex(edid),
            fleet_capabilities().at("physical_outputs")[0].at("edid_sha256").get<std::string>());
}

TEST(DisplayInventory, MapsNvidiaNamesWithoutGuessing) {
  const auto parsed = devices();
  ASSERT_EQ(parsed.size(), 8U);
  EXPECT_EQ(parsed[4].dfp, "DFP-4");
  EXPECT_EQ(parsed[4].dpy, "DPY-4");
  EXPECT_EQ(parsed[4].randr, "HDMI-0");
  EXPECT_EQ(parsed[4].connector, "Connector-3");
  EXPECT_EQ(parsed[5].dfp, "DFP-5");
  EXPECT_EQ(parsed[5].randr, "DP-4");
  EXPECT_EQ(parsed[5].connector, "Connector-0");
  EXPECT_EQ(parsed[6].randr, "DP-5");
  EXPECT_EQ(parsed[7].connector, "Connector-4");
  EXPECT_TRUE(display::parse_display_devices("no devices").empty());
}

TEST(DisplayInventory, ParsesRandrOutputsModesAndEdid) {
  const auto laptop = screen("display/xrandr-laptop.txt");
  EXPECT_EQ(laptop.width, 1920);
  EXPECT_EQ(laptop.height, 1080);
  ASSERT_EQ(laptop.outputs.size(), 8U);
  const auto &panel = laptop.outputs[5];
  EXPECT_EQ(panel.name, "DP-4");
  EXPECT_TRUE(panel.connected);
  EXPECT_TRUE(panel.primary);
  EXPECT_TRUE(panel.enabled);
  EXPECT_EQ(panel.width, 1920);
  EXPECT_EQ(panel.height, 1080);
  EXPECT_EQ(panel.edid.size(), 128U);
  EXPECT_EQ(display::edid_manufacturer(panel.edid), "CMN");
  EXPECT_EQ(panel.signal_format, "DisplayPort");
  EXPECT_EQ(panel.connector_type, "Panel");
  EXPECT_EQ(panel.non_desktop, false);
  ASSERT_EQ(panel.modes.size(), 2U);
  EXPECT_EQ(panel.modes[0].refresh_millihz, 60008);
  EXPECT_TRUE(panel.modes[0].preferred);
  EXPECT_TRUE(panel.modes[0].current);
  EXPECT_EQ(panel.modes[1].refresh_millihz, 40004);
  EXPECT_EQ(laptop.outputs[1].signal_format, "TMDS");
  EXPECT_FALSE(laptop.outputs[0].connected);
  EXPECT_FALSE(display::parse_randr_verbose("Screen 0: minimum 8 x 8, current 1 x 1\n"));
}

TEST(DisplayInventory, KeepsOnlySixtyHertzProgressiveDongleModes) {
  const auto hybrid = screen("display/xrandr-hybrid.txt");
  const auto dongle = std::find_if(hybrid.outputs.begin(), hybrid.outputs.end(),
                                   [](const auto &output) { return output.name == "HDMI-0"; });
  ASSERT_NE(dongle, hybrid.outputs.end());
  EXPECT_EQ(display::edid_monitor_name(dongle->edid), "MEC-O-3-H");
  // 1440x900 is 59.89 Hz and 800x600 is 60.32 Hz on this plug.
  EXPECT_EQ(display::sixty_hertz_modes(*dongle, 640, 480),
            fleet_capabilities().at("physical_outputs")[0].at("modes").get<std::vector<std::string>>());

  display::randr_output_t interlaced;
  interlaced.modes.push_back({"1920x1080i", 1920, 1080, 60000, true, false, false, false});
  interlaced.modes.push_back({"320x240", 320, 240, 60000, false, true, false, false});
  interlaced.modes.push_back({"320x240", 320, 240, 60000, false, false, false, false});
  EXPECT_TRUE(display::sixty_hertz_modes(interlaced, 640, 480).empty());
  EXPECT_EQ(display::sixty_hertz_modes(interlaced, 320, 240), std::vector<std::string> {"320x240"});
  EXPECT_TRUE(display::sixty_hertz(59900));
  EXPECT_TRUE(display::sixty_hertz(60100));
  EXPECT_FALSE(display::sixty_hertz(59887));
  EXPECT_FALSE(display::sixty_hertz(60317));
}

TEST(DisplayInventory, ClassifiesThePanelAndPicksFreeDisplayPortHeads) {
  const auto inventory = display::build_inventory(
    devices(), screen("display/xrandr-laptop.txt"), "PCI:1:0:0", "580.159.04", "physical",
    std::nullopt
  );
  ASSERT_TRUE(inventory);
  ASSERT_EQ(inventory->physical.size(), 1U);
  const auto &panel = inventory->physical[0];
  EXPECT_EQ(panel.device.dfp, "DFP-5");
  EXPECT_EQ(panel.device.dpy, "DPY-5");
  EXPECT_EQ(panel.device.randr, "DP-4");
  EXPECT_EQ(panel.display_name, "Built-in display");
  EXPECT_EQ(panel.preferred, "1920x1080");
  EXPECT_EQ(panel.modes, std::vector<std::string> {"1920x1080"});
  EXPECT_EQ(panel.edid_sha256.size(), 64U);
  // DisplayPort DFPs on connectors the panel does not use, one per connector.
  ASSERT_EQ(inventory->virtual_candidates.size(), 3U);
  EXPECT_EQ(inventory->virtual_candidates[0].device.dfp, "DFP-0");
  EXPECT_EQ(inventory->virtual_candidates[0].device.randr, "DP-0");
  EXPECT_EQ(inventory->virtual_candidates[1].device.dfp, "DFP-2");
  EXPECT_EQ(inventory->virtual_candidates[2].device.dfp, "DFP-6");
  EXPECT_EQ(inventory->virtual_candidates[2].device.randr, "DP-5");
  EXPECT_EQ(inventory->virtual_heads, 0);
  EXPECT_EQ(inventory->fingerprint.size(), 64U);

  EXPECT_FALSE(display::build_inventory(devices(), screen("display/xrandr-laptop.txt"),
                                        "1:0:0", "580.159.04", "physical", std::nullopt));
  EXPECT_FALSE(display::build_inventory(devices(), screen("display/xrandr-laptop.txt"),
                                        "PCI:1:0:0", "580.159.04", "headless", std::nullopt));
}

TEST(DisplayInventory, PlankEdidsAreNeverPhysical) {
  const auto hybrid = screen("display/xrandr-hybrid.txt");
  const auto base = display::build_inventory(devices(), hybrid, "PCI:1:0:0", "580.159.04",
                                             "hybrid", std::nullopt);
  ASSERT_TRUE(base);
  ASSERT_EQ(base->physical.size(), 2U);
  EXPECT_EQ(base->physical[0].device.randr, "HDMI-0");
  EXPECT_EQ(base->physical[0].display_name, "MEC-O-3-H");
  EXPECT_EQ(base->physical[0].preferred, "3840x2160");
  EXPECT_EQ(base->physical[1].device.randr, "DP-4");
  ASSERT_EQ(base->virtual_candidates.size(), 3U);
  EXPECT_EQ(base->virtual_heads, 0);

  const auto reserved = display::build_inventory(devices(), hybrid, "PCI:1:0:0", "580.159.04",
                                                 "hybrid", overlay_for(*base, 3));
  ASSERT_TRUE(reserved);
  EXPECT_EQ(reserved->fingerprint, base->fingerprint);
  EXPECT_EQ(reserved->virtual_heads, 3);
  EXPECT_EQ(reserved->screen_virtual_width, 16384);
  EXPECT_EQ(reserved->screen_virtual_height, 4608);
  EXPECT_EQ(display::build_inventory(devices(), hybrid, "PCI:1:0:0", "580.159.04", "hybrid",
                                     overlay_for(*base, 2))->virtual_heads, 2);
  auto stale = overlay_for(*base, 3);
  stale.fingerprint = std::string(64, '0');
  EXPECT_EQ(display::build_inventory(devices(), hybrid, "PCI:1:0:0", "580.159.04", "hybrid",
                                     stale)->virtual_heads, 0);
  EXPECT_EQ(display::build_inventory(devices(), hybrid, "PCI:1:0:0", "580.159.04", "physical",
                                     overlay_for(*base, 3))->virtual_heads, 0);

  // A physical output hidden during a lease reports "disconnected" but keeps its EDID.
  auto hidden = hybrid;
  for (auto &output : hidden.outputs) {
    if (output.name == "HDMI-0") {
      output.connected = false;
      output.non_desktop = true;
    }
  }
  const auto during_lease = display::build_inventory(devices(), hidden, "PCI:1:0:0", "580.159.04",
                                                     "hybrid", std::nullopt);
  ASSERT_TRUE(during_lease);
  EXPECT_EQ(during_lease->fingerprint, base->fingerprint);

  // A different driver or GPU changes the fingerprint.
  EXPECT_NE(display::build_inventory(devices(), hybrid, "PCI:2:0:0", "580.159.04", "hybrid",
                                     std::nullopt)->fingerprint, base->fingerprint);
  EXPECT_NE(display::build_inventory(devices(), hybrid, "PCI:1:0:0", "580.126.09", "hybrid",
                                     std::nullopt)->fingerprint, base->fingerprint);
}

TEST(DisplayInventory, CacheRoundTripsAndFailsClosed) {
  const auto inventory = fleet_inventory();
  const auto message = display::inventory_message(inventory);
  EXPECT_TRUE(message.starts_with("# Generated by PLANK; do not edit.\nversion=1\n"));
  EXPECT_NE(message.find("\nphysical_1_dfp=DFP-4\n"), std::string::npos);
  EXPECT_NE(message.find("\nphysical_1_display_name=MEC-O-3-H\n"), std::string::npos);
  EXPECT_NE(message.find("\nvirtual_candidate_3_dfp=DFP-6\n"), std::string::npos);
  EXPECT_NE(message.find("\nscreen_virtual=16384x4608\n"), std::string::npos);
  EXPECT_NE(message.find("\nvirtual_heads=3\n"), std::string::npos);
  const auto parsed = display::parse_inventory(message);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(display::inventory_message(*parsed), message);

  const auto replace = [&](std::string_view from, std::string_view to) {
    auto changed = message;
    const auto offset = changed.find(from);
    EXPECT_NE(offset, std::string::npos) << from;
    changed.replace(offset, from.size(), to);
    return changed;
  };
  EXPECT_FALSE(display::parse_inventory(replace("physical_1_dfp=DFP-4", "physical_1_dfp=DFP-9")));
  EXPECT_FALSE(display::parse_inventory(replace("gpu_bus_id=PCI:1:0:0", "gpu_bus_id=PCI:1:0")));
  EXPECT_FALSE(display::parse_inventory(replace("virtual_heads=3", "virtual_heads=4")));
  EXPECT_FALSE(display::parse_inventory(replace("version=1\n", "version=1\nextra=1\n")));
  EXPECT_FALSE(display::parse_inventory(replace("version=1\n", "")));
  EXPECT_FALSE(display::parse_inventory(replace("# Generated", "# Written")));
  EXPECT_FALSE(display::parse_inventory(replace("physical_1_display_name=MEC-O-3-H",
                                                "physical_1_display_name=$(reboot)")));
  EXPECT_FALSE(display::read_inventory("/nonexistent/display-inventory"));
}

TEST(DisplayInventory, ReadsWhatTheHybridOverlayReserved) {
  const auto overlay =
    "# Generated by PLANK; do not edit.\n"
    "# Inventory fingerprint: " + std::string(64, 'a') + "\n"
    "Section \"Device\"\n"
    "    Option \"CustomEDID\" \"DFP-0:/usr/share/plank/display/virtual-1.edid; "
    "DFP-2:/usr/share/plank/display/virtual-2.edid; DFP-6:/usr/share/plank/display/virtual-3.edid\"\n"
    "EndSection\n"
    "Section \"Screen\"\n"
    "    SubSection \"Display\"\n"
    "        Virtual 16384 4608\n"
    "    EndSubSection\n"
    "EndSection\n";
  const auto facts = display::parse_overlay_facts(overlay);
  ASSERT_TRUE(facts);
  EXPECT_EQ(facts->fingerprint, std::string(64, 'a'));
  EXPECT_EQ(facts->virtual_dfps, (std::vector<std::string> {"DFP-0", "DFP-2", "DFP-6"}));
  EXPECT_EQ(facts->virtual_width, 16384);
  EXPECT_EQ(facts->virtual_height, 4608);
  // The virtual policy's overlay carries no inventory fingerprint.
  EXPECT_FALSE(display::parse_overlay_facts(
    "# Generated by PLANK; do not edit.\nOption \"CustomEDID\" \"DFP-0:/x.edid\"\n"));
  EXPECT_FALSE(display::parse_overlay_facts("# foreign\n# Inventory fingerprint: " +
                                            std::string(64, 'a') + "\n"));
}

TEST(DisplayInventory, ConvertsSysfsAddressesToXorgBusIds) {
  EXPECT_EQ(display::xorg_bus_id("0000:01:00.0"), "PCI:1:0:0");
  EXPECT_EQ(display::xorg_bus_id("0001:0a:1f.3"), "PCI:10@1:31:3");
  EXPECT_FALSE(display::xorg_bus_id("0000:01:00"));
  EXPECT_FALSE(display::xorg_bus_id("0000:0g:00.0"));
}

TEST(DisplayInventory, FleetCapabilitiesReproduceTheSharedVectors) {
  const auto capabilities = display::capabilities_from_inventory(fleet_inventory(), nvenc_limits());
  const auto published = arrangement::capabilities_json(capabilities);
  const auto &fixture_value = fleet_capabilities();
  EXPECT_EQ(published.at("physical_outputs"), fixture_value.at("physical_outputs"));
  EXPECT_EQ(published.at("encoding_limits"), fixture_value.at("encoding_limits"));
  EXPECT_EQ(capabilities.max_outputs, 4);
  EXPECT_EQ(capabilities.virtual_heads, 3);
  EXPECT_FALSE(capabilities.packed_capture);
  // Boot-time Virtual 16384x4608, encoder 8192x8192.
  EXPECT_EQ(capabilities.max_canvas_width, 8192);
  EXPECT_EQ(capabilities.max_canvas_height, 4608);
  // 2:1 over the largest carrier (5120x2160), capped at 8192 and 7680x4320 pixels.
  EXPECT_EQ(capabilities.output_limits.max_width, 8192);
  EXPECT_EQ(capabilities.output_limits.max_height, 4320);
  EXPECT_EQ(capabilities.output_limits.max_pixels, 33177600);
  EXPECT_EQ(capabilities.fingerprint.size(), 32U);

  // Every fleet vector resolves identically against the derived capabilities.
  const auto document = nlohmann::json::parse(fixture("protocol/display-arrangement-v1.json"));
  for (const auto &item : document.at("resolve")) {
    if (item.at("capabilities") != "fleet-hybrid") continue;
    const auto result = arrangement::evaluate(item.at("request").get<std::string>(), capabilities);
    const auto name = item.at("name").get<std::string>();
    if (item.contains("error")) {
      EXPECT_EQ(arrangement::error_code(result.error), item.at("error").get<std::string>()) << name;
    } else {
      ASSERT_TRUE(result.resolution) << name << ": " << arrangement::error_code(result.error);
      EXPECT_EQ(arrangement::resolution_json(*result.resolution), item.at("result")) << name;
    }
  }

  // The fingerprint follows every published field.
  auto fewer = nvenc_limits();
  fewer.erase("h264-8-444-nvenc");
  EXPECT_NE(display::capabilities_from_inventory(fleet_inventory(), fewer).fingerprint,
            capabilities.fingerprint);
}

TEST(DisplayInventory, PhysicalPolicyPublishesNoVirtualHeads) {
  const auto inventory = display::build_inventory(
    devices(), screen("display/xrandr-laptop.txt"), "PCI:1:0:0", "580.159.04", "physical",
    std::nullopt
  );
  ASSERT_TRUE(inventory);
  const auto capabilities = display::capabilities_from_inventory(*inventory, {});
  EXPECT_EQ(capabilities.virtual_heads, 0);
  EXPECT_EQ(capabilities.max_outputs, 1);
  EXPECT_EQ(capabilities.max_canvas_width, 8192);
  EXPECT_EQ(capabilities.max_canvas_height, 8192);
  EXPECT_EQ(capabilities.output_limits.max_width, 3840);
  EXPECT_EQ(capabilities.output_limits.max_height, 2160);
  ASSERT_EQ(capabilities.physical_outputs.size(), 1U);
  EXPECT_EQ(capabilities.physical_outputs[0].id, "x11:DP-4");
  EXPECT_EQ(arrangement::evaluate("1:3024x1890+0+0:auto", capabilities).error,
            arrangement::error_t::none);
  EXPECT_EQ(arrangement::evaluate("1:1920x1080+0+0:virtual", capabilities).error,
            arrangement::error_t::no_virtual_output);
  EXPECT_EQ(arrangement::evaluate("1:5120x2880+0+0:auto", capabilities).error,
            arrangement::error_t::output_too_large);
  EXPECT_EQ(display::randr_name_from_id("x11:DP-4"), "DP-4");
}
