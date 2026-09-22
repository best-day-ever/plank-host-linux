/**
 * @file tests/unit/test_display_metamode.cpp
 * @brief Tests for NVIDIA MetaMode parsing and temporary physical-layout planning.
 */
#include "src/session/display_metamode.h"

#include "src/plank_arrangement.h"
#include "src/session/display_inventory.h"

#include <algorithm>
#include <fstream>
#include <iterator>

#include <gtest/gtest.h>

namespace display = plank::display;
namespace arrangement = plank::arrangement;

namespace {
  constexpr std::string_view single_panel =
    "id=50, switchable=no, source=RandR :: DPY-5: 1920x1080_60 @1920x1080 +0+0 "
    "{ViewPortIn=1920x1080, ViewPortOut=1920x1080+0+0}\n";

  constexpr std::string_view two_outputs_and_null =
    "id=51, switchable=yes, source=nv-control :: DPY-0: NULL, "
    "DPY-4: 3840x2160_60 @3840x2160 +1920+0 {ViewPortIn=3840x2160, ViewPortOut=3840x2160+0+0}, "
    "DPY-5: nvidia-auto-select @1920x1080 +0+270 {ViewPortIn=1920x1080, ViewPortOut=1920x1080+0+0}";
}  // namespace

TEST(DisplayMetaMode, ParsesOneLitOutputExactly) {
  const auto snapshot = display::parse_current_metamode(single_panel);
  ASSERT_TRUE(snapshot);
  EXPECT_EQ(snapshot->assignment,
            "DPY-5: 1920x1080_60 @1920x1080 +0+0 {ViewPortIn=1920x1080, ViewPortOut=1920x1080+0+0}");
  ASSERT_EQ(snapshot->outputs.size(), 1U);
  EXPECT_EQ(snapshot->outputs[0].name, "DPY-5");
  EXPECT_EQ(snapshot->outputs[0].mode, "1920x1080_60");
  EXPECT_EQ(snapshot->outputs[0].native_width, 1920);
  EXPECT_EQ(snapshot->outputs[0].native_height, 1080);
  EXPECT_EQ(snapshot->outputs[0].x, 0);
  EXPECT_EQ(snapshot->outputs[0].y, 0);
  EXPECT_TRUE(snapshot->null_outputs.empty());
}

TEST(DisplayMetaMode, ParsesYOffsetsAndNullClauses) {
  const auto snapshot = display::parse_current_metamode(two_outputs_and_null);
  ASSERT_TRUE(snapshot);
  ASSERT_EQ(snapshot->outputs.size(), 2U);
  // Left to right, regardless of clause order.
  EXPECT_EQ(snapshot->outputs[0].name, "DPY-5");
  EXPECT_EQ(snapshot->outputs[0].mode, "nvidia-auto-select");
  EXPECT_EQ(snapshot->outputs[0].x, 0);
  EXPECT_EQ(snapshot->outputs[0].y, 270);
  EXPECT_EQ(snapshot->outputs[1].name, "DPY-4");
  EXPECT_EQ(snapshot->outputs[1].x, 1920);
  EXPECT_EQ(snapshot->outputs[1].y, 0);
  EXPECT_EQ(snapshot->outputs[1].native_width, 3840);
  ASSERT_EQ(snapshot->null_outputs.size(), 1U);
  EXPECT_EQ(snapshot->null_outputs[0], "DPY-0");
  // The rollback record is the exact text after the separator.
  EXPECT_TRUE(snapshot->assignment.starts_with("DPY-0: NULL, DPY-4: 3840x2160_60"));
}

TEST(DisplayMetaMode, RejectsMalformedOrEmptyMetaModes) {
  EXPECT_FALSE(display::parse_current_metamode(""));
  EXPECT_FALSE(display::parse_current_metamode("DPY-5: 1920x1080 @1920x1080 +0+0"));
  EXPECT_FALSE(display::parse_current_metamode(":: DPY-0: NULL, DPY-2: NULL"));
  EXPECT_FALSE(display::parse_current_metamode(
    ":: DPY-5: 1920x1080 @1920x1080 +0+0 {ViewPortIn=1920x1080, ViewPortOut=1920x1080+0+0"
  ));
  EXPECT_FALSE(display::parse_current_metamode(
    ":: DPY-5: 1920x1080 @1920x1080 +0+0 {ViewPortIn=1920x1080}"
  ));
  EXPECT_FALSE(display::parse_current_metamode(
    ":: DPY 5: 1920x1080 @1920x1080 +0+0 {ViewPortOut=1920x1080+0+0}"
  ));
  EXPECT_FALSE(display::parse_current_metamode(
    ":: DPY-5: 1920x1080 @1920x1080 +0 {ViewPortOut=1920x1080+0+0}"
  ));
  EXPECT_FALSE(display::parse_current_metamode(
    ":: DPY-5: 1920x1080 @1920x1080 +0+0 {ViewPortOut=0x1080+0+0}"
  ));
  EXPECT_FALSE(display::parse_current_metamode(
    std::string {":: DPY-5: 1920x1080\t@1920x1080 +0+0 {ViewPortOut=1920x1080+0+0}\x01"}
  ));
}

TEST(DisplayMetaMode, BuildsTemporaryLayoutsOverNativeScanouts) {
  const auto snapshot = display::parse_current_metamode(two_outputs_and_null);
  ASSERT_TRUE(snapshot);
  EXPECT_EQ(display::temporary_metamode(*snapshot, "single", "3024x1890", ""),
            "DPY-5: nvidia-auto-select @3024x1890 +0+0 "
            "{ViewPortIn=3024x1890, ViewPortOut=1920x1080+0+0}");
  EXPECT_EQ(display::temporary_metamode(*snapshot, "dual-horizontal", "3840x2160", "1280x2160"),
            "DPY-5: nvidia-auto-select @3840x2160 +0+0 "
            "{ViewPortIn=3840x2160, ViewPortOut=1920x1080+0+0}, "
            "DPY-4: 3840x2160_60 @1280x2160 +3840+0 "
            "{ViewPortIn=1280x2160, ViewPortOut=3840x2160+0+0}");
  EXPECT_FALSE(display::temporary_metamode(*snapshot, "single", "1280x720", ""));
  EXPECT_FALSE(display::temporary_metamode(*snapshot, "physical", "", ""));
  EXPECT_EQ(display::temporary_layout_outputs("single"), 1U);
  EXPECT_EQ(display::temporary_layout_outputs("dual-horizontal"), 2U);
  EXPECT_EQ(display::temporary_layout_outputs("physical"), 0U);
}

TEST(DisplayMetaMode, RefusesADualLayoutOnOneScanout) {
  const auto snapshot = display::parse_current_metamode(single_panel);
  ASSERT_TRUE(snapshot);
  EXPECT_FALSE(display::temporary_metamode(*snapshot, "dual-horizontal", "1920x1080", "1920x1080"));
  EXPECT_FALSE(display::plan_physical_lease(
    nullptr, snapshot, "dual-horizontal", "1920x1080", "1920x1080"
  ));
}

TEST(DisplayMetaMode, SafeRecoveryLightsTheFirstOutputNatively) {
  const auto snapshot = display::parse_current_metamode(two_outputs_and_null);
  ASSERT_TRUE(snapshot);
  EXPECT_EQ(display::safe_physical_metamode(*snapshot),
            "DPY-5: nvidia-auto-select @1920x1080 +0+0 "
            "{ViewPortIn=1920x1080, ViewPortOut=1920x1080+0+0}");
  EXPECT_TRUE(display::safe_physical_metamode({}).empty());
}

TEST(DisplayMetaMode, ReacquireKeepsTheOriginalSnapshot) {
  const auto original = display::parse_current_metamode(single_panel);
  ASSERT_TRUE(original);
  const auto first = display::plan_physical_lease(nullptr, original, "single", "3024x1890", "");
  ASSERT_TRUE(first);
  EXPECT_EQ(first->snapshot.assignment, original->assignment);

  // The live MetaMode during the first lease is its temporary layout.
  const auto during_lease = display::parse_current_metamode(":: " + first->temporary);
  ASSERT_TRUE(during_lease);
  ASSERT_NE(during_lease->assignment, original->assignment);

  const auto second = display::plan_physical_lease(
    &first->snapshot, during_lease, "single", "2560x1600", ""
  );
  ASSERT_TRUE(second);
  EXPECT_EQ(second->snapshot.assignment, original->assignment);
  EXPECT_EQ(second->temporary,
            "DPY-5: 1920x1080_60 @2560x1600 +0+0 "
            "{ViewPortIn=2560x1600, ViewPortOut=1920x1080+0+0}");

  EXPECT_FALSE(display::plan_physical_lease(nullptr, std::nullopt, "single", "2560x1600", ""));
}

namespace {
  std::string display_fixture(std::string_view name) {
    std::ifstream input {std::string {SUNSHINE_SOURCE_DIR} + "/tests/fixtures/display/" + std::string {name},
                         std::ios::binary};
    return {std::istreambuf_iterator<char> {input}, std::istreambuf_iterator<char> {}};
  }

  /** The fleet shape: the HDMI dummy plug plus three reserved virtual heads. */
  display::inventory_t fleet_inventory() {
    auto devices = display::parse_display_devices(display_fixture("nvidia-dpys-laptop.txt"));
    std::erase_if(devices, [](const auto &device) { return device.dfp == "DFP-5"; });
    const auto screen = display::parse_randr_verbose(display_fixture("xrandr-hybrid.txt"));
    EXPECT_TRUE(screen);
    auto inventory = display::build_inventory(devices, *screen, "PCI:1:0:0", "580.159.04",
                                              "hybrid", std::nullopt);
    EXPECT_TRUE(inventory);
    inventory->virtual_heads = 3;
    return *inventory;
  }

  display::arrangement_plan_t plan_for(std::string_view request, const display::inventory_t &inventory) {
    const auto capabilities = display::capabilities_from_inventory(inventory, {}, true);
    const auto result = arrangement::evaluate(request, capabilities);
    EXPECT_TRUE(result.resolution) << request << ": " << arrangement::error_code(result.error);
    std::string reason;
    const auto plan = display::plan_arrangement(*result.resolution, inventory, reason);
    EXPECT_TRUE(plan) << request << ": " << reason;
    return plan.value_or(display::arrangement_plan_t {});
  }
}  // namespace

TEST(DisplayMetaMode, PlansOneMetaModeOverEveryConnector) {
  const auto inventory = fleet_inventory();
  const auto plan = plan_for("1:3024x1890+0+270:auto,3840x2160+3024+0:auto", inventory);
  EXPECT_EQ(plan.metamode,
            "DPY-0: 3024x1890 @3024x1890 +0+270 {ViewPortIn=3024x1890, ViewPortOut=3024x1890+0+0}, "
            "DPY-4: 3840x2160 @3840x2160 +3024+0 {ViewPortIn=3840x2160, ViewPortOut=3840x2160+0+0}, "
            "DPY-2: NULL, DPY-6: NULL");
  EXPECT_EQ(plan.primary, "DP-0");
  EXPECT_EQ(plan.width, 6864);
  EXPECT_EQ(plan.height, 2160);
  ASSERT_EQ(plan.outputs.size(), 4U);
  EXPECT_EQ(plan.outputs[0].randr, "HDMI-0");
  EXPECT_EQ(plan.outputs[0].backing, "physical");
  EXPECT_EQ(plan.outputs[0].index, 1);
  EXPECT_EQ(plan.outputs[1].randr, "DP-0");
  EXPECT_EQ(plan.outputs[1].backing, "virtual");
  EXPECT_EQ(plan.outputs[1].mode, "3024x1890");
  EXPECT_EQ(plan.outputs[3].randr, "DP-5");
  EXPECT_EQ(plan.outputs[3].backing, "off");
  // Visibility first: shown outputs are desktop outputs, the rest are hidden.
  EXPECT_EQ(display::visibility_arguments(plan, true), (std::vector<std::string> {
    "--output", "HDMI-0", "--set", "non-desktop", "0",
    "--output", "DP-0", "--set", "non-desktop", "0",
    "--output", "DP-2", "--off", "--set", "non-desktop", "1",
    "--output", "DP-5", "--off", "--set", "non-desktop", "1",
  }));
}

TEST(DisplayMetaMode, CarriersAndViewportsUseViewPortIn) {
  const auto inventory = fleet_inventory();
  const auto macbook = plan_for("1:3456x2160+0+0:auto", inventory);
  EXPECT_EQ(macbook.metamode,
            "DPY-0: 3840x2160 @3456x2160 +0+0 {ViewPortIn=3456x2160, ViewPortOut=3840x2160+0+0}, "
            "DPY-4: NULL, DPY-2: NULL, DPY-6: NULL");
  // The dongle is switched off and, when hiding is allowed, removed from the desktop.
  EXPECT_EQ(display::visibility_arguments(macbook, true), (std::vector<std::string> {
    "--output", "HDMI-0", "--off", "--set", "non-desktop", "1",
    "--output", "DP-0", "--set", "non-desktop", "0",
    "--output", "DP-2", "--off", "--set", "non-desktop", "1",
    "--output", "DP-5", "--off", "--set", "non-desktop", "1",
  }));
  EXPECT_EQ(display::visibility_arguments(macbook, false).size(), 17U);

  const auto viewport = plan_for("1:3024x1890+0+0:physical", inventory);
  EXPECT_EQ(viewport.metamode,
            "DPY-4: 3840x2160 @3024x1890 +0+0 {ViewPortIn=3024x1890, ViewPortOut=3840x2160+0+0}, "
            "DPY-0: NULL, DPY-2: NULL, DPY-6: NULL");
  const auto eight_k = plan_for("1:7680x4320+0+0:auto", inventory);
  EXPECT_EQ(eight_k.outputs[1].mode, "5120x2160");
}

TEST(DisplayMetaMode, RefusesPlansTheHardwareCannotShow) {
  const auto inventory = fleet_inventory();
  std::string reason;
  arrangement::resolution_t too_far;
  too_far.outputs.push_back({0, arrangement::backing_t::physical_viewport, 0, "x11:HDMI-0",
                             "3840x2160", "", {0, 0, 7682, 4320}});
  too_far.desktop_width = 7682;
  too_far.desktop_height = 4320;
  EXPECT_FALSE(display::plan_arrangement(too_far, inventory, reason));
  EXPECT_EQ(reason, "output_too_large");

  arrangement::resolution_t missing;
  missing.outputs.push_back({0, arrangement::backing_t::virtual_output, 4, "", "", "1920x1080",
                             {0, 0, 1920, 1080}});
  EXPECT_FALSE(display::plan_arrangement(missing, inventory, reason));
  EXPECT_EQ(reason, "no_virtual_output");

  missing.outputs[0] = {0, arrangement::backing_t::physical, 0, "x11:DP-9", "1920x1080", "",
                        {0, 0, 1920, 1080}};
  EXPECT_FALSE(display::plan_arrangement(missing, inventory, reason));
  EXPECT_EQ(reason, "no_physical_output");

  arrangement::resolution_t twice;
  twice.outputs.push_back({0, arrangement::backing_t::virtual_output, 1, "", "", "1920x1080",
                           {0, 0, 1920, 1080}});
  twice.outputs.push_back({1, arrangement::backing_t::virtual_output, 1, "", "", "1920x1080",
                           {1920, 0, 1920, 1080}});
  EXPECT_FALSE(display::plan_arrangement(twice, inventory, reason));
  EXPECT_EQ(reason, "too_many_displays");
}

TEST(DisplayMetaMode, VerifiesTheLiveDesktop) {
  const auto inventory = fleet_inventory();
  const auto plan = plan_for("1:3024x1890+0+270:auto,3840x2160+3024+0:auto", inventory);
  display::randr_screen_t screen;
  screen.width = 6864;
  screen.height = 2160;
  screen.outputs.push_back({});
  screen.outputs.back().name = "DP-0";
  screen.outputs.back().enabled = true;
  screen.outputs.back().primary = true;
  screen.outputs.back().y = 270;
  screen.outputs.back().width = 3024;
  screen.outputs.back().height = 1890;
  screen.outputs.push_back({});
  screen.outputs.back().name = "HDMI-0";
  screen.outputs.back().enabled = true;
  screen.outputs.back().x = 3024;
  screen.outputs.back().width = 3840;
  screen.outputs.back().height = 2160;
  screen.outputs.push_back({});
  screen.outputs.back().name = "DP-2";
  EXPECT_TRUE(display::arrangement_live(screen, plan));

  auto wrong = screen;
  wrong.width = 9152;
  EXPECT_FALSE(display::arrangement_live(wrong, plan));
  wrong = screen;
  wrong.outputs[0].primary = false;
  EXPECT_FALSE(display::arrangement_live(wrong, plan));
  wrong = screen;
  wrong.outputs[2].enabled = true;
  EXPECT_FALSE(display::arrangement_live(wrong, plan));
  wrong = screen;
  wrong.outputs[1].x = 3000;
  EXPECT_FALSE(display::arrangement_live(wrong, plan));
}

TEST(DisplayMetaMode, RestsOnThePhysicalOutputs) {
  const auto inventory = fleet_inventory();
  EXPECT_EQ(display::rest_metamode(inventory), "DPY-4: nvidia-auto-select +0+0");
  EXPECT_EQ(display::boot_metamode(inventory),
            "DPY-4: nvidia-auto-select +0+0, DPY-0: NULL, DPY-2: NULL, DPY-6: NULL");
  EXPECT_EQ(display::hide_virtual_head_arguments(inventory), (std::vector<std::string> {
    "--output", "DP-0", "--off", "--set", "non-desktop", "1",
    "--output", "DP-2", "--off", "--set", "non-desktop", "1",
    "--output", "DP-5", "--off", "--set", "non-desktop", "1",
  }));

  const auto rest = display::parse_current_metamode(
    ":: DPY-4: 3840x2160 @3840x2160 +0+0 {ViewPortIn=3840x2160, ViewPortOut=3840x2160+0+0}, "
    "DPY-0: NULL"
  );
  ASSERT_TRUE(rest);
  EXPECT_FALSE(display::rest_needed(*rest, inventory, true));
  // gnome-shell arranging five connected heads at greeter start (hardware probe).
  const auto scattered = display::parse_current_metamode(
    ":: DPY-4: 3840x2160 @3840x2160 +7232+3556 {ViewPortIn=3840x2160, ViewPortOut=3840x2160+0+0}"
  );
  ASSERT_TRUE(scattered);
  EXPECT_TRUE(display::rest_needed(*scattered, inventory, false));
  const auto virtual_lit = display::parse_current_metamode(
    ":: DPY-4: 3840x2160 @3840x2160 +0+0 {ViewPortIn=3840x2160, ViewPortOut=3840x2160+0+0}, "
    "DPY-2: 1920x1080 @1920x1080 +3840+0 {ViewPortIn=1920x1080, ViewPortOut=1920x1080+0+0}"
  );
  ASSERT_TRUE(virtual_lit);
  EXPECT_TRUE(display::rest_needed(*virtual_lit, inventory, false));
  const auto other = display::parse_current_metamode(
    ":: DPY-5: 1920x1080 @1920x1080 +0+0 {ViewPortIn=1920x1080, ViewPortOut=1920x1080+0+0}"
  );
  ASSERT_TRUE(other);
  EXPECT_FALSE(display::rest_needed(*other, inventory, false));
  EXPECT_TRUE(display::rest_needed(*other, inventory, true));
  EXPECT_EQ(display::physical_mode_token("3840x2160"), "3840x2160");
}
