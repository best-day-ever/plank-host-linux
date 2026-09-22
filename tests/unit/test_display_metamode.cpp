/**
 * @file tests/unit/test_display_metamode.cpp
 * @brief Tests for NVIDIA MetaMode parsing and temporary physical-layout planning.
 */
#include "src/session/display_metamode.h"

#include <gtest/gtest.h>

namespace display = plank::display;

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
