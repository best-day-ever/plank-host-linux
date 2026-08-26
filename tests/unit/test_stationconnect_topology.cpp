/**
 * @file tests/unit/test_stationconnect_topology.cpp
 * @brief Tests for exact StationConnect host-layout binding.
 */
#include "src/stationconnect_topology.h"

#include <gtest/gtest.h>

namespace topology = stationconnect::topology;

TEST(StationConnectTopology, PublishesVersionFourFeatureContract) {
  EXPECT_EQ(topology::protocol_version, 4U);
  EXPECT_EQ(topology::feature_flags, 0x3FFU);
  EXPECT_TRUE(topology::valid_virtual_mode("1024x2160"));
  EXPECT_TRUE(topology::valid_virtual_mode("2560x2160"));
  EXPECT_TRUE(topology::valid_virtual_mode("4096x2160"));
  EXPECT_FALSE(topology::valid_virtual_mode("5120x2160"));
}

TEST(StationConnectTopology, AcceptsExactQualifiedLayouts) {
  EXPECT_EQ(topology::validate_layout_binding(
              "physical", "", "", "physical", "", "", 1),
            topology::layout_error::none);
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "4096x2160", "", "single", "4096x2160", "", 1),
            topology::layout_error::none);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "3840x2160", "1280x2160",
              "dual-horizontal", "3840x2160", "1280x2160", 2),
            topology::layout_error::none);
}

TEST(StationConnectTopology, EnforcesAdministratorDisplayPolicy) {
  EXPECT_TRUE(topology::layout_allowed_by_display_policy("physical", false));
  EXPECT_FALSE(topology::layout_allowed_by_display_policy("single", false));
  EXPECT_FALSE(topology::layout_allowed_by_display_policy("dual-horizontal", false));
  EXPECT_FALSE(topology::layout_allowed_by_display_policy("physical", true));
  EXPECT_TRUE(topology::layout_allowed_by_display_policy("single", true));
  EXPECT_TRUE(topology::layout_allowed_by_display_policy("dual-horizontal", true));
  EXPECT_FALSE(topology::layout_allowed_by_display_policy("dual-vertical", true));
}

TEST(StationConnectTopology, RejectsMismatchBeforeLaunchState) {
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "1920x1080", "",
              "dual-horizontal", "1920x1080", "1024x2160", 2),
            topology::layout_error::mismatch);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "3840x2160", "1280x2160",
              "dual-horizontal", "3840x2160", "1024x2160", 2),
            topology::layout_error::mismatch);
}

TEST(StationConnectTopology, RejectsInvalidAndUnhealthyLayouts) {
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-vertical", "1920x1080", "",
              "dual-horizontal", "1920x1080", "1280x2160", 2),
            topology::layout_error::invalid_request);
  EXPECT_EQ(topology::validate_layout_binding(
              "physical", "1920x1080", "", "physical", "", "", 1),
            topology::layout_error::invalid_request);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "1920x1080", "1280x2160",
              "dual-horizontal", "1920x1080", "1280x2160", 1),
            topology::layout_error::unhealthy);
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "1920x1080", "1280x2160",
              "single", "1920x1080", "", 1),
            topology::layout_error::invalid_request);
}
