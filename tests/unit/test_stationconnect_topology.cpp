/**
 * @file tests/unit/test_stationconnect_topology.cpp
 * @brief Tests for exact StationConnect host-layout binding.
 */
#include "src/stationconnect_topology.h"

#include <gtest/gtest.h>

namespace topology = stationconnect::topology;

TEST(StationConnectTopology, PublishesVersionTwoFeatureContract) {
  EXPECT_EQ(topology::protocol_version, 2U);
  EXPECT_EQ(topology::feature_flags, 0xFFU);
}

TEST(StationConnectTopology, AcceptsExactQualifiedLayouts) {
  EXPECT_EQ(topology::validate_layout_binding(
              "physical", "", "physical", "", 1),
            topology::layout_error::none);
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "3840x2160", "single", "3840x2160", 1),
            topology::layout_error::none);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "1920x1080",
              "dual-horizontal", "1920x1080", 2),
            topology::layout_error::none);
}

TEST(StationConnectTopology, RejectsMismatchBeforeLaunchState) {
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "1920x1080",
              "dual-horizontal", "1920x1080", 2),
            topology::layout_error::mismatch);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "3840x2160",
              "dual-horizontal", "1920x1080", 2),
            topology::layout_error::mismatch);
}

TEST(StationConnectTopology, RejectsInvalidAndUnhealthyLayouts) {
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-vertical", "1920x1080",
              "dual-horizontal", "1920x1080", 2),
            topology::layout_error::invalid_request);
  EXPECT_EQ(topology::validate_layout_binding(
              "physical", "1920x1080", "physical", "", 1),
            topology::layout_error::invalid_request);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "1920x1080",
              "dual-horizontal", "1920x1080", 1),
            topology::layout_error::unhealthy);
}
