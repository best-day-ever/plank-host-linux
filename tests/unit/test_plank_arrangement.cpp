/**
 * @file tests/unit/test_plank_arrangement.cpp
 * @brief Display-arrangement grammar, check order, error codes and backing rule.
 *
 * Driven by tests/fixtures/protocol/display-arrangement-v1.json, a byte-identical
 * copy of the superproject's shared vectors (checked by its tests/ci).
 */
#include "src/plank_arrangement.h"
#include "src/plank_arrangement_json.h"
#include "src/plank_topology.h"

#include <fstream>
#include <map>
#include <string>

#include <gtest/gtest.h>

namespace arrangement = plank::arrangement;

namespace {
  const nlohmann::json &vectors() {
    static const nlohmann::json document = [] {
      std::ifstream input {
        std::string {SUNSHINE_SOURCE_DIR} + "/tests/fixtures/protocol/display-arrangement-v1.json"
      };
      return nlohmann::json::parse(input);
    }();
    return document;
  }

  std::map<std::string, arrangement::capabilities_t> fixture_capabilities() {
    std::map<std::string, arrangement::capabilities_t> result;
    for (const auto &[name, value] : vectors().at("capabilities").items()) {
      const auto capabilities = arrangement::capabilities_from_json(value);
      EXPECT_TRUE(capabilities) << name;
      if (capabilities) result.emplace(name, *capabilities);
    }
    return result;
  }
}  // namespace

TEST(PlankArrangement, VectorsMatchTheFeatureAndThePool) {
  const auto &document = vectors();
  EXPECT_EQ(document.at("schema_version").get<std::uint32_t>(), plank::topology::protocol_version);
  EXPECT_EQ(document.at("feature").get<std::uint32_t>(),
            plank::topology::feature_display_arrangement);
  EXPECT_EQ(plank::topology::feature_display_arrangement, 0x8000000U);
  EXPECT_EQ(plank::topology::feature_flags & plank::topology::feature_display_arrangement, 0U);
  const auto pool = document.at("virtual_pool").get<std::vector<std::string>>();
  ASSERT_EQ(pool.size(), plank::topology::virtual_mode_pool.size());
  for (std::size_t index = 0; index < pool.size(); ++index) {
    EXPECT_EQ(pool[index], plank::topology::virtual_mode_pool[index]);
    EXPECT_TRUE(plank::topology::valid_virtual_mode(pool[index]));
  }
}

TEST(PlankArrangement, CapabilitiesRoundTripTheirExactShape) {
  for (const auto &[name, value] : vectors().at("capabilities").items()) {
    const auto capabilities = arrangement::capabilities_from_json(value);
    ASSERT_TRUE(capabilities) << name;
    EXPECT_EQ(arrangement::capabilities_json(*capabilities), value) << name;
  }
  auto broken = vectors().at("capabilities").at("fleet-hybrid");
  broken.erase("max_canvas");
  EXPECT_FALSE(arrangement::capabilities_from_json(broken));
}

TEST(PlankArrangement, GrammarVectorsUseTheContractCheckOrder) {
  const auto capabilities = fixture_capabilities();
  const auto &fleet = capabilities.at("fleet-hybrid");
  for (const auto &item : vectors().at("grammar")) {
    const auto request = item.at("request").get<std::string>();
    const auto result = arrangement::evaluate(request, fleet);
    if (item.value("valid", false)) {
      EXPECT_EQ(result.error, arrangement::error_t::none) << request;
      EXPECT_TRUE(result.resolution) << request;
      const auto parsed = arrangement::parse(request);
      ASSERT_TRUE(parsed.request) << request;
      EXPECT_EQ(arrangement::serialize(*parsed.request), request);
    } else {
      EXPECT_EQ(arrangement::error_code(result.error), item.at("error").get<std::string>())
        << request;
      EXPECT_FALSE(result.resolution) << request;
    }
  }
}

TEST(PlankArrangement, ResolveVectorsPinTheBackingRule) {
  const auto capabilities = fixture_capabilities();
  for (const auto &item : vectors().at("resolve")) {
    const auto name = item.at("name").get<std::string>();
    const auto &host = capabilities.at(item.at("capabilities").get<std::string>());
    const auto result = arrangement::evaluate(item.at("request").get<std::string>(), host);
    if (item.contains("error")) {
      EXPECT_EQ(arrangement::error_code(result.error), item.at("error").get<std::string>()) << name;
      EXPECT_FALSE(result.resolution) << name;
      continue;
    }
    ASSERT_TRUE(result.resolution) << name << ": " << arrangement::error_code(result.error);
    EXPECT_EQ(arrangement::resolution_json(*result.resolution), item.at("result")) << name;
  }
}

TEST(PlankArrangement, ChecksRunInContractOrder) {
  const auto capabilities = fixture_capabilities();
  const auto &fleet = capabilities.at("fleet-hybrid");
  // Five entries fail on count (3) before an odd value (5) is looked at.
  EXPECT_EQ(arrangement::evaluate(
              "1:641x480+0+0:auto,640x480+642+0:auto,640x480+1282+0:auto,"
              "640x480+1922+0:auto,640x480+2562+0:auto",
              fleet).error,
            arrangement::error_t::too_many_displays);
  // Not canonical (4) before odd (5).
  EXPECT_EQ(arrangement::evaluate("1:03841x2160+0+0:auto", fleet).error,
            arrangement::error_t::not_canonical);
  // Odd (5) before origin (6).
  EXPECT_EQ(arrangement::evaluate("1:3841x2160+2+0:auto", fleet).error,
            arrangement::error_t::odd_value);
  // Per-entry limits run in entry order: the too-large first entry wins.
  EXPECT_EQ(arrangement::evaluate("1:8194x2160+0+0:auto,600x480+8194+0:auto", fleet).error,
            arrangement::error_t::output_too_large);
  // Limits (7) before overlap (8), overlap before canvas (9).
  EXPECT_EQ(arrangement::evaluate("1:600x480+0+0:auto,640x480+0+0:auto", fleet).error,
            arrangement::error_t::output_too_small);
  EXPECT_EQ(arrangement::evaluate("1:7680x4320+0+0:auto,7680x4320+7000+0:auto", fleet).error,
            arrangement::error_t::overlap);
  // Canvas (9) before the head budget (10).
  const auto &laptop = capabilities.at("physical-laptop");
  EXPECT_EQ(arrangement::evaluate("1:4096x2160+0+0:auto,4096x2160+4098+0:auto", laptop).error,
            arrangement::error_t::canvas_too_large);
  EXPECT_EQ(arrangement::evaluate("1:1920x1080+0+0:auto,1920x1080+1920+0:auto", laptop).error,
            arrangement::error_t::too_many_displays);
  EXPECT_EQ(arrangement::evaluate("1:1920x1080+0+0:auto", laptop).error,
            arrangement::error_t::none);
  // An overflowing number can never be canonical.
  EXPECT_EQ(arrangement::evaluate("1:99999999999x2160+0+0:auto", fleet).error,
            arrangement::error_t::not_canonical);
  EXPECT_EQ(arrangement::evaluate("1:", fleet).error, arrangement::error_t::malformed);
  EXPECT_EQ(arrangement::evaluate("1:3840x2160+0+0:auto,,", fleet).error,
            arrangement::error_t::malformed);
  EXPECT_EQ(arrangement::evaluate(std::string(161, '1'), fleet).error,
            arrangement::error_t::malformed);
}

TEST(PlankArrangement, CarriersComeFromTheVirtualPool) {
  EXPECT_EQ(arrangement::carrier_for(3024, 1890), "3024x1890");
  EXPECT_EQ(arrangement::carrier_for(3456, 2160), "3840x2160");
  EXPECT_EQ(arrangement::carrier_for(5120, 1440), "5120x2160");
  EXPECT_EQ(arrangement::carrier_for(1280, 1024), "1920x1080");
  EXPECT_EQ(arrangement::carrier_for(1920, 1200), "1920x1200");
  EXPECT_EQ(arrangement::carrier_for(640, 480), "1920x1080");
  EXPECT_EQ(arrangement::carrier_for(5120, 2880), "5120x2160");
  EXPECT_EQ(arrangement::carrier_for(7680, 4320), "5120x2160");
  EXPECT_EQ(arrangement::carrier_for(2160, 3840), "5120x2160");
  EXPECT_DOUBLE_EQ(arrangement::downscale_factor(7680, 4320, "3840x2160"), 2.0);
  EXPECT_DOUBLE_EQ(arrangement::downscale_factor(3024, 1890, "1920x1080"), 1.75);
  EXPECT_DOUBLE_EQ(arrangement::downscale_factor(1920, 1080, "3840x2160"), 0.5);
  EXPECT_DOUBLE_EQ(arrangement::downscale_factor(1920, 1080, "junk"), 0.0);
}

TEST(PlankArrangement, LegacyLayoutsBecomeAutoArrangements) {
  const auto single = arrangement::from_legacy("single", "3840x2160", "");
  ASSERT_TRUE(single);
  EXPECT_EQ(arrangement::serialize(*single), "1:3840x2160+0+0:auto");
  const auto dual = arrangement::from_legacy("dual-horizontal", "3024x1890", "5120x2160");
  ASSERT_TRUE(dual);
  EXPECT_EQ(arrangement::serialize(*dual), "1:3024x1890+0+0:auto,5120x2160+3024+0:auto");
  EXPECT_FALSE(arrangement::from_legacy("single", "1280x720", ""));
  EXPECT_FALSE(arrangement::from_legacy("dual-horizontal", "3840x2160", ""));
  EXPECT_FALSE(arrangement::from_legacy("physical", "", ""));
}

TEST(PlankArrangement, NamesMatchTheWire) {
  EXPECT_EQ(arrangement::backing_name(arrangement::backing_t::physical), "physical");
  EXPECT_EQ(arrangement::backing_name(arrangement::backing_t::physical_viewport),
            "physical-viewport");
  EXPECT_EQ(arrangement::backing_name(arrangement::backing_t::virtual_output), "virtual");
  EXPECT_EQ(arrangement::error_code(arrangement::error_t::not_negotiated), "not_negotiated");
  EXPECT_EQ(arrangement::error_code(arrangement::error_t::none), "");
  EXPECT_EQ(arrangement::parse_mode_name("3840x2160"), (std::pair {3840, 2160}));
  EXPECT_FALSE(arrangement::parse_mode_name("3840x"));
  EXPECT_FALSE(arrangement::parse_mode_name("0x2160"));
  EXPECT_FALSE(arrangement::parse_mode_name("3840X2160"));
}
