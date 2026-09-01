/**
 * @file tests/unit/test_plank_bitrate.cpp
 * @brief Tests PLANK active-session bitrate payload validation.
 */

#include "src/plank_bitrate.h"

#include <array>
#include <string_view>

#include "../tests_common.h"

namespace {
std::string_view payload(const std::array<char, 4> &bytes) {
  return {bytes.data(), bytes.size()};
}
}

TEST(PlankBitrate, AcceptsLittleEndianRequest) {
  const std::array<char, 4> encoded {char(0xA0), char(0x86), char(0x01), char(0x00)};
  const auto decoded = plank::bitrate::decode_request(payload(encoded));
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(*decoded, 100000);
}

TEST(PlankBitrate, RejectsMalformedAndOutOfRangeRequests) {
  EXPECT_FALSE(plank::bitrate::decode_request("\x00\x01\x02").has_value());

  const std::array<char, 4> below_minimum {char(0xF3), char(0x01), char(0x00), char(0x00)};
  EXPECT_FALSE(plank::bitrate::decode_request(payload(below_minimum)).has_value());

  const std::array<char, 4> above_maximum {char(0x21), char(0xA1), char(0x07), char(0x00)};
  EXPECT_FALSE(plank::bitrate::decode_request(payload(above_maximum)).has_value());
}

TEST(PlankBitrate, ValidatesExactStartupTarget) {
  EXPECT_EQ(plank::bitrate::validate_target(100000), 100000);
  EXPECT_EQ(plank::bitrate::validate_target(
              plank::bitrate::minimum_kbps),
            plank::bitrate::minimum_kbps);
  EXPECT_EQ(plank::bitrate::validate_target(
              plank::bitrate::maximum_kbps),
            plank::bitrate::maximum_kbps);
  EXPECT_FALSE(plank::bitrate::validate_target(0).has_value());
  EXPECT_FALSE(plank::bitrate::validate_target(500001).has_value());
}
