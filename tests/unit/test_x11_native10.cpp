/**
 * @file tests/unit/test_x11_native10.cpp
 * @brief Tests for native depth-30 X11 capture conversion.
 */

#include "../tests_common.h"

#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
  #include <array>

  #include <src/platform/linux/x11grab.h>

TEST(X11Native10Test, UnpacksQualifiedVisualIntoIdentityGbrPlanes) {
  constexpr std::array<std::uint32_t, 5> source {
    0U,
    0x000003ffU,
    0x000ffc00U,
    0x3ff00000U,
    0x2aa555aaU,
  };
  std::array<std::uint16_t, source.size()> green {};
  std::array<std::uint16_t, source.size()> blue {};
  std::array<std::uint16_t, source.size()> red {};

  platf::x11::unpack_xrgb10_to_gbr10_row(
    source.data(), green.data(), blue.data(), red.data(), source.size());

  EXPECT_EQ(red, (std::array<std::uint16_t, source.size()> {0, 1023, 0, 0, 426}));
  EXPECT_EQ(green, (std::array<std::uint16_t, source.size()> {0, 0, 1023, 0, 341}));
  EXPECT_EQ(blue, (std::array<std::uint16_t, source.size()> {0, 0, 0, 1023, 682}));
}

TEST(X11Native10Test, ScalesDirectlyIntoTenBitIdentityPlanes) {
  constexpr std::array<std::uint32_t, 4> source {
    0x00000000U,
    0x3ff003ffU,
    0x000ffc00U,
    0x3fffffffU,
  };
  std::array<std::uint16_t, 1> green {};
  std::array<std::uint16_t, 1> blue {};
  std::array<std::uint16_t, 1> red {};

  platf::x11::scale_xrgb10_to_gbr10(
    reinterpret_cast<const std::uint8_t *>(source.data()),
    2U * sizeof(std::uint32_t), 2, 2,
    green.data(), sizeof(std::uint16_t),
    blue.data(), sizeof(std::uint16_t),
    red.data(), sizeof(std::uint16_t), 1, 1);

  EXPECT_EQ(green[0], 512);
  EXPECT_EQ(blue[0], 512);
  EXPECT_EQ(red[0], 512);
}

TEST(X11Native10Test, UsesCenterAlignedBilinearSampling) {
  constexpr std::array<std::uint32_t, 2> source {0U, 0x000003ffU};
  std::array<std::uint16_t, 4> green {};
  std::array<std::uint16_t, 4> blue {};
  std::array<std::uint16_t, 4> red {};

  platf::x11::scale_xrgb10_to_gbr10(
    reinterpret_cast<const std::uint8_t *>(source.data()),
    2U * sizeof(std::uint32_t), 2, 1,
    green.data(), green.size() * sizeof(std::uint16_t),
    blue.data(), blue.size() * sizeof(std::uint16_t),
    red.data(), red.size() * sizeof(std::uint16_t), 4, 1);

  EXPECT_EQ(red, (std::array<std::uint16_t, 4> {0, 256, 767, 1023}));
  EXPECT_EQ(green, (std::array<std::uint16_t, 4> {0, 0, 0, 0}));
  EXPECT_EQ(blue, (std::array<std::uint16_t, 4> {0, 0, 0, 0}));
}
#endif
