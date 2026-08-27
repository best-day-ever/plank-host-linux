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
#endif
