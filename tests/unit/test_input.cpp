/**
 * @file tests/unit/test_input.cpp
 * @brief Tests for retained stream input and raw-HID tablet lifecycle behavior.
 */

// standard includes
#include <cstring>
#include <memory>
#include <string>
#include <vector>

extern "C" {
#include <moonlight-common-c/src/StationConnect.h>
}

// local includes
#include "../tests_common.h"
#include "src/config.h"
#include "src/input.h"
#include "src/platform/virtualhid_input.h"
#include "src/utility.h"

namespace {
  std::vector<std::uint8_t> make_raw_hid_device_frame(const std::uint16_t generation) {
    SC_RAW_HID_DEVICE_MESSAGE device {};
    device.interfaceCount = util::endian::little<std::uint16_t>(1);
    device.bus = util::endian::little<std::uint16_t>(3);
    device.vendor = util::endian::little<std::uint32_t>(0x056a);
    device.product = util::endian::little<std::uint32_t>(0x0357);

    std::vector<std::uint8_t> frame(sizeof(SC_RAW_HID_WIRE_HEADER) + sizeof(device));
    SC_RAW_HID_WIRE_HEADER header {};
    header.magic = util::endian::little(static_cast<std::uint32_t>(SC_RAW_HID_WIRE_MAGIC));
    header.version = util::endian::little(static_cast<std::uint16_t>(SC_RAW_HID_WIRE_VERSION));
    header.type = util::endian::little(static_cast<std::uint16_t>(SC_RAW_HID_DEVICE));
    header.generation = util::endian::little(generation);
    header.payloadLength = util::endian::little(static_cast<std::uint32_t>(sizeof(device)));
    std::memcpy(frame.data(), &header, sizeof(header));
    std::memcpy(frame.data() + sizeof(header), &device, sizeof(device));
    return frame;
  }

  /**
   * @brief Fixture that installs a fake global virtual input backend.
   */
  class InputRetainedSessionTest: public ::testing::Test {
  protected:
    /**
     * @brief Install an observable fake virtual-input runtime.
     */
    void SetUp() override {
      auto platform_input = platf::input();
      ASSERT_TRUE(platform_input);
      auto &context = platf::virtualhid::get_input_context(platform_input);
      context = platf::virtualhid::input_context_t {lvh::BackendKind::fake};
      ASSERT_NE(context.runtime, nullptr);
      input::testing::set_platform_input(std::move(platform_input));
    }

    /**
     * @brief Destroy retained test sessions.
     */
    void TearDown() override {
      input::terminate_retained_input();
      input::testing::set_platform_input({});
    }
  };
}  // namespace

TEST(InputConfigDefaults, AdvertisesNativePenWithoutRemappingRightAlt) {
  EXPECT_TRUE(config::input.keyboard);
  EXPECT_FALSE(config::input.key_rightalt_to_key_win);
  EXPECT_TRUE(config::input.mouse);
  EXPECT_TRUE(config::input.always_send_scancodes);
  EXPECT_TRUE(config::input.high_resolution_scrolling);
}

TEST_F(InputRetainedSessionTest, DisconnectSuspendsRatherThanDiscardingResumableRawTablet) {
  const std::string session_id = "resumed-tablet-client";
  std::uint64_t first_connection_id = 0;
  auto first = input::alloc(std::make_shared<safe::mail_raw_t>(), session_id, first_connection_id);
  ASSERT_TRUE(input::testing::handle_raw_hid(first, make_raw_hid_device_frame(7)));
  ASSERT_EQ(input::testing::raw_hid_generation(first), 7);

  std::uint64_t resumed_connection_id = 0;
  auto resumed = input::alloc(std::make_shared<safe::mail_raw_t>(), session_id, resumed_connection_id);
  ASSERT_EQ(first, resumed);
  ASSERT_GT(resumed_connection_id, first_connection_id);
  ASSERT_TRUE(input::testing::handle_raw_hid(resumed, make_raw_hid_device_frame(8)));
  ASSERT_EQ(input::testing::raw_hid_generation(resumed), 8);

  input::reset(first, first_connection_id);
  EXPECT_EQ(input::testing::raw_hid_generation(resumed), 8);

  input::reset(resumed, resumed_connection_id);
  EXPECT_EQ(input::testing::raw_hid_generation(resumed), 8);
}
