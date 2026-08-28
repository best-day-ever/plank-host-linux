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
#include "src/raw_hid_tablet.h"
#include "src/utility.h"

namespace {
  std::vector<std::uint8_t> make_raw_hid_frame(
    const SC_RAW_HID_MESSAGE_TYPE type,
    const std::uint16_t interface_id,
    const std::uint16_t generation,
    const void *payload,
    const std::size_t payload_size
  ) {
    std::vector<std::uint8_t> frame(sizeof(SC_RAW_HID_WIRE_HEADER) + payload_size);
    SC_RAW_HID_WIRE_HEADER header {};
    header.magic = util::endian::little(static_cast<std::uint32_t>(SC_RAW_HID_WIRE_MAGIC));
    header.version = util::endian::little(static_cast<std::uint16_t>(SC_RAW_HID_WIRE_VERSION));
    header.type = util::endian::little(static_cast<std::uint16_t>(type));
    header.interfaceId = util::endian::little(interface_id);
    header.generation = util::endian::little(generation);
    header.payloadLength = util::endian::little(static_cast<std::uint32_t>(payload_size));
    std::memcpy(frame.data(), &header, sizeof(header));
    if (payload_size != 0) {
      std::memcpy(frame.data() + sizeof(header), payload, payload_size);
    }
    return frame;
  }

  std::vector<std::uint8_t> make_raw_hid_device_frame(
    const std::uint16_t generation,
    const std::uint32_t product = 0x0357
  ) {
    SC_RAW_HID_DEVICE_MESSAGE device {};
    device.interfaceCount = util::endian::little<std::uint16_t>(1);
    device.bus = util::endian::little<std::uint16_t>(3);
    device.vendor = util::endian::little<std::uint32_t>(0x056a);
    device.product = util::endian::little(product);
    std::memcpy(device.name, "Any exact raw tablet", 20);
    std::memcpy(device.unique, "model-independent", 17);
    return make_raw_hid_frame(SC_RAW_HID_DEVICE, 0, generation, &device, sizeof(device));
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

TEST_F(InputRetainedSessionTest, ConsumesNumLockWithoutChangingNumericKeypadIdentity) {
  const std::string session_id = "always-on-num-lock";
  std::uint64_t connection_id = 0;
  auto session = input::alloc(std::make_shared<safe::mail_raw_t>(), session_id, connection_id);

  input::testing::handle_keyboard(session, 0x61, false);
  EXPECT_EQ(input::testing::last_keyboard_code(), 0x61);

  input::testing::handle_keyboard(session, 0x90, false);
  input::testing::handle_keyboard(session, 0x90, true);
  EXPECT_EQ(input::testing::last_keyboard_code(), 0x61);
}

TEST_F(InputRetainedSessionTest, ExactRawTabletSuppressesNormalizedFallbackUntilDetach) {
  if (!raw_hid::available()) {
    GTEST_SKIP() << "/dev/uhid is unavailable to the test process";
  }

  const std::string session_id = "exclusive-raw-tablet";
  std::uint64_t connection_id = 0;
  auto session = input::alloc(std::make_shared<safe::mail_raw_t>(), session_id, connection_id);
  ASSERT_TRUE(input::testing::normalized_pen_enabled(session));

  constexpr std::uint16_t generation = 11;
  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_device_frame(generation, 0x0358)));
  EXPECT_TRUE(input::testing::normalized_pen_enabled(session));

  // Minimal valid HID application collection. Backend ownership changes from
  // the generic fallback to raw HID only after all descriptors are accepted
  // and exact UHID endpoints exist.
  const std::uint8_t descriptor[] {
    0x05, 0x01,  // Usage Page (Generic Desktop)
    0x09, 0x02,  // Usage (Mouse)
    0xa1, 0x01,  // Collection (Application)
    0xc0,  // End Collection
  };
  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_frame(
                                                        SC_RAW_HID_DESCRIPTOR,
                                                        0,
                                                        generation,
                                                        descriptor,
                                                        sizeof(descriptor)
                                                      )));
  EXPECT_FALSE(input::testing::normalized_pen_enabled(session));

  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_frame(
                                                        SC_RAW_HID_SUSPEND,
                                                        0,
                                                        generation,
                                                        nullptr,
                                                        0
                                                      )));
  EXPECT_FALSE(input::testing::normalized_pen_enabled(session));

  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_frame(
                                                        SC_RAW_HID_DETACH,
                                                        0,
                                                        generation,
                                                        nullptr,
                                                        0
                                                      )));
  EXPECT_TRUE(input::testing::normalized_pen_enabled(session));
}

TEST_F(InputRetainedSessionTest, NormalizedPenReleasesRetainedRawTabletEndpoints) {
  if (!raw_hid::available()) {
    GTEST_SKIP() << "/dev/uhid is unavailable to the test process";
  }

  const std::string session_id = "raw-to-normalized-tablet";
  std::uint64_t connection_id = 0;
  auto session = input::alloc(std::make_shared<safe::mail_raw_t>(), session_id, connection_id);

  constexpr std::uint16_t generation = 12;
  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_device_frame(generation, 0x0357)));
  const std::uint8_t descriptor[] {
    0x05, 0x01,
    0x09, 0x02,
    0xa1, 0x01,
    0xc0,
  };
  ASSERT_TRUE(input::testing::handle_raw_hid(session, make_raw_hid_frame(
                                                        SC_RAW_HID_DESCRIPTOR,
                                                        0,
                                                        generation,
                                                        descriptor,
                                                        sizeof(descriptor)
                                                      )));
  ASSERT_FALSE(input::testing::normalized_pen_enabled(session));
  ASSERT_EQ(input::testing::raw_hid_generation(session), generation);

  input::testing::select_normalized_pen(session);

  EXPECT_TRUE(input::testing::normalized_pen_enabled(session));
  EXPECT_EQ(input::testing::raw_hid_generation(session), 0);
}
