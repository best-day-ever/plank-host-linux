#include <cstring>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

extern "C" {
#include <moonlight-common-c/src/StationConnect.h>
}

#include "src/raw_hid_tablet.h"
#include "src/utility.h"

namespace {
  std::vector<std::uint8_t> make_frame(
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
}  // namespace

TEST(RawHidTablet, RejectsMalformedTransportFrames) {
  const auto mail = std::make_shared<safe::mail_raw_t>();
  raw_hid::tablet_t tablet {mail->queue<std::vector<std::uint8_t>>("raw-hid-test")};

  EXPECT_FALSE(tablet.handle({}));

  auto frame = make_frame(SC_RAW_HID_DETACH, 0, 1, nullptr, 0);
  reinterpret_cast<SC_RAW_HID_WIRE_HEADER *>(frame.data())->magic = 0;
  EXPECT_FALSE(tablet.handle(frame));

  frame = make_frame(SC_RAW_HID_DETACH, 0, 1, nullptr, 0);
  reinterpret_cast<SC_RAW_HID_WIRE_HEADER *>(frame.data())->payloadLength = util::endian::little<std::uint32_t>(1);
  EXPECT_FALSE(tablet.handle(frame));
}

TEST(RawHidTablet, EnforcesGenerationAndInterfaceBounds) {
  const auto mail = std::make_shared<safe::mail_raw_t>();
  raw_hid::tablet_t tablet {mail->queue<std::vector<std::uint8_t>>("raw-hid-test")};
  SC_RAW_HID_DEVICE_MESSAGE device {};
  device.interfaceCount = util::endian::little<std::uint16_t>(2);
  device.bus = util::endian::little<std::uint16_t>(3);
  device.vendor = util::endian::little<std::uint32_t>(0x056a);
  device.product = util::endian::little<std::uint32_t>(0x0357);

  EXPECT_TRUE(tablet.handle(make_frame(
    SC_RAW_HID_DEVICE,
    0,
    7,
    &device,
    sizeof(device)
  )));

  const std::uint8_t descriptor[] {0x05, 0x0d, 0x09, 0x02};
  EXPECT_FALSE(tablet.handle(make_frame(
    SC_RAW_HID_DESCRIPTOR,
    2,
    7,
    descriptor,
    sizeof(descriptor)
  )));
  EXPECT_FALSE(tablet.handle(make_frame(
    SC_RAW_HID_DESCRIPTOR,
    0,
    8,
    descriptor,
    sizeof(descriptor)
  )));
  EXPECT_TRUE(tablet.handle(make_frame(
    SC_RAW_HID_DESCRIPTOR,
    0,
    7,
    descriptor,
    sizeof(descriptor)
  )));
  EXPECT_FALSE(tablet.handle(make_frame(
    SC_RAW_HID_DESCRIPTOR,
    0,
    7,
    descriptor,
    sizeof(descriptor)
  )));
}
