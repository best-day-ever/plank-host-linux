/**
 * @file tests/unit/test_clipboard_protocol.cpp
 * @brief Tests for PLANK clipboard payload and UTF-8 validation.
 */
#include "src/clipboard_protocol.h"

#include <gtest/gtest.h>

namespace clipboard = stream::clipboard;

TEST(ClipboardProtocol, RequiresExactNonEmptyChunkLength) {
  PLANK_CLIPBOARD_WIRE_HEADER wire {};
  wire.chunkSize = util::endian::little(std::uint32_t {5});

  EXPECT_TRUE(clipboard::payload_size_matches(
    wire, sizeof(wire) + 5, PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  ));
  EXPECT_FALSE(clipboard::payload_size_matches(
    wire, sizeof(wire) + 4, PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  ));
  EXPECT_FALSE(clipboard::payload_size_matches(
    wire, sizeof(wire) + 6, PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  ));

  wire.chunkSize = 0;
  EXPECT_FALSE(clipboard::payload_size_matches(
    wire, sizeof(wire), PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  ));

  wire.chunkSize = util::endian::little(
    static_cast<std::uint32_t>(PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE + 1)
  );
  EXPECT_FALSE(clipboard::payload_size_matches(
    wire,
    sizeof(wire) + PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE + 1,
    PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  ));
}

TEST(ClipboardProtocol, AcceptsUnicodeScalarsOnly) {
  const std::uint8_t valid[] = {0xF0, 0x9F, 0x94, 0xA5};
  EXPECT_TRUE(clipboard::valid_utf8(valid, sizeof(valid)));

  const std::uint8_t overlong[] = {0xC0, 0xAF};
  EXPECT_FALSE(clipboard::valid_utf8(overlong, sizeof(overlong)));

  const std::uint8_t surrogate[] = {0xED, 0xA0, 0x80};
  EXPECT_FALSE(clipboard::valid_utf8(surrogate, sizeof(surrogate)));

  const std::uint8_t out_of_range[] = {0xF4, 0x90, 0x80, 0x80};
  EXPECT_FALSE(clipboard::valid_utf8(out_of_range, sizeof(out_of_range)));

  const std::uint8_t embedded_null[] = {'a', 0, 'b'};
  EXPECT_FALSE(clipboard::valid_utf8(embedded_null, sizeof(embedded_null)));
  EXPECT_FALSE(clipboard::valid_utf8(nullptr, 0));
}
