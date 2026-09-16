/**
 * @file src/clipboard_protocol.h
 * @brief Shared validation helpers for PLANK clipboard frames.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
#include <moonlight-common-c/src/plank.h>
}

#include "utility.h"

namespace stream::clipboard {
  inline bool valid_utf8(const std::uint8_t *data, std::size_t size) {
    if (data == nullptr || size == 0) {
      return false;
    }
    for (std::size_t index = 0; index < size;) {
      const auto byte = data[index];
      if (byte <= 0x7F) {
        if (byte == 0) {
          return false;
        }
        ++index;
        continue;
      }
      const auto continuation = [&](std::size_t offset) {
        return index + offset < size && (data[index + offset] & 0xC0) == 0x80;
      };
      if (byte >= 0xC2 && byte <= 0xDF) {
        if (!continuation(1)) {
          return false;
        }
        index += 2;
        continue;
      }
      if (byte >= 0xE0 && byte <= 0xEF) {
        if (!continuation(1) || !continuation(2)) {
          return false;
        }
        const auto second = data[index + 1];
        if ((byte == 0xE0 && second < 0xA0) ||
            (byte == 0xED && second > 0x9F)) {
          return false;
        }
        index += 3;
        continue;
      }
      if (byte >= 0xF0 && byte <= 0xF4) {
        if (!continuation(1) || !continuation(2) || !continuation(3)) {
          return false;
        }
        const auto second = data[index + 1];
        if ((byte == 0xF0 && second < 0x90) ||
            (byte == 0xF4 && second > 0x8F)) {
          return false;
        }
        index += 4;
        continue;
      }
      return false;
    }
    return true;
  }

  inline std::uint32_t chunk_size(const PLANK_CLIPBOARD_WIRE_HEADER &wire) {
    std::uint32_t value {};
    std::memcpy(&value, &wire.chunkSize, sizeof(value));
    return util::endian::little(value);
  }

  inline bool payload_size_matches(const PLANK_CLIPBOARD_WIRE_HEADER &wire,
                                   std::size_t payload_size,
                                   std::uint32_t maximum_chunk_size) {
    const auto size = chunk_size(wire);
    return size > 0 &&
           size <= maximum_chunk_size &&
           payload_size == sizeof(wire) + size;
  }
}  // namespace stream::clipboard
