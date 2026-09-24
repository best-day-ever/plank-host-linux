#pragma once

#include <cstdint>

#include "plank_topology.h"

namespace plank::clipboard_entitlements {
  constexpr std::uint32_t effective_features(std::uint32_t requested,
                                              bool text_allowed,
                                              bool files_allowed) {
    if (!text_allowed) {
      requested &= ~(topology::feature_clipboard_sync | topology::feature_file_clipboard);
    } else if (!files_allowed) {
      requested &= ~topology::feature_file_clipboard;
    }
    return requested;
  }
}
