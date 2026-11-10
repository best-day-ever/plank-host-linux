#pragma once

#include <cstdint>
#include <optional>
#include <sys/types.h>

namespace plank::session {
  /** A support unlock is explicit, privileged and bound to an observed desktop. */
  inline bool support_unlock_allowed(std::optional<uid_t> actor, uid_t expected_owner,
                                     uid_t actual_owner, std::uint64_t expected_generation,
                                     std::uint64_t actual_generation, std::optional<bool> locked,
                                     bool support_authorized) {
    return actor && *actor != 0 && expected_owner != 0 && *actor != expected_owner &&
      expected_owner == actual_owner && expected_generation != 0 &&
      expected_generation == actual_generation && locked.value_or(false) && support_authorized;
  }
}
