/**
 * @file tests/collaboration/test_monitor.cpp
 * @brief Isolated Linux fixture: consent-channel failure must not disable desktop revocation.
 * Run only in a disposable container; /run/plank must not already exist.
 */
#include <gtest/gtest.h>
#include "src/session/collaboration.h"
#include "src/session/session_context.h"
#include <atomic>
#include <filesystem>
#include <fstream>
#include <thread>

namespace {
  std::atomic<bool> unlocked {true};
  /** @brief Wait for the real monitor thread to enforce a terminal permission. */
  bool wait_revoked(const std::shared_ptr<plank::collaboration::request_t> &entry) {
    for (int i = 0; i < 100; ++i) {
      if (entry->lease->permission == plank::collaboration::permission_t::revoked) return true;
      std::this_thread::sleep_for(std::chrono::milliseconds {10});
    }
    return false;
  }
}
namespace plank::session {
  std::optional<uid_t> unlocked_desktop_owner() { return unlocked ? std::optional<uid_t> {1001} : std::nullopt; }
  std::uint64_t desktop_generation() { return 7; }
  bool request_collaboration_ui() { return false; }
}
TEST(CollaborationMonitor, FailedOwnerChannelStillRevokesSupportOnLockAndShutdown) {
  ASSERT_FALSE(std::filesystem::exists("/run/plank")) << "Disposable container required";
  ASSERT_TRUE(std::filesystem::create_directory("/run/plank"));
  // A regular file deliberately prevents opening the credential-checked listener.
  std::ofstream("/run/plank/collaboration.sock") << "fixture";
  auto &state = plank::collaboration::registry();
  std::shared_ptr<plank::collaboration::request_t> entry;
  {
    plank::collaboration::ui_t monitor;
    {
      std::lock_guard lock {state.mutex};
      entry = state.add(1002, "support", {1001, 7}, "id", "grant", std::chrono::steady_clock::now(), true);
    }
    ASSERT_TRUE(entry);
    unlocked = false;
    EXPECT_TRUE(wait_revoked(entry));
    unlocked = true;
    {
      std::lock_guard lock {state.mutex};
      entry = state.add(1002, "support", {1001, 7}, "id2", "grant2", std::chrono::steady_clock::now(), true);
    }
    ASSERT_TRUE(entry);
  }
  EXPECT_EQ(entry->lease->permission, plank::collaboration::permission_t::revoked);
  EXPECT_TRUE(std::filesystem::is_regular_file("/run/plank/collaboration.sock"));
  std::filesystem::remove("/run/plank/collaboration.sock");
  std::filesystem::remove("/run/plank");
}
