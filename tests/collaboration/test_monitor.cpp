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
  std::atomic<bool> pause_snapshot {false};
  std::atomic<bool> snapshot_taken {false};
  std::atomic<bool> release_snapshot {false};
  std::atomic<unsigned> observations {0};
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
  std::optional<uid_t> unlocked_desktop_owner() {
    const bool snapshot = unlocked.load();
    ++observations;
    if (pause_snapshot.exchange(false)) {
      snapshot_taken = true;
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {2};
      while (!release_snapshot && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds {1});
    }
    return snapshot ? std::optional<uid_t> {1001} : std::nullopt;
  }
  std::uint64_t desktop_generation() { return 7; }
  bool request_collaboration_ui() { return false; }
}
TEST(CollaborationMonitor, FreshUnlockGrantSurvivesAnEarlierLockedSnapshot) {
  ASSERT_FALSE(std::filesystem::exists("/run/plank"));
  ASSERT_TRUE(std::filesystem::create_directory("/run/plank"));
  std::ofstream("/run/plank/collaboration.sock") << "fixture";
  unlocked = false; snapshot_taken = false; release_snapshot = false;
  observations = 0; pause_snapshot = true;
  auto &state = plank::collaboration::registry();
  {
    plank::collaboration::ui_t monitor;
    for (unsigned i = 0; i < 100 && !snapshot_taken; ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds {5});
    EXPECT_TRUE(snapshot_taken);
    std::shared_ptr<plank::collaboration::request_t> entry;
    {
      // Match HTTPS: the desktop unlocks and the new grant is inserted while
      // the monitor still holds an older locked observation outside the mutex.
      std::lock_guard lock {state.mutex};
      unlocked = true;
      entry = state.add(1002, "support", {1001, 7}, "fresh-unlock", "fresh-grant",
                        std::chrono::steady_clock::now(), true);
    }
    release_snapshot = true;
    for (unsigned i = 0; i < 100 && observations < 2; ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds {5});
    EXPECT_GE(observations.load(), 2u);
    {
      std::lock_guard lock {state.mutex};
      ASSERT_TRUE(entry);
      EXPECT_EQ(entry->lease->permission, plank::collaboration::permission_t::control);
    }
  }
  std::filesystem::remove("/run/plank/collaboration.sock");
  std::filesystem::remove("/run/plank");
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
