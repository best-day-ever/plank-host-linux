/**
 * @file tests/unit/test_display_lifecycle.cpp
 * @brief Display snapshots remain owned until exact recovery and inventory publication succeeds.
 */
#include "src/session/display_lifecycle.h"

#include <gtest/gtest.h>
#include <vector>

namespace display = plank::display;

namespace {
  using steady_clock_t = std::chrono::steady_clock;
  const auto now = steady_clock_t::time_point {std::chrono::seconds {100}};

  struct lease_t {
    std::string owner;
    std::string session;
    std::string snapshot;
    bool active {};
    steady_clock_t::time_point deadline;
    bool operator==(const lease_t &) const = default;
  };

  lease_t original() {
    return {"owner", "old-server", "original-layout", true, steady_clock_t::time_point::max()};
  }

  lease_t attempted() {
    return {"owner", "new-server", "new-server-original", false, now};
  }
}

TEST(DisplayLifecycle, FailedRecordCannotMutateOrRestoreAnExistingLease) {
  std::optional<lease_t> owned {original()};
  const auto before = owned;
  int changes = 0, restores = 0;
  const auto result = display::recorded_display_change(
    [] { return false; }, [&] { ++changes; return std::string {}; },
    [&] { ++restores; return true; });
  display::reconcile_display_change(owned, attempted(), result.effect, now);
  EXPECT_EQ(result.reason, "state_failed");
  EXPECT_EQ(result.effect, display::display_change_effect_t::unchanged);
  EXPECT_EQ(changes, 0);
  EXPECT_EQ(restores, 0);
  EXPECT_EQ(owned, before);
}

TEST(DisplayLifecycle, PreMutationRefusalPreservesOwnerSnapshotAndDeadline) {
  for (const bool active : {false, true}) {
    auto previous = original();
    previous.active = active;
    previous.deadline = active ? steady_clock_t::time_point::max() : now + std::chrono::seconds {7};
    std::optional<lease_t> owned {previous};
    display::reconcile_display_change(
      owned, attempted(), display::display_change_effect_t::unchanged, now);
    ASSERT_TRUE(owned);
    EXPECT_EQ(*owned, previous);
  }
}

TEST(DisplayLifecycle, RefusedFirstAcquireDoesNotCreateAnOwner) {
  std::optional<lease_t> owned;
  display::reconcile_display_change(
    owned, attempted(), display::display_change_effect_t::unchanged, now);
  EXPECT_FALSE(owned);
}

TEST(DisplayLifecycle, SuccessfulApplyIsRecordedBeforeMutationAndKeepsOriginalSnapshot) {
  std::vector<std::string> events;
  const auto result = display::recorded_display_change(
    [&] { events.push_back("record"); return true; },
    [&] { events.push_back("change"); return std::string {}; },
    [&] { events.push_back("restore"); return true; });
  EXPECT_EQ(events, (std::vector<std::string> {"record", "change"}));
  EXPECT_TRUE(result.reason.empty());
  std::optional<lease_t> owned;
  auto lease = attempted();
  lease.active = true;
  lease.deadline = steady_clock_t::time_point::max();
  display::reconcile_display_change(owned, lease, result.effect, now);
  ASSERT_TRUE(owned);
  EXPECT_EQ(*owned, lease);
}

TEST(DisplayLifecycle, EveryApplyFailureRunsExactRollbackBeforeDroppingOwnership) {
  for (const auto *reason : {"visibility_prepare_failed", "visibility_finalize_failed", "verify_failed"}) {
    std::vector<std::string> events;
    std::optional<std::string> record;
    const auto next = attempted();
    const auto result = display::recorded_display_change(
      [&] { events.push_back("record"); record = next.snapshot; return true; },
      [&] { events.push_back("change"); return std::string {reason}; },
      [&] { events.push_back("exact-restore"); record.reset(); return true; });
    EXPECT_EQ(result.reason, reason);
    EXPECT_EQ(result.effect, display::display_change_effect_t::restored);
    EXPECT_EQ(events, (std::vector<std::string> {"record", "change", "exact-restore"}));
    std::optional<lease_t> owned {original()};
    display::reconcile_display_change(owned, next, result.effect, now);
    EXPECT_FALSE(record);
    EXPECT_FALSE(owned);
  }
}

TEST(DisplayLifecycle, FailedNewServerCarryKeepsItsRecordAndOwnerForRecovery) {
  std::optional<std::string> record {"old-server-original"};
  std::optional<lease_t> owned {original()};
  auto next = attempted();
  next.active = true;
  next.deadline = steady_clock_t::time_point::max();
  const auto result = display::recorded_display_change(
    [&] { record = next.snapshot; return true; },
    [] { return std::string {"verify_failed"}; },
    [&] {
      // A working emergency physical output still cannot clear the exact snapshot.
      EXPECT_EQ(record, next.snapshot);
      return false;
    });
  display::reconcile_display_change(owned, next, result.effect, now);
  ASSERT_TRUE(owned);
  EXPECT_EQ(owned->owner, next.owner);
  EXPECT_EQ(owned->session, next.session);
  EXPECT_EQ(owned->snapshot, next.snapshot);
  EXPECT_EQ(record, next.snapshot);
  EXPECT_FALSE(owned->active);
  EXPECT_EQ(owned->deadline, now + std::chrono::seconds {30});
  // A later successful exact recovery is the transition that releases ownership.
  record.reset();
  display::reconcile_display_change(owned, next, display::display_change_effect_t::restored,
                                    owned->deadline);
  EXPECT_FALSE(owned);
  EXPECT_FALSE(record);
}

TEST(DisplayLifecycle, RepeatedRecoveryFailureRetainsSnapshotAndBoundsRetryFrequency) {
  auto lease = original();
  display::retry_display_recovery(lease, now);
  EXPECT_EQ(lease.snapshot, original().snapshot);
  EXPECT_EQ(lease.owner, original().owner);
  EXPECT_FALSE(lease.active);
  const auto retry = lease.deadline;
  EXPECT_EQ(retry, now + std::chrono::seconds {30});
  display::retry_display_recovery(lease, retry);
  EXPECT_EQ(lease.deadline, now + std::chrono::seconds {60});
  EXPECT_EQ(lease.snapshot, original().snapshot);
}

TEST(DisplayInventoryPublication, FailedCaptureRetriesInTheSameSession) {
  std::optional<int> cached;
  std::string ready;
  int captures = 0, writes = 0;
  const auto capture = [&]() -> std::optional<int> {
    return ++captures == 1 ? std::nullopt : std::optional<int> {42};
  };
  const auto publish = [&](int inventory) { ++writes; return inventory == 42; };
  EXPECT_FALSE(display::publish_session_inventory(cached, ready, "server", capture, publish));
  EXPECT_FALSE(cached);
  EXPECT_TRUE(ready.empty());
  EXPECT_EQ(writes, 0);
  EXPECT_TRUE(display::publish_session_inventory(cached, ready, "server", capture, publish));
  EXPECT_EQ(captures, 2);
  EXPECT_EQ(writes, 1);
  EXPECT_EQ(cached, 42);
  EXPECT_EQ(ready, "server");
}

TEST(DisplayInventoryPublication, FailedPublicationDoesNotMakeTheSessionReady) {
  std::optional<int> cached;
  std::string ready;
  int writes = 0;
  const auto capture = [] { return std::optional<int> {42}; };
  const auto publish = [&](int) { return ++writes > 1; };
  EXPECT_FALSE(display::publish_session_inventory(cached, ready, "server", capture, publish));
  EXPECT_FALSE(cached);
  EXPECT_TRUE(ready.empty());
  EXPECT_TRUE(display::publish_session_inventory(cached, ready, "server", capture, publish));
  EXPECT_EQ(ready, "server");
  EXPECT_EQ(writes, 2);
}

TEST(DisplayInventoryPublication, FailedNewSessionCaptureCannotReuseAnOldInventory) {
  std::optional<int> cached {1};
  std::string ready {"old-server"};
  EXPECT_FALSE(display::publish_session_inventory(cached, ready, "new-server",
    [] { return std::optional<int> {}; }, [](int) { ADD_FAILURE(); return true; }));
  EXPECT_FALSE(cached);
  EXPECT_TRUE(ready.empty());
  EXPECT_TRUE(display::publish_session_inventory(cached, ready, "new-server",
    [] { return std::optional<int> {2}; }, [](int value) { return value == 2; }));
  EXPECT_EQ(cached, 2);
  EXPECT_EQ(ready, "new-server");
}

TEST(DisplayInventoryPublication, PublishedSameSessionInventoryIsNotRecaptured) {
  std::optional<int> cached {42};
  std::string ready {"server"};
  EXPECT_TRUE(display::publish_session_inventory(cached, ready, "server",
    [] { ADD_FAILURE(); return std::optional<int> {}; },
    [](int) { ADD_FAILURE(); return false; }));
  EXPECT_EQ(cached, 42);
  EXPECT_EQ(ready, "server");
}
