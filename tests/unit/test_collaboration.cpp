/**
 * @file tests/unit/test_collaboration.cpp
 * @brief Behavioral tests for desktop-bound consent, denial, expiry, revocation, and replay.
 */
#include <gtest/gtest.h>
#include "src/session/collaboration.h"
using namespace plank::collaboration;
namespace {
  const desktop_t owner {1001, 7};
  const auto now = std::chrono::steady_clock::now();
  /** @brief Make one deterministic request for authorization-state testing. */
  std::shared_ptr<request_t> request(registry_t &state, uid_t uid = 1002) {
    return state.add(uid, "support", owner, std::to_string(uid), "grant-" + std::to_string(uid), now);
  }
}
TEST(Collaboration, PendingNeverGrantsMediaAndOnlyOwnerCanApprove) {
  registry_t state;
  const auto entry = request(state);
  ASSERT_TRUE(entry);
  EXPECT_FALSE(state.claim(entry->grant, 1002, owner, now));
  EXPECT_FALSE(state.decide(entry->id, 1002, owner, permission_t::control));
  EXPECT_FALSE(state.decide(entry->id, 1001, {1001, 8}, permission_t::control));
  EXPECT_TRUE(state.decide(entry->id, 1001, owner, permission_t::view));
  EXPECT_TRUE(state.claim(entry->grant, 1002, owner, now));
  EXPECT_FALSE(state.claim(entry->grant, 1002, owner, now));
}
TEST(Collaboration, GrantIsBoundToGuestAndExactDesktop) {
  registry_t state;
  const auto entry = request(state);
  ASSERT_TRUE(state.decide(entry->id, 1001, owner, permission_t::control));
  EXPECT_FALSE(state.claim(entry->grant, 1003, owner, now));
  EXPECT_FALSE(state.claim(entry->grant, 1002, {1001, 8}, now));
  EXPECT_FALSE(state.find(entry->id, 1003));
  EXPECT_TRUE(state.find(entry->id, 1001));
}
TEST(Collaboration, DenyAndTimeoutCannotBeApprovedLater) {
  registry_t state;
  const auto entry = request(state);
  ASSERT_TRUE(state.decide(entry->id, 1001, owner, permission_t::denied));
  EXPECT_FALSE(state.decide(entry->id, 1001, owner, permission_t::control));
  const auto timed_out = request(state, 1003);
  state.refresh(&owner, true, now + std::chrono::seconds {121});
  EXPECT_EQ(timed_out->lease->permission, permission_t::expired);
  EXPECT_FALSE(state.decide(timed_out->id, 1001, owner, permission_t::view));
  EXPECT_FALSE(state.claim(timed_out->grant, 1003, owner, now));
}
TEST(Collaboration, RevocationAndDowngradeReleaseOnlyGuestInput) {
  registry_t state;
  const auto entry = request(state);
  unsigned releases = 0;
  entry->lease->release_input = [&]() { ++releases; };
  ASSERT_TRUE(state.decide(entry->id, 1001, owner, permission_t::control));
  ASSERT_TRUE(state.decide(entry->id, 1001, owner, permission_t::view));
  EXPECT_EQ(releases, 1);
  ASSERT_TRUE(state.decide(entry->id, 1001, owner, permission_t::control));
  state.revoke_all();
  EXPECT_EQ(releases, 2);
  EXPECT_EQ(entry->lease->permission, permission_t::revoked);
}
TEST(Collaboration, LockLogoutGenerationChangeAndHelperLossRevoke) {
  for (int reason = 0; reason < 3; ++reason) {
    registry_t state;
    const auto entry = request(state);
    ASSERT_TRUE(state.decide(entry->id, 1001, owner, permission_t::view));
    const desktop_t next {1001, 8};
    state.refresh(reason == 0 ? nullptr : reason == 1 ? &next : &owner, reason != 2, now);
    EXPECT_EQ(entry->lease->permission, permission_t::revoked);
  }
}
TEST(Collaboration, PendingConsentAndManagementPanelSuspendEveryGuest) {
  registry_t state;
  const auto entry = request(state);
  ASSERT_TRUE(state.decide(entry->id, 1001, owner, permission_t::control));
  state.suspend(false);
  EXPECT_FALSE(entry->lease->input_suspended);
  auto pending = request(state, 1003);
  EXPECT_TRUE(entry->lease->input_suspended);
  ASSERT_TRUE(state.decide(pending->id, 1001, owner, permission_t::denied));
  state.suspend(false);
  EXPECT_FALSE(entry->lease->input_suspended);
  state.suspend(true);
  EXPECT_TRUE(entry->lease->input_suspended);
}
TEST(Collaboration, DuplicateIsIdempotentAndAdmissionIsBounded) {
  registry_t state;
  const auto first = request(state);
  EXPECT_EQ(first, request(state));
  EXPECT_FALSE(state.add(1001, "owner", owner, "owner-id", "owner-grant", now));
  EXPECT_TRUE(request(state, 1003)); EXPECT_TRUE(request(state, 1004)); EXPECT_TRUE(request(state, 1005));
  EXPECT_FALSE(request(state, 1006));
  state.revoke_all();
  EXPECT_TRUE(request(state, 1006));
}
TEST(Collaboration, ActiveGrantDoesNotExpireButDisconnectRevokesIt) {
  registry_t state;
  const auto entry = request(state);
  ASSERT_TRUE(state.decide(entry->id, 1001, owner, permission_t::view));
  ASSERT_TRUE(state.claim(entry->grant, 1002, owner, now));
  state.refresh(&owner, true, now + std::chrono::hours {12});
  EXPECT_EQ(entry->lease->permission, permission_t::view);
  state.ended(entry->lease);
  EXPECT_EQ(entry->lease->permission, permission_t::revoked);
}
