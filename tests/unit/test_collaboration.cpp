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
    state.ui_connected = true;
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

TEST(CollaborationSupport, DisabledOrFailedGroupLookupNeverAuthorizes) {
  unsigned calls = 0;
  const auto member = [&](uid_t uid, const std::string &group) {
    ++calls;
    return uid == 1002 && group == "support-admins";
  };
  EXPECT_FALSE(support_authorized(1002, "", member));
  EXPECT_EQ(calls, 0);
  EXPECT_FALSE(support_authorized(1003, "support-admins", member));
  EXPECT_FALSE(support_authorized(1002, "missing-group", member));
  EXPECT_TRUE(support_authorized(1002, "support-admins", member));
  EXPECT_FALSE(support_authorized(1002, "support-admins", [](auto, const auto &) { return false; }));
}
TEST(CollaborationSupport, JoinsWithoutConsentOrHelperAndOwnerCannotDeny) {
  registry_t state;
  auto entry = state.add(1002, "support", owner, "id", "grant", now, true);
  ASSERT_TRUE(entry);
  EXPECT_EQ(entry->lease->permission, permission_t::control);
  EXPECT_FALSE(entry->lease->input_suspended);
  for (const auto permission : {permission_t::denied, permission_t::revoked, permission_t::view})
    EXPECT_FALSE(state.decide(entry->id, owner.owner, owner, permission));
  state.refresh(&owner, false, now);
  EXPECT_EQ(entry->lease->permission, permission_t::control);
  EXPECT_FALSE(state.claim(entry->grant, 1003, owner, now, true));
  EXPECT_FALSE(state.claim(entry->grant, 1002, {1001, 8}, now, true));
  EXPECT_TRUE(state.claim(entry->grant, 1002, owner, now, true));
  EXPECT_FALSE(state.claim(entry->grant, 1002, owner, now, true));
  state.helper_disconnected();
  state.refresh(&owner, false, now + std::chrono::hours {12});
  EXPECT_EQ(entry->lease->permission, permission_t::control);
}
TEST(CollaborationSupport, RevokedMembershipCannotUseAnUnclaimedGrant) {
  registry_t state;
  const auto entry = state.add(1002, "support", owner, "id", "grant", now, true);
  EXPECT_FALSE(state.claim(entry->grant, 1002, owner, now, false));
  EXPECT_EQ(entry->lease->permission, permission_t::revoked);
  EXPECT_FALSE(state.claim(entry->grant, 1002, owner, now, true));
}
TEST(CollaborationSupport, SupportCannotKeepAStaleOrAbandonedDesktop) {
  for (int reason = 0; reason < 5; ++reason) {
    registry_t state;
    const auto entry = state.add(1002, "support", owner, "id", "grant", now, true);
    ASSERT_TRUE(state.claim(entry->grant, 1002, owner, now, true));
    unsigned stops = 0, releases = 0;
    entry->lease->revoke_transport = [&] { ++stops; };
    entry->lease->release_input = [&] { ++releases; };
    const desktop_t next {1001, 8};
    if (reason == 0) state.refresh(nullptr, false, now);
    if (reason == 1) state.refresh(&next, false, now);
    if (reason == 2) state.revoke_all();
    if (reason == 3) state.ended(entry->lease);
    if (reason == 4) state.add(1002, "former-support", owner, "new-id", "new-grant", now, false);
    EXPECT_EQ(entry->lease->permission, permission_t::revoked);
    EXPECT_EQ(stops, 1);
    EXPECT_EQ(releases, 1);
  }
}
TEST(CollaborationSupport, ConsentGuestsStillFailClosedOnHelperLoss) {
  registry_t state;
  auto ordinary = request(state);
  ASSERT_TRUE(state.decide(ordinary->id, owner.owner, owner, permission_t::control));
  auto support = state.add(1003, "support", owner, "support-id", "support-grant", now, true);
  state.helper_disconnected();
  EXPECT_EQ(ordinary->lease->permission, permission_t::revoked);
  EXPECT_EQ(support->lease->permission, permission_t::control);
  EXPECT_FALSE(state.claim(ordinary->grant, 1002, owner, now, true));
  EXPECT_TRUE(state.claim(support->grant, 1003, owner, now, true));
}
TEST(CollaborationSupport, OrdinaryApprovalCannotLaunchWithoutHelperEvenForAdmin) {
  registry_t state;
  auto ordinary = request(state);
  ASSERT_TRUE(state.decide(ordinary->id, owner.owner, owner, permission_t::control));
  state.ui_connected = false;
  EXPECT_FALSE(state.claim(ordinary->grant, 1002, owner, now, true));
}
TEST(CollaborationSupport, OrdinaryRequestsCannotExhaustBoundedSupportSlots) {
  registry_t state;
  for (uid_t uid = 1002; uid < 1006; ++uid) ASSERT_TRUE(request(state, uid));
  EXPECT_FALSE(request(state, 1006));
  for (uid_t uid = 1006; uid < 1010; ++uid)
    ASSERT_TRUE(state.add(uid, "support", owner, std::to_string(uid), std::to_string(uid), now, true));
  EXPECT_FALSE(state.add(1010, "support", owner, "extra", "extra", now, true));
}
TEST(CollaborationSupport, ExpiryAndSecurityPanelStillApply) {
  registry_t state;
  auto entry = state.add(1002, "support", owner, "id", "grant", now, true);
  state.suspend(true);
  EXPECT_TRUE(entry->lease->input_suspended);
  state.suspend(false);
  EXPECT_FALSE(entry->lease->input_suspended);
  state.refresh(&owner, false, now + std::chrono::seconds {120});
  EXPECT_EQ(entry->lease->permission, permission_t::expired);
  EXPECT_FALSE(state.claim(entry->grant, 1002, owner, now, true));
}

TEST(CollaborationSupport, NewSupportRequestCannotUnsuspendAnOpenOwnerPanel) {
  registry_t state;
  auto ordinary = request(state);
  ASSERT_TRUE(state.decide(ordinary->id, owner.owner, owner, permission_t::control));
  state.suspend(true);
  auto support = state.add(1003, "support", owner, "id", "grant", now, true);
  ASSERT_TRUE(support);
  EXPECT_TRUE(ordinary->lease->input_suspended);
  EXPECT_TRUE(support->lease->input_suspended);
  state.suspend(false);
  EXPECT_FALSE(ordinary->lease->input_suspended);
  EXPECT_FALSE(support->lease->input_suspended);
}
