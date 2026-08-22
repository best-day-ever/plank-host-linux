/**
 * @file tests/unit/test_session_context.cpp
 * @brief Security policy tests for StationConnect logind session selection.
 */
#include <gtest/gtest.h>

#include "src/session/session_context.h"

namespace session = stationconnect::session;

namespace {
  session::descriptor_t valid_session() {
    return {
      "c7",
      1000,
      "seat0",
      "x11",
      "user",
      "active",
      true,
      false,
    };
  }
}  // namespace

TEST(SessionContext, AcceptsActiveLocalSeat0UserAndGreeter) {
  auto descriptor = valid_session();
  EXPECT_TRUE(session::eligible_graphical_session(descriptor));

  descriptor.session_class = "greeter";
  EXPECT_TRUE(session::eligible_graphical_session(descriptor));
}

TEST(SessionContext, RejectsInactiveRemoteOrNonSeat0Sessions) {
  auto descriptor = valid_session();
  descriptor.active = false;
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.remote = true;
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.seat = "seat1";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.state = "closing";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));
}

TEST(SessionContext, RejectsUnsupportedSessionTypesAndClasses) {
  auto descriptor = valid_session();
  descriptor.type = "tty";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.type = "wayland";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.session_class = "lock-screen";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));
}

TEST(SessionContext, BuildsOnlyBoundedEligibleAttestations) {
  auto descriptor = valid_session();
  EXPECT_EQ(session::greeter_attestation_message(descriptor), "SC-GREETER-1\nc7\n1000");

  descriptor.id = "invalid\nsession";
  EXPECT_TRUE(session::greeter_attestation_message(descriptor).empty());

  descriptor = valid_session();
  descriptor.remote = true;
  EXPECT_TRUE(session::greeter_attestation_message(descriptor).empty());
}
