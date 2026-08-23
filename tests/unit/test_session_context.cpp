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

  session::update_t valid_update() {
    return {
      7,
      valid_session(),
      {":0", "/run/user/1000/gdm/Xauthority", "/run/user/1000",
       "unix:path=/run/user/1000/bus", "unix:/run/user/1000/pulse/native",
       "/home/test/.config/pulse/cookie"},
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

TEST(SessionContext, RoundTripsBoundedDesktopUpdates) {
  const auto update = valid_update();
  const auto message = session::session_update_message(update);
  const auto parsed = session::parse_session_update(message);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->generation, update.generation);
  EXPECT_EQ(parsed->session.id, update.session.id);
  EXPECT_EQ(parsed->session.uid, update.session.uid);
  EXPECT_EQ(parsed->environment.display, update.environment.display);
  EXPECT_EQ(parsed->environment.pulse_cookie, update.environment.pulse_cookie);
}

TEST(SessionContext, RejectsMalformedOrIneligibleDesktopUpdates) {
  auto update = valid_update();
  auto message = session::session_update_message(update);
  ASSERT_FALSE(message.empty());
  message.pop_back();
  EXPECT_FALSE(session::parse_session_update(message));

  update.session.remote = true;
  EXPECT_TRUE(session::session_update_message(update).empty());

  update = valid_update();
  update.generation = 0;
  EXPECT_TRUE(session::session_update_message(update).empty());
}
