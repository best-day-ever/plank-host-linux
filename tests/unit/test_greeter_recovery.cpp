/**
 * @file test_greeter_recovery.cpp
 * @brief Checks bounded GDM recovery across a failed greeter handoff.
 */
#include "src/session/greeter_recovery.h"

#include <gtest/gtest.h>

using namespace std::chrono_literals;

TEST(GreeterRecovery, IgnoresVanishedSeatRecordsButProtectsUserSessions) {
  using plank::session::seat_session_blocks_greeter_recovery;
  EXPECT_FALSE(seat_session_blocks_greeter_recovery(0, "greeter"));
  EXPECT_TRUE(seat_session_blocks_greeter_recovery(0, "user"));
  EXPECT_FALSE(seat_session_blocks_greeter_recovery(-ENXIO, ""));
  EXPECT_FALSE(seat_session_blocks_greeter_recovery(-ENOENT, ""));
  EXPECT_TRUE(seat_session_blocks_greeter_recovery(-EACCES, ""));
  EXPECT_TRUE(plank::session::session_record_vanished(-ENOENT));
  EXPECT_TRUE(plank::session::session_record_vanished(-ENXIO));
  EXPECT_FALSE(plank::session::session_record_vanished(-EACCES));
}

TEST(GreeterRecovery, WaitsForStalledGreeterAndRequiresSafeState) {
  plank::session::greeter_recovery_t recovery;
  const auto start = plank::session::greeter_recovery_t::clock::time_point {};
  EXPECT_FALSE(recovery.observe("c1", false, true, start));
  EXPECT_FALSE(recovery.observe("c1", false, true, start + 19s));
  EXPECT_FALSE(recovery.observe("c1", false, false, start + 21s));
  EXPECT_TRUE(recovery.observe("c1", false, true, start + 22s));
  EXPECT_FALSE(recovery.observe("c1", false, true, start + 23s));
}

TEST(GreeterRecovery, LimitsRestartsAcrossNewGreeterSessions) {
  plank::session::greeter_recovery_t recovery;
  const auto start = plank::session::greeter_recovery_t::clock::time_point {};
  recovery.observe("c1", false, true, start);
  EXPECT_TRUE(recovery.observe("c1", false, true, start + 20s));
  EXPECT_FALSE(recovery.observe("", false, false, start + 21s));
  EXPECT_FALSE(recovery.observe("c2", false, true, start + 22s));
  EXPECT_TRUE(recovery.observe("c2", false, true, start + 42s));
  EXPECT_FALSE(recovery.observe("c3", false, true, start + 43s));
  EXPECT_FALSE(recovery.observe("c3", false, true, start + 90s));
  EXPECT_FALSE(recovery.observe("c3", true, false, start + 91s));
  EXPECT_FALSE(recovery.observe("c4", false, true, start + 92s));
  EXPECT_FALSE(recovery.observe("c4", false, true, start + 112s));
  EXPECT_TRUE(recovery.observe("c4", false, true, start + 650s));
}

TEST(GreeterRecovery, InactiveGreeterWaitsAndRecoversOnlyAfterLeasesAreGone) {
  plank::session::greeter_recovery_t recovery;
  const auto start = plank::session::greeter_recovery_t::clock::time_point {};
  EXPECT_FALSE(recovery.observe("c21", false, false, start));
  EXPECT_FALSE(recovery.observe("c21", false, false, start + 25s));
  EXPECT_TRUE(recovery.observe("c21", false, true, start + 26s));
  EXPECT_FALSE(recovery.observe("c21", true, false, start + 27s));
}

TEST(GreeterActivation, ClosingUsersAllowActivationButStillPreventDestructiveRecovery) {
  using plank::session::seat_session_blocks_greeter_activation;
  EXPECT_FALSE(seat_session_blocks_greeter_activation(0, "greeter", 0, "online", 0));
  EXPECT_FALSE(seat_session_blocks_greeter_activation(0, "user", 0, "closing", 0));
  EXPECT_TRUE(plank::session::seat_session_blocks_greeter_recovery(0, "user"));
  EXPECT_TRUE(seat_session_blocks_greeter_activation(0, "user", 0, "closing", 1));
  EXPECT_TRUE(seat_session_blocks_greeter_activation(0, "user", 0, "online", 0));
  EXPECT_TRUE(seat_session_blocks_greeter_activation(0, "user", 0, "active", 1));
  EXPECT_TRUE(seat_session_blocks_greeter_activation(0, "user-early", 0, "closing", 0));
  EXPECT_TRUE(seat_session_blocks_greeter_activation(-EACCES, "", 0, "", 0));
  EXPECT_TRUE(seat_session_blocks_greeter_activation(0, "user", -EACCES, "", 0));
  EXPECT_TRUE(seat_session_blocks_greeter_activation(0, "user", 0, "closing", -EACCES));
  EXPECT_FALSE(seat_session_blocks_greeter_activation(-ENXIO, "", -ENXIO, "", -ENXIO));
  EXPECT_FALSE(seat_session_blocks_greeter_activation(-ENOENT, "", -ENOENT, "", -ENOENT));
}

TEST(GreeterActivation, RevalidatesBeforeCallingLogindAndReturnsItsFailure) {
  int calls = 0;
  auto activate = [&](std::string_view id) { ++calls; return id == "c1"; };
  EXPECT_FALSE(plank::session::activate_greeter_if_current("", [] { return "c1"; }, activate));
  EXPECT_FALSE(plank::session::activate_greeter_if_current("c1", [] { return ""; }, activate));
  EXPECT_FALSE(plank::session::activate_greeter_if_current("c1", [] { return "c2"; }, activate));
  EXPECT_EQ(calls, 0);
  EXPECT_FALSE(plank::session::activate_greeter_if_current("c2", [] { return "c2"; }, activate));
  EXPECT_TRUE(plank::session::activate_greeter_if_current("c1", [] { return "c1"; }, activate));
  EXPECT_EQ(calls, 2);
}

TEST(GreeterActivation, BoundsRetriesAndRecoversEverySubsequentSignOut) {
  plank::session::greeter_activation_t activation;
  const auto start = plank::session::greeter_activation_t::clock::time_point {};
  EXPECT_FALSE(activation.observe("c1", start));
  EXPECT_FALSE(activation.observe("c1", start + 2s));
  EXPECT_TRUE(activation.observe("c1", start + 3s));
  EXPECT_FALSE(activation.observe("c1", start + 4s));
  EXPECT_FALSE(activation.observe("c1", start + 22s));
  EXPECT_TRUE(activation.observe("c1", start + 23s));
  EXPECT_FALSE(activation.observe("c1", start + 90s));
  EXPECT_FALSE(activation.observe("", start + 91s));
  EXPECT_FALSE(activation.observe("c1", start + 92s));
  EXPECT_TRUE(activation.observe("c1", start + 95s));
  EXPECT_FALSE(activation.observe("c2", start + 96s));
  EXPECT_TRUE(activation.observe("c2", start + 99s));
  EXPECT_FALSE(activation.observe("c3", start + 100s));
  EXPECT_TRUE(activation.observe("c3", start + 103s));
}
