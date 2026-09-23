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
