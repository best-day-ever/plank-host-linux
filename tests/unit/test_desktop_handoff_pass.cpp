/**
 * @file tests/unit/test_desktop_handoff_pass.cpp
 * @brief Tests for the one-shot GDM handoff pass shared with pam_plank_handoff.so.
 */
#include "src/auth/desktop_handoff_pass.h"

#include <gtest/gtest.h>

namespace handoff = plank::auth::handoff;

TEST(DesktopHandoffPass, RoundTripsTheExactFormat) {
  const handoff::pass_t pass {1234, "alice", 987654};
  const auto encoded = handoff::encode(pass);
  EXPECT_EQ(encoded, "PLANK-HANDOFF-1\nuid=1234\naccount=alice\nexpires=987654\n");
  const auto parsed = handoff::parse(encoded);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->uid, 1234U);
  EXPECT_EQ(parsed->account, "alice");
  EXPECT_EQ(parsed->expires_ms, 987654U);
}

TEST(DesktopHandoffPass, RejectsMalformedPasses) {
  EXPECT_FALSE(handoff::parse(""));
  EXPECT_FALSE(handoff::parse("PLANK-HANDOFF-2\nuid=1\naccount=a\nexpires=1\n"));
  EXPECT_FALSE(handoff::parse("PLANK-HANDOFF-1\nuid=1\naccount=a\nexpires=1"));
  EXPECT_FALSE(handoff::parse("PLANK-HANDOFF-1\nuid=1\naccount=a\nexpires=1\nextra\n"));
  EXPECT_FALSE(handoff::parse("PLANK-HANDOFF-1\nuid=x1\naccount=a\nexpires=1\n"));
  EXPECT_FALSE(handoff::parse("PLANK-HANDOFF-1\nuid=\naccount=a\nexpires=1\n"));
  EXPECT_FALSE(handoff::parse("PLANK-HANDOFF-1\nuid=1\nexpires=1\naccount=a\n"));
  EXPECT_FALSE(handoff::parse("PLANK-HANDOFF-1\nuid=0\naccount=root\nexpires=1\n"));
  EXPECT_FALSE(handoff::parse("PLANK-HANDOFF-1\nuid=1\naccount=Alice\nexpires=1\n"));
  EXPECT_FALSE(handoff::parse(std::string(handoff::maximum_pass_size + 1, 'a')));
}

TEST(DesktopHandoffPass, TypesOnlyPlainAccountNames) {
  EXPECT_TRUE(handoff::typeable_account_name("alice"));
  EXPECT_TRUE(handoff::typeable_account_name("j.doe_2-x"));
  EXPECT_FALSE(handoff::typeable_account_name(""));
  EXPECT_FALSE(handoff::typeable_account_name("-alice"));
  EXPECT_FALSE(handoff::typeable_account_name("Alice"));
  EXPECT_FALSE(handoff::typeable_account_name("alice@IPA.EXAMPLE"));
  EXPECT_FALSE(handoff::typeable_account_name("a b"));
  EXPECT_FALSE(handoff::typeable_account_name("alice\n"));
  EXPECT_FALSE(handoff::typeable_account_name(std::string(handoff::maximum_account_name + 1, 'a')));
}

TEST(DesktopHandoffPass, AdmitsOnlyItsAccountBeforeExpiry) {
  const handoff::pass_t pass {1234, "alice", 50000};
  EXPECT_TRUE(handoff::admits(pass, 1234, "alice", 20000));
  EXPECT_TRUE(handoff::admits(pass, 1234, "alice", 49999));
  EXPECT_FALSE(handoff::admits(pass, 1234, "alice", 50000));
  EXPECT_FALSE(handoff::admits(pass, 1235, "alice", 20000));
  EXPECT_FALSE(handoff::admits(pass, 1234, "bob", 20000));
  EXPECT_FALSE(handoff::admits(pass, 0, "alice", 20000));
  // A deadline further out than one lifetime was not written by the worker.
  EXPECT_FALSE(handoff::admits(pass, 1234, "alice", 50000 - handoff::pass_lifetime_ms - 1));
}
