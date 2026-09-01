#include <string>

#include <gtest/gtest.h>

#include "src/auth/pam_broker_policy.h"

namespace auth = plank::auth;

TEST(PamBrokerPolicy, DefaultsToDenyWhenOptionIsAbsent) {
  std::string error;
  const auto policy = auth::parse_broker_policy("[security]\ncert = cert.pem\n", error);
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_FALSE(policy->allow_root_login);
}

TEST(PamBrokerPolicy, AcceptsExplicitBooleanValues) {
  std::string error;
  auto policy = auth::parse_broker_policy("[security]\nallow_root_login = true\n", error);
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_TRUE(policy->allow_root_login);

  error.clear();
  policy = auth::parse_broker_policy("[SECURITY]\nALLOW_ROOT_LOGIN = FALSE\n", error);
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_FALSE(policy->allow_root_login);
}

TEST(PamBrokerPolicy, RejectsInvalidOrDuplicateRootPolicy) {
  std::string error;
  EXPECT_FALSE(auth::parse_broker_policy(
    "[security]\nallow_root_login = yes\n", error
  ).has_value());
  EXPECT_FALSE(error.empty());

  error.clear();
  EXPECT_FALSE(auth::parse_broker_policy(
    "[security]\nallow_root_login = false\nallow_root_login = true\n", error
  ).has_value());
  EXPECT_FALSE(error.empty());
}

TEST(PamBrokerPolicy, IgnoresSameKeyOutsideSecuritySection) {
  std::string error;
  const auto policy = auth::parse_broker_policy(
    "[display]\nallow_root_login = true\n[security]\nallow_root_login = false\n",
    error
  );
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_FALSE(policy->allow_root_login);
}
