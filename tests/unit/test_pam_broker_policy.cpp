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

TEST(PamBrokerPolicy, GssapiIsDisabledByDefault) {
  std::string error;
  const auto policy = auth::parse_broker_policy("[security]\ncert = /etc/plank/tls/cert.pem\n", error);
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_FALSE(policy->gssapi_enabled());
  EXPECT_EQ(policy->gssapi_required_indicator, "otp");
  EXPECT_EQ(policy->gssapi_pam_service, "plank-remote");
  EXPECT_EQ(policy->tls_certificate, "/etc/plank/tls/cert.pem");
}

TEST(PamBrokerPolicy, ParsesGssapiSettings) {
  std::string error;
  const auto policy = auth::parse_broker_policy(
    "[security]\n"
    "gssapi_keytab = /etc/plank/plank.keytab\n"
    "gssapi_required_indicator = pkinit\n"
    "GSSAPI_PAM_SERVICE = plank-remote-test\n"
    "cert = /etc/plank/tls/cert.pem\n",
    error
  );
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_TRUE(policy->gssapi_enabled());
  EXPECT_EQ(policy->gssapi_keytab, "/etc/plank/plank.keytab");
  EXPECT_EQ(policy->gssapi_required_indicator, "pkinit");
  EXPECT_EQ(policy->gssapi_pam_service, "plank-remote-test");
}

TEST(PamBrokerPolicy, ReadsCertificateFromAnySectionButGssapiOnlyFromSecurity) {
  std::string error;
  auto policy = auth::parse_broker_policy(
    "[network]\ncert = /srv/tls/cert.pem\ngssapi_keytab = /etc/other.keytab\n"
    "[security]\ngssapi_keytab = /etc/plank/plank.keytab\n",
    error
  );
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_EQ(policy->tls_certificate, "/srv/tls/cert.pem");
  EXPECT_EQ(policy->gssapi_keytab, "/etc/plank/plank.keytab");
  EXPECT_TRUE(policy->gssapi_enabled());

  policy = auth::parse_broker_policy("[general]\ngssapi_keytab = /etc/plank/plank.keytab\n"
                                     "cert = /etc/plank/tls/cert.pem\n",
                                     error);
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_FALSE(policy->gssapi_enabled());
}

TEST(PamBrokerPolicy, RelativeOrDuplicateCertificateDisablesGssapiOnly) {
  std::string error;
  auto policy = auth::parse_broker_policy(
    "[security]\ngssapi_keytab = /etc/plank/plank.keytab\ncert = credentials/cacert.pem\n",
    error
  );
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_FALSE(policy->gssapi_enabled());

  policy = auth::parse_broker_policy(
    "[security]\ngssapi_keytab = /etc/plank/plank.keytab\ncert = /a.pem\n[general]\ncert = /b.pem\n",
    error
  );
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_TRUE(policy->tls_certificate.empty());
  EXPECT_FALSE(policy->gssapi_enabled());

  policy = auth::parse_broker_policy(
    "[security]\ncert = /a.pem\ncert = /a.pem\n", error
  );
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_TRUE(policy->tls_certificate.empty());
}

TEST(PamBrokerPolicy, RejectsInvalidGssapiSettings) {
  for (const char *contents : {
         "[security]\ngssapi_keytab = relative.keytab\n",
         "[security]\ngssapi_keytab = /a\ngssapi_keytab = /b\n",
         "[security]\ngssapi_required_indicator =\n",
         "[security]\ngssapi_required_indicator = otp pkinit\n",
         "[security]\ngssapi_required_indicator = otp\ngssapi_required_indicator = otp\n",
         "[security]\ngssapi_pam_service = ../plank-host\n",
         "[security]\ngssapi_pam_service = plank/remote\n",
         "[security]\ngssapi_pam_service =\n",
         "[security]\ngssapi_pam_service = a\ngssapi_pam_service = b\n",
       }) {
    std::string error;
    EXPECT_FALSE(auth::parse_broker_policy(contents, error).has_value()) << contents;
    EXPECT_FALSE(error.empty()) << contents;
  }
}

TEST(PamBrokerPolicy, EmptyKeytabLeavesGssapiDisabled) {
  std::string error;
  const auto policy = auth::parse_broker_policy(
    "[security]\ngssapi_keytab =\ncert = /etc/plank/tls/cert.pem\n", error
  );
  ASSERT_TRUE(policy.has_value()) << error;
  EXPECT_FALSE(policy->gssapi_enabled());
}
