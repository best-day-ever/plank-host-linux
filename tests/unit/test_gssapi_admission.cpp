/**
 * @file tests/unit/test_gssapi_admission.cpp
 * @brief Kerberos GSSAPI admission policy, channel bindings and token codec tests.
 */
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "src/auth/gssapi_admission.h"

namespace gssapi = plank::auth::gssapi;

namespace {
  constexpr std::string_view realm = "EXAMPLE.TEST";

  gssapi::accepted_context_t admitted_context() {
    gssapi::accepted_context_t context;
    context.initiator = "alice@EXAMPLE.TEST";
    context.acceptor = "plank/workstation.example.test@EXAMPLE.TEST";
    context.localname = "alice";
    context.indicators = {"otp"};
    context.kerberos_mechanism = true;
    context.channel_bound = true;
    return context;
  }

  gssapi::admission_e evaluate(const gssapi::accepted_context_t &context,
                               std::string_view username = "alice",
                               const std::vector<std::string> &indicators = {"otp"}) {
    return gssapi::evaluate(context, realm, username, indicators);
  }
}  // namespace

TEST(GssapiAdmission, AdmitsSameRealmOtpInitiatorForItsOwnAccount) {
  EXPECT_EQ(evaluate(admitted_context()), gssapi::admission_e::admitted);
  auto context = admitted_context();
  context.indicators = {"hardened", "otp"};
  EXPECT_EQ(evaluate(context), gssapi::admission_e::admitted);
}

TEST(GssapiAdmission, RequiresKerberosMechanismAndVerifiedChannelBindings) {
  auto context = admitted_context();
  context.kerberos_mechanism = false;
  EXPECT_EQ(evaluate(context), gssapi::admission_e::wrong_mechanism);

  context = admitted_context();
  context.channel_bound = false;
  EXPECT_EQ(evaluate(context), gssapi::admission_e::not_channel_bound);

  context = admitted_context();
  context.anonymous = true;
  EXPECT_EQ(evaluate(context), gssapi::admission_e::anonymous);
}

TEST(GssapiAdmission, RequiresPlankAcceptorInDefaultRealm) {
  auto context = admitted_context();
  context.acceptor = "host/workstation.example.test@EXAMPLE.TEST";
  EXPECT_EQ(evaluate(context), gssapi::admission_e::wrong_service);
  context.acceptor = "plank@EXAMPLE.TEST";
  EXPECT_EQ(evaluate(context), gssapi::admission_e::wrong_service);
  context.acceptor = "plank/workstation.example.test@OTHER.TEST";
  EXPECT_EQ(evaluate(context), gssapi::admission_e::wrong_service);
  context.acceptor.clear();
  EXPECT_EQ(evaluate(context), gssapi::admission_e::wrong_service);
}

TEST(GssapiAdmission, DeniesForeignRealmAndMultiComponentInitiators) {
  auto context = admitted_context();
  context.initiator = "alice@OTHER.TEST";
  EXPECT_EQ(evaluate(context), gssapi::admission_e::foreign_realm);

  context = admitted_context();
  context.initiator = "alice/admin@EXAMPLE.TEST";
  EXPECT_EQ(evaluate(context), gssapi::admission_e::malformed_principal);
  context.initiator = "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS";
  EXPECT_EQ(evaluate(context), gssapi::admission_e::malformed_principal);
  context.initiator = "ali\\@ce@EXAMPLE.TEST";
  EXPECT_EQ(evaluate(context), gssapi::admission_e::malformed_principal);
  context.initiator = "alice";
  EXPECT_EQ(evaluate(context), gssapi::admission_e::malformed_principal);
  context.initiator = "alice@EXAMPLE.TEST@EXAMPLE.TEST";
  EXPECT_EQ(evaluate(context), gssapi::admission_e::malformed_principal);
}

TEST(GssapiAdmission, RequiresLocalNameToMatchRequestedAccount) {
  EXPECT_EQ(evaluate(admitted_context(), "bob"), gssapi::admission_e::localname_mismatch);
  auto context = admitted_context();
  context.localname.clear();
  EXPECT_EQ(evaluate(context), gssapi::admission_e::localname_mismatch);
  context.localname = "Alice";
  EXPECT_EQ(evaluate(context), gssapi::admission_e::localname_mismatch);
}

TEST(GssapiAdmission, RequiresConfiguredIndicator) {
  auto context = admitted_context();
  context.indicators.clear();
  EXPECT_EQ(evaluate(context), gssapi::admission_e::missing_indicator);
  context.indicators = {"otpx", "pkinit"};
  EXPECT_EQ(evaluate(context), gssapi::admission_e::missing_indicator);
  EXPECT_EQ(evaluate(admitted_context(), "alice", {"pkinit"}), gssapi::admission_e::missing_indicator);
}

TEST(GssapiAdmission, AdmitsAnyOfSeveralConfiguredIndicators) {
  const std::vector<std::string> accepted {"otp", "passkey"};
  auto context = admitted_context();
  EXPECT_EQ(evaluate(context, "alice", accepted), gssapi::admission_e::admitted);
  context.indicators = {"passkey"};
  EXPECT_EQ(evaluate(context, "alice", accepted), gssapi::admission_e::admitted);
  context.indicators = {"hardened", "passkey", "otp"};
  EXPECT_EQ(evaluate(context, "alice", accepted), gssapi::admission_e::admitted);
  context.indicators = {"passkey"};
  EXPECT_EQ(evaluate(context), gssapi::admission_e::missing_indicator);
  context.indicators = {"hardened", "pkinit", "passkeyx"};
  EXPECT_EQ(evaluate(context, "alice", accepted), gssapi::admission_e::missing_indicator);
  context.indicators.clear();
  EXPECT_EQ(evaluate(context, "alice", accepted), gssapi::admission_e::missing_indicator);
}

TEST(GssapiAdmission, EmptyConfigurationFailsClosed) {
  const std::vector<std::string> otp {"otp"};
  EXPECT_EQ(gssapi::evaluate(admitted_context(), "", "alice", otp),
            gssapi::admission_e::configuration_error);
  EXPECT_EQ(gssapi::evaluate(admitted_context(), realm, "", otp),
            gssapi::admission_e::configuration_error);
  EXPECT_EQ(gssapi::evaluate(admitted_context(), realm, "alice", std::vector<std::string> {}),
            gssapi::admission_e::configuration_error);
  EXPECT_EQ(gssapi::evaluate(admitted_context(), realm, "alice", std::vector<std::string> {""}),
            gssapi::admission_e::configuration_error);
  EXPECT_EQ(gssapi::evaluate(admitted_context(), realm, "alice", std::vector<std::string> {"otp", ""}),
            gssapi::admission_e::configuration_error);
}

TEST(GssapiAdmission, ParsesPrincipals) {
  const auto principal = gssapi::parse_principal("plank/host.example.test@EXAMPLE.TEST");
  ASSERT_TRUE(principal);
  ASSERT_EQ(principal->components.size(), 2);
  EXPECT_EQ(principal->components[0], "plank");
  EXPECT_EQ(principal->components[1], "host.example.test");
  EXPECT_EQ(principal->realm, "EXAMPLE.TEST");
  EXPECT_FALSE(gssapi::parse_principal("@EXAMPLE.TEST"));
  EXPECT_FALSE(gssapi::parse_principal("alice@"));
  EXPECT_FALSE(gssapi::parse_principal("plank//host@EXAMPLE.TEST"));
  EXPECT_FALSE(gssapi::parse_principal(std::string_view {"al\0ice@EXAMPLE.TEST", 19}));
}

TEST(GssapiAdmission, BuildsTlsServerEndPointBindings) {
  std::array<std::uint8_t, 32> digest {};
  for (std::size_t index = 0; index < digest.size(); ++index) {
    digest[index] = static_cast<std::uint8_t>(index);
  }
  const auto data = gssapi::channel_binding_application_data(digest);
  ASSERT_EQ(data.size(), 21 + 32);
  EXPECT_EQ(std::string(data.begin(), data.begin() + 21), "tls-server-end-point:");
  EXPECT_TRUE(std::equal(digest.begin(), digest.end(), data.begin() + 21));
  EXPECT_TRUE(gssapi::channel_binding_application_data(std::span {digest}.first(31)).empty());
}

TEST(GssapiToken, RoundTripsBase64) {
  for (std::size_t size : {1U, 2U, 3U, 4U, 5U, 1000U}) {
    std::vector<std::uint8_t> bytes(size);
    for (std::size_t index = 0; index < size; ++index) {
      bytes[index] = static_cast<std::uint8_t>(index * 37U + 11U);
    }
    const auto encoded = gssapi::encode_token(bytes);
    const auto decoded = gssapi::decode_token(encoded);
    ASSERT_TRUE(decoded) << size;
    EXPECT_EQ(*decoded, bytes);
  }
  EXPECT_EQ(gssapi::encode_token(std::vector<std::uint8_t> {'f', 'o', 'o', 'b'}), "Zm9vYg==");
  ASSERT_TRUE(gssapi::decode_token("YIIB"));
  EXPECT_EQ(gssapi::decode_token("YIIB")->size(), 3);
}

TEST(GssapiToken, RejectsMalformedBase64) {
  EXPECT_FALSE(gssapi::decode_token(""));
  EXPECT_FALSE(gssapi::decode_token("Zm9vYg="));  // length not a multiple of four
  EXPECT_FALSE(gssapi::decode_token("Zm9vYg"));  // missing padding
  EXPECT_FALSE(gssapi::decode_token("Zm9v Yg=="));  // whitespace
  EXPECT_FALSE(gssapi::decode_token("Zm9vYg==\n"));
  EXPECT_FALSE(gssapi::decode_token("Zm9-Yg=="));  // URL-safe alphabet
  EXPECT_FALSE(gssapi::decode_token("Zm=vYg=="));  // interior padding
  EXPECT_FALSE(gssapi::decode_token("Zm9vYh=="));  // non-canonical trailing bits
  EXPECT_FALSE(gssapi::decode_token("Zm9vYmE="  "Zm9v"));  // padding before final group
  EXPECT_FALSE(gssapi::decode_token("===="));
}

TEST(GssapiToken, EnforcesTokenSizeLimit) {
  std::vector<std::uint8_t> largest(plank::auth::maximum_gssapi_token_size, 0x5a);
  EXPECT_TRUE(gssapi::decode_token(gssapi::encode_token(largest)));
  largest.push_back(0x5a);
  EXPECT_FALSE(gssapi::decode_token(gssapi::encode_token(largest)));
  EXPECT_FALSE(gssapi::decode_token(std::string(64U * 1024U, 'A')));
}

TEST(GssapiAdmission, DescribesEveryOutcome) {
  for (int value = static_cast<int>(gssapi::admission_e::admitted);
       value <= static_cast<int>(gssapi::admission_e::missing_indicator); ++value) {
    EXPECT_NE(gssapi::describe(static_cast<gssapi::admission_e>(value)), "unknown");
  }
}
