#include <array>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/auth/pam_broker_protocol.h"
#include "src/auth/pam_client.h"

namespace auth = plank::auth;

TEST(PamBrokerProtocol, RoundTripsBoundedMessage) {
  std::vector<std::uint8_t> payload;
  ASSERT_TRUE(auth::append_string(payload, "test-user"));
  ASSERT_TRUE(auth::append_string(payload, "198.51.100.250"));
  ASSERT_TRUE(auth::append_string(payload, "plank"));
  const auth::message_t original {
    auth::message_type_e::begin,
    42,
    payload,
  };

  const auto frame = auth::encode_message(original);
  ASSERT_FALSE(frame.empty());
  auth::message_t decoded;
  ASSERT_TRUE(auth::decode_message(frame, decoded));
  EXPECT_EQ(decoded.type, original.type);
  EXPECT_EQ(decoded.transaction_id, original.transaction_id);

  std::size_t offset = 0;
  std::string username;
  std::string remote_host;
  std::string tty;
  EXPECT_TRUE(auth::read_string(decoded.payload, offset, username));
  EXPECT_TRUE(auth::read_string(decoded.payload, offset, remote_host));
  EXPECT_TRUE(auth::read_string(decoded.payload, offset, tty));
  EXPECT_EQ(offset, decoded.payload.size());
  EXPECT_EQ(username, "test-user");
  EXPECT_EQ(remote_host, "198.51.100.250");
  EXPECT_EQ(tty, "plank");
}

TEST(PamBrokerProtocol, RejectsMalformedAndOversizeFrames) {
  auth::message_t message {
    auth::message_type_e::cancel,
    7,
    {},
  };
  auto frame = auth::encode_message(message);
  ASSERT_EQ(frame.size(), sizeof(auth::wire_header_t));

  auth::message_t decoded;
  EXPECT_FALSE(auth::decode_message(std::span {frame}.first(frame.size() - 1), decoded));

  auto *header = reinterpret_cast<auth::wire_header_t *>(frame.data());
  header->magic = 0;
  EXPECT_FALSE(auth::decode_message(frame, decoded));

  message.transaction_id = 0;
  EXPECT_TRUE(auth::encode_message(message).empty());
  message.transaction_id = 7;
  message.payload.resize(auth::maximum_payload_size + 1);
  EXPECT_TRUE(auth::encode_message(message).empty());

  std::vector<std::uint8_t> fields;
  EXPECT_FALSE(auth::append_string(fields, std::string(auth::maximum_field_size + 1, 'x')));
}

TEST(PamBrokerProtocol, RoundTripsEmptyAndMaximumPayloads) {
  for (const auto size : {std::size_t {0}, std::size_t {1}, auth::maximum_payload_size}) {
    const auth::message_t original {
      auth::message_type_e::result,
      42,
      std::vector<std::uint8_t>(size, 0xa5),
    };
    const auto frame = auth::encode_message(original);
    ASSERT_EQ(frame.size(), sizeof(auth::wire_header_t) + size);
    auth::message_t decoded;
    ASSERT_TRUE(auth::decode_message(frame, decoded));
    EXPECT_EQ(decoded.payload, original.payload);
    EXPECT_EQ(decoded.type, original.type);
    EXPECT_EQ(decoded.transaction_id, original.transaction_id);
  }
}

TEST(PamBrokerProtocol, ReadsAndWritesStreamFrames) {
  std::array<int, 2> sockets {};
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets.data()), 0);
  const auth::message_t original {
    auth::message_type_e::result,
    91,
    {1, 2, 3, 4},
  };
  ASSERT_TRUE(auth::write_message(sockets[0], original));

  auth::message_t decoded;
  ASSERT_TRUE(auth::read_message(sockets[1], decoded));
  EXPECT_EQ(decoded.type, original.type);
  EXPECT_EQ(decoded.transaction_id, original.transaction_id);
  EXPECT_EQ(decoded.payload, original.payload);
  close(sockets[0]);
  close(sockets[1]);
}

TEST(PamBrokerProtocol, ClosedPeerDoesNotRaiseSigpipe) {
  int sockets[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets), 0);
  close(sockets[1]);

  EXPECT_FALSE(auth::write_message(sockets[0], {
    auth::message_type_e::cancel,
    42,
    {},
  }));
  close(sockets[0]);
}

TEST(PamBrokerProtocol, RejectsEmbeddedNulString) {
  std::vector<std::uint8_t> payload;
  ASSERT_TRUE(auth::append_string(payload, std::string_view {"a\0b", 3}));
  std::size_t offset = 0;
  std::string decoded;
  EXPECT_FALSE(auth::read_string(payload, offset, decoded));
}

TEST(PamBrokerClient, AdvancesChallengeAndSuccess) {
  std::array<int, 2> sockets {};
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets.data()), 0);
  constexpr std::uint64_t transaction_id = 1234;
  auto client = auth::pam_client_t::adopt_for_test(sockets[0], transaction_id);

  std::vector<std::uint8_t> challenge;
  auth::append_integer(challenge, static_cast<std::uint32_t>(1));
  auth::append_integer(challenge, static_cast<std::int32_t>(1));
  ASSERT_TRUE(auth::append_string(challenge, "Password: "));
  ASSERT_TRUE(auth::write_message(sockets[1], {
    auth::message_type_e::challenge,
    transaction_id,
    std::move(challenge),
  }));

  const auto prompt = client.read_step_for_test();
  ASSERT_EQ(prompt.state, auth::step_t::state_e::challenge);
  ASSERT_EQ(prompt.prompts.size(), 1);
  EXPECT_EQ(prompt.prompts.front().style, 1);
  EXPECT_EQ(prompt.prompts.front().text, "Password: ");

  std::thread responder {[&]() {
    auth::message_t response;
    ASSERT_TRUE(auth::read_message(sockets[1], response));
    EXPECT_EQ(response.type, auth::message_type_e::response);
    EXPECT_EQ(response.transaction_id, transaction_id);
    std::size_t offset = 0;
    std::uint32_t count = 0;
    std::string secret;
    EXPECT_TRUE(auth::read_integer(response.payload, offset, count));
    EXPECT_EQ(count, 1);
    EXPECT_TRUE(auth::read_string(response.payload, offset, secret));
    EXPECT_EQ(secret, "secret");

    std::vector<std::uint8_t> result;
    auth::append_integer(result, static_cast<std::uint16_t>(auth::phase_e::authenticated));
    auth::append_integer(result, static_cast<std::int32_t>(0));
    ASSERT_TRUE(auth::write_message(sockets[1], {
      auth::message_type_e::result,
      transaction_id,
      std::move(result),
    }));
  }};
  const auto success = client.respond({"secret"});
  responder.join();
  EXPECT_EQ(success.state, auth::step_t::state_e::authenticated);
  EXPECT_TRUE(client.connected());
  client.close();
  close(sockets[1]);
}

TEST(PamBrokerProtocol, RoundTripsGssapiBegin) {
  auth::begin_request_t request {"test-user", "198.51.100.250", "plank", {0x60, 0x00, 0x82, 0x01}};
  std::vector<std::uint8_t> payload;
  ASSERT_TRUE(auth::encode_begin(request, true, payload));
  const auto frame = auth::encode_message({auth::message_type_e::begin_gssapi, 9, payload});
  ASSERT_FALSE(frame.empty());
  auth::message_t message;
  ASSERT_TRUE(auth::decode_message(frame, message));
  EXPECT_EQ(message.type, auth::message_type_e::begin_gssapi);

  auth::begin_request_t decoded;
  ASSERT_TRUE(auth::decode_begin(message.payload, true, decoded));
  EXPECT_EQ(decoded.username, "test-user");
  EXPECT_EQ(decoded.remote_host, "198.51.100.250");
  EXPECT_EQ(decoded.tty, "plank");
  EXPECT_EQ(decoded.gssapi_token, request.gssapi_token);

  // A GSSAPI payload is not a valid password begin payload and vice versa.
  EXPECT_FALSE(auth::decode_begin(message.payload, false, decoded));
  std::vector<std::uint8_t> password_payload;
  ASSERT_TRUE(auth::encode_begin({"test-user", "client", "plank", {}}, false, password_payload));
  EXPECT_FALSE(auth::decode_begin(password_payload, true, decoded));
  ASSERT_TRUE(auth::decode_begin(password_payload, false, decoded));
  EXPECT_TRUE(decoded.gssapi_token.empty());
}

TEST(PamBrokerProtocol, BoundsGssapiBeginFields) {
  std::vector<std::uint8_t> payload;
  EXPECT_FALSE(auth::encode_begin({"test-user", "client", "plank", {}}, true, payload));
  EXPECT_FALSE(auth::encode_begin({"test-user", "client", "plank", {1}}, false, payload));
  EXPECT_FALSE(auth::encode_begin({"", "client", "plank", {1}}, true, payload));
  EXPECT_FALSE(auth::encode_begin({std::string(257, 'u'), "client", "plank", {1}}, true, payload));
  EXPECT_FALSE(auth::encode_begin({"u", std::string(257, 'h'), "plank", {1}}, true, payload));
  EXPECT_FALSE(auth::encode_begin({"u", "client", std::string(129, 't'), {1}}, true, payload));

  auth::begin_request_t largest {"u", "client", "plank",
                                 std::vector<std::uint8_t>(auth::maximum_gssapi_token_size, 0)};
  ASSERT_TRUE(auth::encode_begin(largest, true, payload));
  auth::begin_request_t decoded;
  EXPECT_TRUE(auth::decode_begin(payload, true, decoded));
  EXPECT_EQ(decoded.gssapi_token.size(), auth::maximum_gssapi_token_size);

  largest.gssapi_token.push_back(0);
  EXPECT_FALSE(auth::encode_begin(largest, true, payload));

  // Hand-built oversize and truncated token fields are rejected on decode.
  std::vector<std::uint8_t> forged;
  ASSERT_TRUE(auth::append_string(forged, "u"));
  ASSERT_TRUE(auth::append_string(forged, "client"));
  ASSERT_TRUE(auth::append_string(forged, "plank"));
  auth::append_integer(forged, static_cast<std::uint32_t>(auth::maximum_gssapi_token_size + 1));
  forged.resize(forged.size() + auth::maximum_gssapi_token_size + 1);
  EXPECT_FALSE(auth::decode_begin(forged, true, decoded));

  std::vector<std::uint8_t> truncated;
  ASSERT_TRUE(auth::append_string(truncated, "u"));
  ASSERT_TRUE(auth::append_string(truncated, "client"));
  ASSERT_TRUE(auth::append_string(truncated, "plank"));
  auth::append_integer(truncated, static_cast<std::uint32_t>(8));
  truncated.push_back(1);
  EXPECT_FALSE(auth::decode_begin(truncated, true, decoded));

  // Trailing bytes after the token are rejected.
  ASSERT_TRUE(auth::encode_begin({"u", "client", "plank", {1, 2}}, true, payload));
  payload.push_back(0);
  EXPECT_FALSE(auth::decode_begin(payload, true, decoded));
}

TEST(PamBrokerProtocol, AllowsNulBytesOnlyInOpaqueFields) {
  std::vector<std::uint8_t> payload;
  const std::vector<std::uint8_t> bytes {0, 1, 0, 2};
  ASSERT_TRUE(auth::append_bytes(payload, bytes, 4));
  std::size_t offset = 0;
  std::vector<std::uint8_t> decoded;
  ASSERT_TRUE(auth::read_bytes(payload, offset, decoded, 4));
  EXPECT_EQ(decoded, bytes);
  offset = 0;
  EXPECT_FALSE(auth::read_bytes(payload, offset, decoded, 3));
  EXPECT_FALSE(auth::append_bytes(payload, bytes, 3));
}

TEST(PamBrokerProtocol, RejectsUnknownMessageTypes) {
  auto frame = auth::encode_message({auth::message_type_e::cancel, 7, {}});
  auto *header = reinterpret_cast<auth::wire_header_t *>(frame.data());
  auth::message_t decoded;
  header->type = auth::to_little(static_cast<std::uint16_t>(7));
  EXPECT_FALSE(auth::decode_message(frame, decoded));
  header->type = 0;
  EXPECT_FALSE(auth::decode_message(frame, decoded));
  header->type = auth::to_little(static_cast<std::uint16_t>(auth::message_type_e::begin_gssapi));
  EXPECT_TRUE(auth::decode_message(frame, decoded));
}

TEST(PamBrokerClient, GssapiAdmissionIsSingleRoundTrip) {
  constexpr std::uint64_t transaction_id = 77;
  const std::vector<std::uint8_t> token {0x60, 0x82, 0x00, 0x10};
  for (const bool admitted : {true, false}) {
    std::array<int, 2> sockets {};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets.data()), 0);
    auto client = auth::pam_client_t::adopt_for_test(sockets[0], transaction_id);
    std::thread broker {[&]() {
      auth::message_t begin;
      ASSERT_TRUE(auth::read_message(sockets[1], begin));
      EXPECT_EQ(begin.type, auth::message_type_e::begin_gssapi);
      auth::begin_request_t request;
      ASSERT_TRUE(auth::decode_begin(begin.payload, true, request));
      EXPECT_EQ(request.username, "test-user");
      EXPECT_EQ(request.gssapi_token, token);
      std::vector<std::uint8_t> result;
      auth::append_integer(result, static_cast<std::uint16_t>(
        admitted ? auth::phase_e::authenticated : auth::phase_e::authenticate
      ));
      auth::append_integer(result, static_cast<std::int32_t>(admitted ? 0 : 7));
      ASSERT_TRUE(auth::write_message(sockets[1], {
        auth::message_type_e::result, transaction_id, std::move(result),
      }));
    }};
    const auto step = client.submit_gssapi_for_test("test-user", "client", "plank", token);
    broker.join();
    EXPECT_EQ(step.state, admitted ? auth::step_t::state_e::authenticated :
                                     auth::step_t::state_e::denied);
    EXPECT_EQ(client.connected(), admitted);
    client.close();
    close(sockets[1]);
  }
}

TEST(PamBrokerClient, GssapiChallengeIsAProtocolDenial) {
  std::array<int, 2> sockets {};
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets.data()), 0);
  constexpr std::uint64_t transaction_id = 78;
  auto client = auth::pam_client_t::adopt_for_test(sockets[0], transaction_id);
  std::thread broker {[&]() {
    auth::message_t begin;
    ASSERT_TRUE(auth::read_message(sockets[1], begin));
    std::vector<std::uint8_t> challenge;
    auth::append_integer(challenge, static_cast<std::uint32_t>(1));
    auth::append_integer(challenge, static_cast<std::int32_t>(1));
    ASSERT_TRUE(auth::append_string(challenge, "Password: "));
    ASSERT_TRUE(auth::write_message(sockets[1], {
      auth::message_type_e::challenge, transaction_id, std::move(challenge),
    }));
  }};
  const std::vector<std::uint8_t> token {1, 2, 3};
  const auto step = client.submit_gssapi_for_test("test-user", "client", "plank", token);
  broker.join();
  EXPECT_EQ(step.state, auth::step_t::state_e::denied);
  EXPECT_EQ(step.phase, auth::phase_e::protocol);
  EXPECT_FALSE(client.connected());
  close(sockets[1]);
}
