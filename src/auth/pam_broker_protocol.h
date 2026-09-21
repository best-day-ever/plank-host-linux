/**
 * @file src/auth/pam_broker_protocol.h
 * @brief Versioned local IPC framing for the PLANK PAM broker.
 */
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

namespace plank::auth {
  constexpr std::uint32_t wire_magic = 0x504c4150U;  ///< ASCII `PLAP` in host notation.
  constexpr std::uint16_t wire_version = 1;  ///< Initial PAM broker protocol version.
  constexpr std::size_t maximum_payload_size = 64U * 1024U;  ///< Per-message allocation limit.
  constexpr std::size_t maximum_field_size = 4096U;  ///< Per-string allocation limit.
  constexpr std::size_t maximum_fields = 64U;  ///< Per-message list-entry limit.
  constexpr std::size_t maximum_gssapi_token_size = 32U * 1024U;  ///< Kerberos AP-REQ (with PAC) byte limit.
  constexpr std::size_t maximum_username_size = 256U;  ///< Account-name byte limit in begin requests.
  constexpr std::size_t maximum_remote_host_size = 256U;  ///< Remote-host label byte limit in begin requests.
  constexpr std::size_t maximum_tty_size = 128U;  ///< Logical TTY byte limit in begin requests.

  /**
   * @brief Messages exchanged between Sunshine and the privileged broker.
   */
  enum class message_type_e: std::uint16_t {
    begin = 1,  ///< Begin an authentication transaction.
    challenge = 2,  ///< Deliver PAM prompts and informational messages.
    response = 3,  ///< Return responses corresponding to one challenge.
    result = 4,  ///< Report authentication success or a PAM error.
    cancel = 5,  ///< Close an authenticated PAM session.
    begin_gssapi = 6,  ///< Admit a Kerberos GSSAPI initiator, then run account and session phases.
  };

  /**
   * @brief Authentication phase associated with a result message.
   */
  enum class phase_e: std::uint16_t {
    protocol = 1,  ///< Local IPC or request validation.
    start = 2,  ///< `pam_start()`.
    authenticate = 3,  ///< `pam_authenticate()`.
    account = 4,  ///< `pam_acct_mgmt()`.
    establish_credentials = 5,  ///< `pam_setcred(PAM_ESTABLISH_CRED)`.
    open_session = 6,  ///< `pam_open_session()`.
    authenticated = 7,  ///< All required PAM operations completed.
  };

#pragma pack(push, 1)
  /**
   * @brief Fixed header preceding each local broker payload.
   */
  struct wire_header_t {
    std::uint32_t magic;  ///< Protocol magic in little-endian order.
    std::uint16_t version;  ///< Protocol version in little-endian order.
    std::uint16_t type;  ///< A @ref message_type_e value in little-endian order.
    std::uint64_t transaction_id;  ///< Nonzero caller-generated transaction identifier.
    std::uint32_t payload_length;  ///< Following payload size in little-endian order.
  };
#pragma pack(pop)

  static_assert(sizeof(wire_header_t) == 20);

  /**
   * @brief Decoded broker message.
   */
  struct message_t {
    message_type_e type;  ///< Message operation.
    std::uint64_t transaction_id;  ///< Transaction correlation identifier.
    std::vector<std::uint8_t> payload;  ///< Operation-specific bytes.
  };

  /**
   * @brief PAM conversation message sent to the unprivileged caller.
   */
  struct prompt_t {
    std::int32_t style;  ///< PAM message style.
    std::string text;  ///< PAM-provided prompt or information.
  };

  /**
   * @brief Convert a host integer to the broker's little-endian representation.
   *
   * @tparam T Unsigned integral type.
   * @param value Host-order value.
   * @return Little-endian value.
   */
  template<typename T>
  constexpr T to_little(T value) {
    static_assert(std::is_unsigned_v<T>);
    if constexpr (std::endian::native == std::endian::little) {
      return value;
    } else {
      return std::byteswap(value);
    }
  }

  /**
   * @brief Convert a broker little-endian integer to host order.
   *
   * @tparam T Unsigned integral type.
   * @param value Little-endian value.
   * @return Host-order value.
   */
  template<typename T>
  constexpr T from_little(T value) {
    return to_little(value);
  }

  /**
   * @brief Append an integral value to a payload in little-endian order.
   *
   * @tparam T Integral type.
   * @param output Destination payload.
   * @param value Host-order value.
   */
  template<typename T>
  void append_integer(std::vector<std::uint8_t> &output, T value) {
    using unsigned_t = std::make_unsigned_t<T>;
    const auto wire_value = to_little(static_cast<unsigned_t>(value));
    const auto *bytes = reinterpret_cast<const std::uint8_t *>(&wire_value);
    output.insert(output.end(), bytes, bytes + sizeof(wire_value));
  }

  /**
   * @brief Read an integral value from a payload.
   *
   * @tparam T Integral type.
   * @param input Source payload.
   * @param offset Updated byte offset.
   * @param value Receives the host-order value.
   * @return True when a complete value was available.
   */
  template<typename T>
  bool read_integer(std::span<const std::uint8_t> input, std::size_t &offset, T &value) {
    using unsigned_t = std::make_unsigned_t<T>;
    if (offset > input.size() || input.size() - offset < sizeof(unsigned_t)) {
      return false;
    }
    unsigned_t wire_value;
    std::memcpy(&wire_value, input.data() + offset, sizeof(wire_value));
    value = static_cast<T>(from_little(wire_value));
    offset += sizeof(wire_value);
    return true;
  }

  /**
   * @brief Append one length-prefixed string to a payload.
   *
   * @param output Destination payload.
   * @param value String bytes; embedded NUL bytes are rejected by consumers.
   * @return True when the field was within protocol limits.
   */
  inline bool append_string(std::vector<std::uint8_t> &output, std::string_view value) {
    if (value.size() > maximum_field_size ||
        output.size() > maximum_payload_size - sizeof(std::uint32_t) - value.size()) {
      return false;
    }
    append_integer(output, static_cast<std::uint32_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
    return true;
  }

  /**
   * @brief Read one bounded length-prefixed string.
   *
   * @param input Source payload.
   * @param offset Updated byte offset.
   * @param value Receives the decoded string.
   * @return True when the field was valid and contained no NUL byte.
   */
  inline bool read_string(std::span<const std::uint8_t> input, std::size_t &offset, std::string &value) {
    std::uint32_t length;
    if (!read_integer(input, offset, length) || length > maximum_field_size ||
        offset > input.size() || input.size() - offset < length) {
      return false;
    }
    const auto *begin = reinterpret_cast<const char *>(input.data() + offset);
    if (std::find(begin, begin + length, '\0') != begin + length) {
      return false;
    }
    value.assign(begin, length);
    offset += length;
    return true;
  }

  /**
   * @brief Append one length-prefixed opaque byte field to a payload.
   *
   * Unlike @ref append_string, the field may contain NUL bytes.
   *
   * @param output Destination payload.
   * @param value Field bytes.
   * @param maximum_size Field-specific size limit.
   * @return True when the field was within protocol limits.
   */
  inline bool append_bytes(std::vector<std::uint8_t> &output, std::span<const std::uint8_t> value,
                           std::size_t maximum_size) {
    if (value.size() > maximum_size ||
        output.size() > maximum_payload_size - sizeof(std::uint32_t) ||
        value.size() > maximum_payload_size - sizeof(std::uint32_t) - output.size()) {
      return false;
    }
    append_integer(output, static_cast<std::uint32_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
    return true;
  }

  /**
   * @brief Read one bounded length-prefixed opaque byte field.
   *
   * @param input Source payload.
   * @param offset Updated byte offset.
   * @param value Receives the field bytes.
   * @param maximum_size Field-specific size limit.
   * @return True when the field was complete and within the limit.
   */
  inline bool read_bytes(std::span<const std::uint8_t> input, std::size_t &offset,
                         std::vector<std::uint8_t> &value, std::size_t maximum_size) {
    std::uint32_t length;
    if (!read_integer(input, offset, length) || length > maximum_size ||
        offset > input.size() || input.size() - offset < length) {
      return false;
    }
    value.assign(input.begin() + static_cast<std::ptrdiff_t>(offset),
                 input.begin() + static_cast<std::ptrdiff_t>(offset + length));
    offset += length;
    return true;
  }

  /**
   * @brief Fields shared by the password and GSSAPI begin requests.
   */
  struct begin_request_t {
    std::string username;  ///< Requested operating-system account.
    std::string remote_host;  ///< Auditable source host label.
    std::string tty;  ///< Logical service terminal.
    std::vector<std::uint8_t> gssapi_token;  ///< Initiator context token; empty for `begin`.
  };

  /**
   * @brief Encode a `begin` (no token) or `begin_gssapi` (token) payload.
   *
   * The `begin_gssapi` payload is the `begin` payload followed by one
   * length-prefixed opaque field holding the initiator's context token.
   *
   * @param request Request fields.
   * @param gssapi Whether to append the GSSAPI token field.
   * @param payload Receives the payload.
   * @return True when every field is within protocol limits.
   */
  inline bool encode_begin(const begin_request_t &request, bool gssapi,
                           std::vector<std::uint8_t> &payload) {
    payload.clear();
    if (request.username.empty() || request.username.size() > maximum_username_size ||
        request.remote_host.size() > maximum_remote_host_size ||
        request.tty.size() > maximum_tty_size ||
        (gssapi && request.gssapi_token.empty()) ||
        (!gssapi && !request.gssapi_token.empty())) {
      return false;
    }
    return append_string(payload, request.username) &&
           append_string(payload, request.remote_host) &&
           append_string(payload, request.tty) &&
           (!gssapi || append_bytes(payload, request.gssapi_token, maximum_gssapi_token_size));
  }

  /**
   * @brief Decode a `begin` or `begin_gssapi` payload exactly.
   *
   * @param payload Encoded payload.
   * @param gssapi Whether a nonempty token field must follow the strings.
   * @param request Receives the decoded fields.
   * @return True when the payload was exact and every field was valid.
   */
  inline bool decode_begin(std::span<const std::uint8_t> payload, bool gssapi,
                           begin_request_t &request) {
    std::size_t offset = 0;
    request = {};
    return read_string(payload, offset, request.username) && !request.username.empty() &&
           request.username.size() <= maximum_username_size &&
           read_string(payload, offset, request.remote_host) &&
           request.remote_host.size() <= maximum_remote_host_size &&
           read_string(payload, offset, request.tty) && request.tty.size() <= maximum_tty_size &&
           (!gssapi || (read_bytes(payload, offset, request.gssapi_token,
                                   maximum_gssapi_token_size) &&
                        !request.gssapi_token.empty())) &&
           offset == payload.size();
  }

  /**
   * @brief Serialize one complete broker message.
   *
   * @param message Decoded message.
   * @return Wire frame, or an empty vector when validation fails.
   */
  inline std::vector<std::uint8_t> encode_message(const message_t &message) {
    if (message.transaction_id == 0 || message.payload.size() > maximum_payload_size) {
      return {};
    }
    wire_header_t header {
      to_little(wire_magic),
      to_little(wire_version),
      to_little(static_cast<std::uint16_t>(message.type)),
      to_little(message.transaction_id),
      to_little(static_cast<std::uint32_t>(message.payload.size())),
    };
    std::vector<std::uint8_t> frame(sizeof(header) + message.payload.size());
    std::memcpy(frame.data(), &header, sizeof(header));
    if (!message.payload.empty()) {
      std::memcpy(frame.data() + sizeof(header), message.payload.data(), message.payload.size());
    }
    return frame;
  }

  /**
   * @brief Parse and validate one complete broker frame.
   *
   * @param frame Header and payload bytes.
   * @param message Receives the decoded message.
   * @return True when framing and limits were valid.
   */
  inline bool decode_message(std::span<const std::uint8_t> frame, message_t &message) {
    if (frame.size() < sizeof(wire_header_t)) {
      return false;
    }
    wire_header_t header;
    std::memcpy(&header, frame.data(), sizeof(header));
    const auto payload_length = from_little(header.payload_length);
    const auto type = from_little(header.type);
    if (from_little(header.magic) != wire_magic || from_little(header.version) != wire_version ||
        from_little(header.transaction_id) == 0 || payload_length > maximum_payload_size ||
        frame.size() != sizeof(header) + payload_length ||
        type < static_cast<std::uint16_t>(message_type_e::begin) ||
        type > static_cast<std::uint16_t>(message_type_e::begin_gssapi)) {
      return false;
    }
    message.type = static_cast<message_type_e>(type);
    message.transaction_id = from_little(header.transaction_id);
    message.payload.assign(frame.begin() + sizeof(header), frame.end());
    return true;
  }

  /**
   * @brief Write every byte, retrying interrupted system calls.
   *
   * @param descriptor Connected stream socket.
   * @param bytes Bytes to write.
   * @return True when all bytes were written.
   */
  inline bool write_all(int descriptor, std::span<const std::uint8_t> bytes) {
    while (!bytes.empty()) {
      const auto written = send(descriptor, bytes.data(), bytes.size(), MSG_NOSIGNAL);
      if (written < 0 && errno == EINTR) {
        continue;
      }
      if (written <= 0) {
        return false;
      }
      bytes = bytes.subspan(static_cast<std::size_t>(written));
    }
    return true;
  }

  /**
   * @brief Read an exact byte count, retrying interrupted system calls.
   *
   * @param descriptor Connected stream socket.
   * @param bytes Destination bytes.
   * @return True when all bytes were read.
   */
  inline bool read_all(int descriptor, std::span<std::uint8_t> bytes) {
    while (!bytes.empty()) {
      const auto count = read(descriptor, bytes.data(), bytes.size());
      if (count < 0 && errno == EINTR) {
        continue;
      }
      if (count <= 0) {
        return false;
      }
      bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
    return true;
  }

  /**
   * @brief Write one framed message to a stream socket.
   *
   * @param descriptor Connected stream socket.
   * @param message Message to send.
   * @return True when the complete frame was written.
   */
  inline bool write_message(int descriptor, const message_t &message) {
    const auto frame = encode_message(message);
    return !frame.empty() && write_all(descriptor, frame);
  }

  /**
   * @brief Write a framed message and erase its temporary wire copy.
   *
   * @param descriptor Connected stream socket.
   * @param message Message containing sensitive payload bytes.
   * @return True when the complete frame was written.
   */
  inline bool write_sensitive_message(int descriptor, const message_t &message) {
    auto frame = encode_message(message);
    const bool written = !frame.empty() && write_all(descriptor, frame);
    if (!frame.empty()) {
      explicit_bzero(frame.data(), frame.size());
    }
    return written;
  }

  /**
   * @brief Read one bounded framed message from a stream socket.
   *
   * @param descriptor Connected stream socket.
   * @param message Receives the decoded message.
   * @return True when a complete valid frame was read.
   */
  inline bool read_message(int descriptor, message_t &message) {
    std::array<std::uint8_t, sizeof(wire_header_t)> header_bytes;
    if (!read_all(descriptor, header_bytes)) {
      return false;
    }
    wire_header_t header;
    std::memcpy(&header, header_bytes.data(), sizeof(header));
    const auto payload_length = from_little(header.payload_length);
    if (payload_length > maximum_payload_size) {
      return false;
    }
    std::vector<std::uint8_t> frame(sizeof(header) + payload_length);
    std::copy(header_bytes.begin(), header_bytes.end(), frame.begin());
    if (payload_length != 0 &&
        !read_all(descriptor, std::span {frame}.subspan(sizeof(header)))) {
      return false;
    }
    return decode_message(frame, message);
  }
}  // namespace plank::auth
