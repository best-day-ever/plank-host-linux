/**
 * @file src/auth/gssapi_admission.h
 * @brief Library-independent GSSAPI admission policy for the PLANK PAM broker.
 *
 * The root broker accepts a Kerberos GSSAPI context and then applies this
 * policy to the accepted initiator before running the PAM account, credential
 * and session phases. Keeping the decision free of Kerberos library types
 * makes every denial reason unit-testable without a KDC.
 */
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "pam_broker_protocol.h"

namespace plank::auth::gssapi {
  /// RFC 5929 channel-binding type prefix placed before the certificate hash.
  constexpr std::string_view channel_binding_prefix = "tls-server-end-point:";
  /// SHA-256 digest size of the host leaf certificate.
  constexpr std::size_t certificate_digest_size = 32U;
  /// Kerberos service name the acceptor principal must use (`plank/<fqdn>@REALM`).
  constexpr std::string_view acceptor_service = "plank";

  /**
   * @brief Outcome of GSSAPI admission. Only @ref admission_e::admitted admits.
   */
  enum class admission_e {
    admitted,  ///< Every check passed.
    disabled,  ///< GSSAPI admission is not configured on this host.
    configuration_error,  ///< Keytab, certificate or Kerberos configuration unusable.
    context_error,  ///< The token was rejected by the GSSAPI library (replay, bindings, keys, clock).
    incomplete,  ///< The mechanism required another round trip; single-token admission only.
    wrong_mechanism,  ///< The accepted mechanism was not raw Kerberos V5.
    not_channel_bound,  ///< The initiator did not supply matching channel bindings.
    anonymous,  ///< Anonymous initiators are never admitted.
    wrong_service,  ///< The ticket was not issued for a `plank/<host>` acceptor in the default realm.
    malformed_principal,  ///< The initiator principal is not a plain single-component name.
    foreign_realm,  ///< The initiator is not in the host's default realm.
    localname_mismatch,  ///< The principal does not map to the requested local account.
    missing_indicator,  ///< The required Kerberos authentication indicator is absent.
  };

  /**
   * @brief Facts extracted from an accepted security context.
   */
  struct accepted_context_t {
    std::string initiator;  ///< Initiator principal display name, e.g. `user@REALM`.
    std::string acceptor;  ///< Acceptor principal display name, e.g. `plank/host@REALM`.
    std::string localname;  ///< Local account mapped by the Kerberos library; empty when unmapped.
    std::vector<std::string> indicators;  ///< KDC-authenticated auth-indicator values.
    bool kerberos_mechanism {false};  ///< Whether the accepted mechanism is Kerberos V5.
    bool channel_bound {false};  ///< Whether the library verified matching channel bindings.
    bool anonymous {false};  ///< Whether the context is anonymous.
  };

  /**
   * @brief Components of an unescaped Kerberos principal display name.
   */
  struct principal_t {
    std::vector<std::string> components;  ///< Name components separated by `/`.
    std::string realm;  ///< Realm after the final `@`.
  };

  /**
   * @brief Split a principal display name into components and realm.
   *
   * Escaped characters are rejected rather than interpreted, so the policy
   * never has to reason about quoting.
   *
   * @param display Principal display name.
   * @return Parsed principal, or no value when malformed.
   */
  inline std::optional<principal_t> parse_principal(std::string_view display) {
    if (display.empty() || display.size() > 1024 ||
        display.find_first_of(std::string_view {"\\\0", 2}) != std::string_view::npos) {
      return std::nullopt;
    }
    const auto at = display.find('@');
    if (at == std::string_view::npos || at == 0 || at + 1 == display.size() ||
        display.find('@', at + 1) != std::string_view::npos) {
      return std::nullopt;
    }
    principal_t principal;
    principal.realm = std::string {display.substr(at + 1)};
    auto name = display.substr(0, at);
    while (true) {
      const auto slash = name.find('/');
      const auto component = name.substr(0, slash);
      if (component.empty()) {
        return std::nullopt;
      }
      principal.components.emplace_back(component);
      if (slash == std::string_view::npos) {
        break;
      }
      name.remove_prefix(slash + 1);
    }
    return principal;
  }

  /**
   * @brief Apply the admission policy to an accepted security context.
   *
   * Requirements, in order: Kerberos V5 mechanism, verified channel
   * bindings, a non-anonymous initiator, a `plank/<host>` acceptor in the
   * default realm, a single-component initiator in the default realm whose
   * library-mapped local name equals the requested account, and the required
   * authentication indicator.
   *
   * @param context Facts from the accepted context.
   * @param default_realm Host's default Kerberos realm.
   * @param requested_username Account named in the authentication request.
   * @param required_indicator Required auth-indicator value.
   * @return Admission outcome.
   */
  inline admission_e evaluate(const accepted_context_t &context, std::string_view default_realm,
                              std::string_view requested_username,
                              std::string_view required_indicator) {
    if (default_realm.empty() || requested_username.empty() || required_indicator.empty()) {
      return admission_e::configuration_error;
    }
    if (!context.kerberos_mechanism) {
      return admission_e::wrong_mechanism;
    }
    if (!context.channel_bound) {
      return admission_e::not_channel_bound;
    }
    if (context.anonymous) {
      return admission_e::anonymous;
    }
    const auto acceptor = parse_principal(context.acceptor);
    if (!acceptor || acceptor->components.size() != 2 ||
        acceptor->components.front() != acceptor_service || acceptor->realm != default_realm) {
      return admission_e::wrong_service;
    }
    const auto initiator = parse_principal(context.initiator);
    if (!initiator || initiator->components.size() != 1) {
      return admission_e::malformed_principal;
    }
    if (initiator->realm != default_realm) {
      return admission_e::foreign_realm;
    }
    if (context.localname.empty() || context.localname != requested_username) {
      return admission_e::localname_mismatch;
    }
    if (std::find(context.indicators.begin(), context.indicators.end(), required_indicator) ==
        context.indicators.end()) {
      return admission_e::missing_indicator;
    }
    return admission_e::admitted;
  }

  /**
   * @brief Build RFC 5929 `tls-server-end-point` channel-binding application data.
   *
   * @param certificate_digest SHA-256 of the host leaf certificate DER.
   * @return ASCII prefix followed by the raw 32-byte digest, or empty on a size mismatch.
   */
  inline std::vector<std::uint8_t> channel_binding_application_data(
    std::span<const std::uint8_t> certificate_digest
  ) {
    if (certificate_digest.size() != certificate_digest_size) {
      return {};
    }
    std::vector<std::uint8_t> data(channel_binding_prefix.begin(), channel_binding_prefix.end());
    data.insert(data.end(), certificate_digest.begin(), certificate_digest.end());
    return data;
  }

  /**
   * @brief Strictly decode a base64 `gssapi_token` from an authentication request.
   *
   * Accepts only the standard alphabet with required, canonical padding and
   * no whitespace. Tokens that decode to zero bytes or more than
   * @ref plank::auth::maximum_gssapi_token_size bytes are rejected.
   *
   * @param encoded Base64 text.
   * @return Token bytes, or no value when malformed or out of range.
   */
  inline std::optional<std::vector<std::uint8_t>> decode_token(std::string_view encoded) {
    constexpr std::size_t maximum_encoded_size = (maximum_gssapi_token_size + 2) / 3 * 4;
    if (encoded.empty() || encoded.size() % 4 != 0 || encoded.size() > maximum_encoded_size) {
      return std::nullopt;
    }
    const auto value_of = [](char character) -> int {
      if (character >= 'A' && character <= 'Z') return character - 'A';
      if (character >= 'a' && character <= 'z') return character - 'a' + 26;
      if (character >= '0' && character <= '9') return character - '0' + 52;
      if (character == '+') return 62;
      if (character == '/') return 63;
      return -1;
    };
    std::size_t padding = 0;
    if (encoded.back() == '=') {
      padding = encoded[encoded.size() - 2] == '=' ? 2 : 1;
    }
    std::vector<std::uint8_t> output;
    output.reserve(encoded.size() / 4 * 3);
    for (std::size_t offset = 0; offset < encoded.size(); offset += 4) {
      const bool last = offset + 4 == encoded.size();
      std::uint32_t group = 0;
      for (std::size_t index = 0; index < 4; ++index) {
        const char character = encoded[offset + index];
        int value;
        if (character == '=') {
          if (!last || index < 4 - padding) {
            return std::nullopt;
          }
          value = 0;
        } else {
          value = value_of(character);
          if (value < 0 || (last && index >= 4 - padding)) {
            return std::nullopt;
          }
        }
        group = (group << 6U) | static_cast<std::uint32_t>(value);
      }
      // Canonical encoding: bits discarded by padding must be zero.
      if ((last && padding == 1 && (group & 0xffU) != 0) ||
          (last && padding == 2 && (group & 0xffffU) != 0)) {
        return std::nullopt;
      }
      output.push_back(static_cast<std::uint8_t>(group >> 16U));
      if (!last || padding < 2) {
        output.push_back(static_cast<std::uint8_t>(group >> 8U));
      }
      if (!last || padding < 1) {
        output.push_back(static_cast<std::uint8_t>(group));
      }
    }
    if (output.empty() || output.size() > maximum_gssapi_token_size) {
      return std::nullopt;
    }
    return output;
  }

  /**
   * @brief Encode bytes as standard padded base64.
   *
   * @param bytes Input bytes.
   * @return Base64 text.
   */
  inline std::string encode_token(std::span<const std::uint8_t> bytes) {
    constexpr std::string_view alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve((bytes.size() + 2) / 3 * 4);
    for (std::size_t offset = 0; offset < bytes.size(); offset += 3) {
      const std::size_t remaining = bytes.size() - offset;
      std::uint32_t group = static_cast<std::uint32_t>(bytes[offset]) << 16U;
      if (remaining > 1) group |= static_cast<std::uint32_t>(bytes[offset + 1]) << 8U;
      if (remaining > 2) group |= bytes[offset + 2];
      output.push_back(alphabet[(group >> 18U) & 0x3fU]);
      output.push_back(alphabet[(group >> 12U) & 0x3fU]);
      output.push_back(remaining > 1 ? alphabet[(group >> 6U) & 0x3fU] : '=');
      output.push_back(remaining > 2 ? alphabet[group & 0x3fU] : '=');
    }
    return output;
  }

  /**
   * @brief Describe an admission outcome for administrator logs.
   *
   * @param result Admission outcome.
   * @return Stable, credential-free text.
   */
  constexpr std::string_view describe(admission_e result) {
    switch (result) {
      case admission_e::admitted:
        return "admitted";
      case admission_e::disabled:
        return "GSSAPI admission is not configured";
      case admission_e::configuration_error:
        return "GSSAPI acceptor configuration error";
      case admission_e::context_error:
        return "GSSAPI context rejected";
      case admission_e::incomplete:
        return "GSSAPI context needs another round trip";
      case admission_e::wrong_mechanism:
        return "mechanism is not Kerberos V5";
      case admission_e::not_channel_bound:
        return "channel bindings absent or unverified";
      case admission_e::anonymous:
        return "anonymous initiator";
      case admission_e::wrong_service:
        return "ticket is not for a plank service in the default realm";
      case admission_e::malformed_principal:
        return "initiator is not a single-component principal";
      case admission_e::foreign_realm:
        return "initiator is outside the default realm";
      case admission_e::localname_mismatch:
        return "initiator does not map to the requested account";
      case admission_e::missing_indicator:
        return "required authentication indicator absent";
    }
    return "unknown";
  }
}  // namespace plank::auth::gssapi
