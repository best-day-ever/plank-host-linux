/**
 * @file src/auth/gssapi_acceptor.h
 * @brief Kerberos GSSAPI acceptor used only by the root PLANK PAM broker.
 */
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "gssapi_admission.h"
#include "pam_broker_policy.h"

namespace plank::auth::gssapi {
  /**
   * @brief Result of accepting one initiator token.
   */
  struct acceptance_t {
    admission_e result {admission_e::configuration_error};  ///< Admission outcome.
    std::string initiator;  ///< Initiator principal when the context was accepted.
    std::string detail;  ///< Credential-free diagnostic text for administrator logs.
  };

  /**
   * @brief Compute SHA-256 over the DER of the first certificate in a PEM file.
   *
   * @param path PEM certificate path (the leaf the host's TLS listener serves).
   * @param error Receives a reason on failure.
   * @return Digest, or no value on failure.
   */
  std::optional<std::array<std::uint8_t, certificate_digest_size>> certificate_digest(
    const std::string &path, std::string &error
  );

  /**
   * @brief Verify that a keytab is a root-owned regular file with no group/other access.
   *
   * @param path Keytab path.
   * @param error Receives a reason on failure.
   * @return True when the keytab may be used.
   */
  bool keytab_is_private(const std::string &path, std::string &error);

  /**
   * @brief Pin the Kerberos replay cache for this process.
   *
   * Clears environment overrides that could disable the replay cache and, when
   * the distribution's persistent root-owned replay-cache directory exists,
   * selects it so replay protection survives broker restarts. Call once at
   * startup before any worker is forked.
   */
  void configure_replay_cache();

  /**
   * @brief Accept one Kerberos initiator token and apply the admission policy.
   *
   * Credentials come from the configured keytab through a per-call credential
   * store, so no process-global keytab state is modified. Channel bindings are
   * `tls-server-end-point:` followed by SHA-256 of the configured certificate,
   * with unspecified (empty) addresses. The library replay cache is used.
   *
   * @param policy Broker policy holding keytab, certificate and indicator settings.
   * @param token Initiator context token (a Kerberos V5 AP-REQ).
   * @param requested_username Account named in the authentication request.
   * @return Admission outcome and diagnostics. Token bytes are never included.
   */
  acceptance_t accept_initiator(const broker_policy_t &policy,
                                std::span<const std::uint8_t> token,
                                std::string_view requested_username);
}  // namespace plank::auth::gssapi
