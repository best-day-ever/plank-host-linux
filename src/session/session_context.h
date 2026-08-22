/**
 * @file src/session/session_context.h
 * @brief Logind-backed graphical-session selection for StationConnect.
 */
#pragma once

#include <optional>
#include <string>

#include <sys/types.h>

namespace stationconnect::session {
  struct descriptor_t {
    std::string id;
    uid_t uid {};
    std::string seat;
    std::string type;
    std::string session_class;
    std::string state;
    bool active {};
    bool remote {};
  };

  struct environment_t {
    std::string display;
    std::string xauthority;
    std::string runtime_directory;
    std::string dbus_address;
  };

  /** Return true only for a supported, local active seat0 session. */
  bool eligible_graphical_session(const descriptor_t &session);

  /** Query one logind session. */
  std::optional<descriptor_t> describe(std::string_view session_id);

  /** Query and validate the currently active session on seat0. */
  std::optional<descriptor_t> active_seat0_graphical_session();

  /**
   * Find DISPLAY and Xauthority in a process belonging to the selected
   * logind session. Only a small environment whitelist is returned.
   */
  std::optional<environment_t> discover_environment(const descriptor_t &session);

  /** Authorize an account against the supervisor-attested active seat0 session. */
  bool supervisor_attests_account_for_active_seat0(uid_t account_uid);

  /** Build the bounded message sent over the inherited supervisor socket. */
  std::string session_attestation_message(const descriptor_t &session);
}  // namespace stationconnect::session
