/**
 * @file src/session_stream.h
 * @brief Native session launch and active-stream ownership declarations.
 */
#pragma once

// standard includes
#include <cstdint>
#include <memory>
#include <string>

#include <sys/types.h>

namespace session_stream {
  /**
   * @brief Authorized launch state shared with native QUIC stream setup.
   */
  struct launch_session_t {
    uint32_t id;  ///< Launch-session identifier assigned before stream startup.

    bool host_audio;  ///< Whether host audio should be played locally.
    std::string unique_id;  ///< Moonlight client unique identifier for this launch request.
    int width;  ///< Frame or display width in pixels.
    int height;  ///< Frame or display height in pixels.
    int fps;  ///< Requested video frame rate.
    int appid;  ///< Application ID requested for launch or resume.
    int surround_info;  ///< Encoded GameStream surround-sound capability flags.
    std::string surround_params;  ///< Client-provided surround-sound layout parameters.
    bool continuous_audio;  ///< Whether audio packets continue during silence.
    bool enable_hdr;  ///< Whether HDR streaming is requested.
    std::string output_id;  ///< Opaque StationConnect output selected by the client.
    std::string output_name;  ///< Capture backend name resolved from output_id.
    std::string display_mode;  ///< StationConnect presentation mode negotiated at launch.
    std::string topology_generation;  ///< Client topology generation bound to this launch.
    std::string host_layout;  ///< Exact StationConnect host display layout required by the bookmark.
    std::string virtual_mode_1;  ///< Exact qualified mode required for virtual output 1.
    std::string virtual_mode_2;  ///< Exact qualified mode required for virtual output 2.
    std::string capture_source;  ///< Exact StationConnect capture source requested by the client.
    std::string encoder_backend;  ///< Exact StationConnect encoder backend requested by the client.
    std::string encoding_mode;  ///< Exact StationConnect codec/depth/chroma/encoder mode requested by the client.
    std::uint32_t quic_udp_payload_mtu {};  ///< Fixed complete QUIC UDP payload ceiling selected for both peers.
    bool span_desktop {};  ///< Whether the complete virtual desktop is captured for this session.
    std::uint32_t stationconnect_protocol_version {};  ///< Selected StationConnect extension version.
    std::uint32_t stationconnect_feature_flags {};  ///< Client-supported StationConnect feature bits.
    bool stationconnect_display_lease {};  ///< Whether this stream owns a temporary physical-display layout.
    uid_t stationconnect_display_lease_uid {};  ///< PAM account that owns the temporary display lease.

    std::shared_ptr<void> authentication_session;  ///< PAM lifetime retained by StationConnect streams.
    std::shared_ptr<void> datasmash_endpoint;  ///< Experimental QUIC data-plane lifetime.
  };

  /**
   * @brief Queue an authorized launch for native QUIC negotiation.
   *
   * @param launch_session Session state prepared by the GameStream launch handler.
   */
  void launch_session_raise(std::shared_ptr<launch_session_t> launch_session);

  /**
   * @brief Clear state for the specified launch session.
   * @param launch_session_id The ID of the session to clear.
   */
  void launch_session_clear(uint32_t launch_session_id);

  /**
   * @brief Get the number of active sessions.
   * @return Count of active sessions.
   */
  int session_count();

  /**
   * @brief Check whether an accepted launch awaits its native QUIC peer.
   * @return True when a launch session is pending.
   */
  bool launch_session_pending();

  /**
   * @brief Terminates all running streaming sessions.
   */
  void terminate_sessions();
  /**
   * @brief Runs the native QUIC session-setup worker.
   */
  void start();
}  // namespace session_stream
