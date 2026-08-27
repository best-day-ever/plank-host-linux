/**
 * @file src/rtsp.h
 * @brief Declarations for RTSP streaming.
 */
#pragma once

// standard includes
#include <atomic>
#include <memory>

#include <sys/types.h>

// local includes
#include "crypto.h"
#include "thread_safe.h"

namespace rtsp_stream {
  constexpr auto RTSP_SETUP_PORT = 21;  ///< GameStream base-port offset used for the RTSP setup listener.

  /**
   * @brief RTSP launch session state shared with stream setup.
   */
  struct launch_session_t {
    uint32_t id;  ///< RTSP launch-session identifier assigned before stream startup.

    crypto::aes_t gcm_key;  ///< AES-GCM key negotiated for encrypted RTSP messages.
    crypto::aes_t iv;  ///< Initial RTSP AES-GCM IV supplied by the client.

    std::string av_ping_payload;  ///< AV ping payload.
    uint32_t control_connect_data;  ///< Client-provided token used when connecting the control channel.

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
    bool span_desktop {};  ///< Whether the complete virtual desktop is captured for this session.
    std::uint32_t stationconnect_protocol_version {};  ///< Selected StationConnect extension version.
    std::uint32_t stationconnect_feature_flags {};  ///< Client-supported StationConnect feature bits.
    bool stationconnect_display_lease {};  ///< Whether this stream owns a temporary physical-display layout.
    uid_t stationconnect_display_lease_uid {};  ///< PAM account that owns the temporary display lease.

    std::optional<crypto::cipher::gcm_t> rtsp_cipher;  ///< AES-GCM cipher used once encrypted RTSP is negotiated.
    std::string rtsp_url_scheme;  ///< URL scheme selected by the RTSP SETUP flow.
    uint32_t rtsp_iv_counter;  ///< Counter value mixed into encrypted RTSP IVs.
    std::shared_ptr<void> authentication_session;  ///< PAM lifetime retained by StationConnect streams.
  };

  /**
   * @brief Queue a launch session until the RTSP client connects.
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
   * @brief Check whether an accepted launch is still waiting for its RTSP peer.
   * @return True when a launch session is pending.
   */
  bool launch_session_pending();

  /**
   * @brief Terminates all running streaming sessions.
   */
  void terminate_sessions();
  /**
   * @brief Terminate active sessions associated with a client certificate.
   *
   * @param cert Certificate data or object used by the operation.
   */

  /**
   * @brief Runs the RTSP server loop.
   */
  void start();
}  // namespace rtsp_stream
