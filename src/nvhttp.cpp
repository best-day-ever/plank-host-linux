/**
 * @file src/nvhttp.cpp
 * @brief Definitions for the nvhttp (GameStream) server.
 */
// macros
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

// standard includes
#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <format>
#include <functional>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>

// lib includes
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/context_base.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <nlohmann/json.hpp>
#include <Simple-Web-Server/server_http.hpp>

#include <unistd.h>

#ifdef STATIONCONNECT_DATASMASH
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "stationconnect_datasmash.h"
#endif

// local includes
#include "config.h"
#include "auth/web_auth.h"
#include "display_device.h"
#include "globals.h"
#include "httpcommon.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "process.h"
#include "rtsp.h"
#include "session/session_context.h"
#include "stationconnect_topology.h"
#include "utility.h"
#include "uuid.h"
#include "video.h"

using namespace std::literals;

namespace nvhttp {

  static constexpr std::string_view EMPTY_PROPERTY_TREE_ERROR_MSG = "Property tree is empty. Probably, control flow got interrupted by an unexpected C++ exception. This is a bug in Sunshine. Moonlight-qt will report Malformed XML (missing root element)."sv;

  namespace fs = std::filesystem;
  namespace pt = boost::property_tree;

  constexpr std::string_view pam_broker_socket = "/run/stationconnect/pam/auth.sock"sv;  ///< Privileged broker activation path.
  constexpr std::string_view runtime_display_state =
    "/run/stationconnect/host/display-state"sv;
  std::unique_ptr<stationconnect::auth::web_auth_manager_t> web_auth;  ///< PAM conversations and ephemeral tokens.
  constexpr auto stationconnect_topology_version = stationconnect::topology::protocol_version;
  constexpr std::uint32_t stationconnect_host_metadata_version = 1;
  constexpr auto stationconnect_feature_selected_output =
    stationconnect::topology::feature_selected_output;
  constexpr auto stationconnect_feature_scaled_span =
    stationconnect::topology::feature_scaled_span;
  constexpr auto stationconnect_feature_topology_generation =
    stationconnect::topology::feature_topology_generation;
  constexpr auto stationconnect_feature_composite_source_regions =
    stationconnect::topology::feature_composite_source_regions;
  constexpr auto stationconnect_feature_host_layout_binding =
    stationconnect::topology::feature_host_layout_binding;
  constexpr auto stationconnect_feature_independent_virtual_modes =
    stationconnect::topology::feature_independent_virtual_modes;
  constexpr auto stationconnect_feature_dynamic_host_layout =
    stationconnect::topology::feature_dynamic_host_layout;
  constexpr auto stationconnect_feature_temporary_physical_layout =
    stationconnect::topology::feature_temporary_physical_layout;
  constexpr auto stationconnect_feature_capture_source_selection =
    stationconnect::topology::feature_capture_source_selection;
  constexpr auto stationconnect_feature_encoder_backend_selection =
    stationconnect::topology::feature_encoder_backend_selection;
  constexpr auto stationconnect_feature_nvfbc_hevc10_nvenc =
    stationconnect::topology::feature_nvfbc_hevc10_nvenc;
  constexpr auto stationconnect_topology_features = stationconnect::topology::feature_flags;

#ifdef STATIONCONNECT_DATASMASH
  std::string datasmash_last_error(ScDatasmashNativeEndpoint *endpoint) {
    std::array<char, 512> error {};
    sc_datasmash_native_endpoint_last_error(endpoint, error.data(), error.size());
    return error.data();
  }

  std::optional<std::string> certificate_sha256(const std::string &path) {
    BIO *bio = BIO_new_file(path.c_str(), "r");
    if (bio == nullptr) {
      return std::nullopt;
    }
    X509 *certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (certificate == nullptr) {
      return std::nullopt;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int digest_size = 0;
    const bool success =
      X509_digest(certificate, EVP_sha256(), digest.data(), &digest_size) == 1 &&
      digest_size == 32;
    X509_free(certificate);
    if (!success) {
      return std::nullopt;
    }
    // util::hex_vec() defaults to the little-endian representation used by
    // legacy GameStream fields. Certificate pins use the conventional byte
    // order emitted by TLS implementations and openssl x509 -fingerprint.
    return util::hex_vec(std::vector<std::uint8_t>(
      digest.begin(), digest.begin() + digest_size
    ), true);
  }

  bool start_datasmash_data_plane(rtsp_stream::launch_session_t &session,
                                  pt::ptree &tree) {
    if (session.data_plane != "datasmash") {
      return true;
    }

    const auto fingerprint = certificate_sha256(config::nvhttp.cert);
    if (!fingerprint) {
      tree.put("root.<xmlattr>.status_code", 503);
      tree.put("root.<xmlattr>.status_message",
               "Unable to fingerprint the StationConnect data-plane certificate");
      return false;
    }

    std::array<unsigned char, 32> token_bytes {};
    if (RAND_bytes(token_bytes.data(), token_bytes.size()) != 1) {
      tree.put("root.<xmlattr>.status_code", 503);
      tree.put("root.<xmlattr>.status_message",
               "Unable to create the StationConnect data-plane token");
      return false;
    }
    std::string token = util::hex_vec(std::vector<std::uint8_t>(
      token_bytes.begin(), token_bytes.end()
    ));
    OPENSSL_cleanse(token_bytes.data(), token_bytes.size());

    const auto port = net::map_port(0);
    const std::string bind_address = "0.0.0.0:" + std::to_string(port);
    ScDatasmashConfig endpoint_config {};
    endpoint_config.struct_size = sizeof(endpoint_config);
    endpoint_config.abi_version = SC_DATASMASH_ABI_VERSION;
    endpoint_config.mode = SC_DATASMASH_MODE_SERVER;
    endpoint_config.handshake_timeout_ms = 10000;
    const auto configured_idle_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(
        config::stream.ping_timeout
      ).count();
    const auto idle_ms = std::clamp<std::int64_t>(configured_idle_ms, 200, 120000);
    const auto keep_alive_ms = std::clamp<std::int64_t>(idle_ms / 2, 100, 5000);
    endpoint_config.idle_timeout_ms = static_cast<std::uint32_t>(idle_ms);
    endpoint_config.keep_alive_interval_ms = static_cast<std::uint32_t>(keep_alive_ms);
    endpoint_config.bind_address = bind_address.c_str();
    endpoint_config.certificate_path = config::nvhttp.cert.c_str();
    endpoint_config.private_key_path = config::nvhttp.pkey.c_str();
    endpoint_config.session_token = token.c_str();

    ScDatasmashNativeEndpoint *endpoint = nullptr;
    int result = sc_datasmash_native_endpoint_create(&endpoint_config, &endpoint);
    if (result == SC_DATASMASH_OK) {
      result = sc_datasmash_native_endpoint_start(endpoint);
    }
    if (result != SC_DATASMASH_OK) {
      const std::string error_message = endpoint == nullptr ?
        "endpoint creation failed" : datasmash_last_error(endpoint);
      if (endpoint != nullptr) {
        sc_datasmash_native_endpoint_destroy(endpoint);
      }
      OPENSSL_cleanse(token.data(), token.size());
      BOOST_LOG(error) << "Unable to start experimental datasmash listener: "sv
                       << error_message;
      tree.put("root.<xmlattr>.status_code", 503);
      tree.put("root.<xmlattr>.status_message",
               "Unable to start the experimental StationConnect data plane");
      return false;
    }

    session.datasmash_endpoint = std::shared_ptr<void>(endpoint, [](void *raw_endpoint) {
      auto *endpoint = static_cast<ScDatasmashNativeEndpoint *>(raw_endpoint);
      sc_datasmash_native_endpoint_stop(endpoint);
      sc_datasmash_native_endpoint_destroy(endpoint);
    });
    tree.put("root.StationConnectDatasmashPort", port);
    tree.put("root.StationConnectDatasmashCertificateSha256", *fingerprint);
    tree.put("root.StationConnectDatasmashToken", token);
    OPENSSL_cleanse(token.data(), token.size());
    BOOST_LOG(info) << "Experimental datasmash listener started on UDP port "sv << port
                    << " (idle timeout "sv << idle_ms << " ms)"sv;
    return true;
  }
#endif

  /**
   * @brief HTTPS server backend that requires TLS 1.3.
   */
  class SunshineHTTPSServer: public SimpleWeb::ServerBase<SunshineHTTPS> {
  public:
    /**
     * @brief Initialize the HTTPS server with Sunshine's certificate and key files.
     *
     * @param certification_file Path to the server certificate file.
     * @param private_key_file Path to the matching private key file.
     */
    SunshineHTTPSServer(const std::string &certification_file, const std::string &private_key_file,
                        bool tls13_only):
        ServerBase<SunshineHTTPS>::ServerBase(443),
        context(boost::asio::ssl::context::tls_server) {
      // Disabling TLS 1.0 and 1.1 (see RFC 8996)
      context.set_options(boost::asio::ssl::context::no_tlsv1);
      context.set_options(boost::asio::ssl::context::no_tlsv1_1);
      if (tls13_only && SSL_CTX_set_min_proto_version(context.native_handle(), TLS1_3_VERSION) != 1) {
        throw std::runtime_error("Unable to require TLS 1.3 for StationConnect authentication");
      }
      context.use_certificate_chain_file(certification_file);
      context.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
    }

  protected:
    boost::asio::ssl::context context;  ///< TLS server context configured with Sunshine's certificate and protocol policy.

    // This is Server<HTTPS>::accept() with SSL validation support added
    /**
     * @brief Accept a pending connection and arm the server for the next client.
     */
    void accept() override {
      auto connection = create_connection(*io_service, context);

      acceptor->async_accept(connection->socket->lowest_layer(), [this, connection](const SimpleWeb::error_code &ec) {
        auto lock = connection->handler_runner->continue_lock();
        if (!lock) {
          return;
        }

        if (ec != SimpleWeb::error::operation_aborted) {
          this->accept();
        }

        auto session = std::make_shared<Session>(config.max_request_streambuf_size, connection);

        if (!ec) {
          boost::asio::ip::tcp::no_delay option(true);
          SimpleWeb::error_code ec;
          session->connection->socket->lowest_layer().set_option(option, ec);

          session->connection->set_timeout(config.timeout_request);
          session->connection->socket->async_handshake(boost::asio::ssl::stream_base::server, [this, session](const SimpleWeb::error_code &ec) {
            session->connection->cancel_timeout();
            auto lock = session->connection->handler_runner->continue_lock();
            if (!lock) {
              return;
            }
            if (!ec) {
              this->read(session);
            } else if (this->on_error) {
              this->on_error(session->request, ec);
            }
          });
        } else if (this->on_error) {
          this->on_error(session->request, ec);
        }
      });
    }
  };

  /**
   * @brief HTTPS server type used for GameStream endpoints requiring TLS.
   */
  using https_server_t = SunshineHTTPSServer;
  /**
   * @brief Plain HTTP server type used for GameStream endpoints without TLS.
   */
  using http_server_t = SimpleWeb::Server<SimpleWeb::HTTP>;

  std::atomic<uint32_t> session_id_counter;  ///< Monotonic counter used to allocate GameStream session IDs.
  std::mutex session_start_mutex;  ///< Serializes launch/resume state transitions.

  /**
   * @brief Case-insensitive map used for HTTP headers and query parameters.
   */
  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  /**
   * @brief Shared HTTPS response object passed to GameStream handlers.
   */
  using resp_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SunshineHTTPS>::Response>;
  /**
   * @brief Shared HTTPS request object received by GameStream handlers.
   */
  using req_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SunshineHTTPS>::Request>;
  /**
   * @brief Shared HTTP response object passed to redirect and discovery handlers.
   */
  using resp_http_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Response>;
  /**
   * @brief Shared HTTP request object received by redirect and discovery handlers.
   */
  using req_http_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Request>;

  /**
   * @brief Return the normalized peer address used to bind an authentication session.
   *
   * @param request HTTPS request.
   * @return Normalized peer address without a port.
   */
  std::string authentication_peer(const req_https_t &request) {
    return net::addr_to_normalized_string(request->remote_endpoint().address());
  }

  /**
   * @brief Write a non-cacheable JSON authentication response.
   *
   * @param response HTTPS response.
   * @param status HTTP status.
   * @param body JSON response body.
   */
  void write_auth_json(const resp_https_t &response, SimpleWeb::StatusCode status,
                       const nlohmann::json &body) {
    SimpleWeb::CaseInsensitiveMultimap headers {
      {"Content-Type", "application/json"},
      {"Cache-Control", "no-store"},
      {"Pragma", "no-cache"},
    };
    response->write(status, body.dump(), headers);
    response->close_connection_after_response = true;
  }

  /**
   * @brief Convert one internal PAM step to the HTTPS schema.
   *
   * @param step Internal authentication state.
   * @return JSON response without credential data.
   */
  nlohmann::json auth_step_json(const stationconnect::auth::web_auth_step_t &step) {
    using state_e = stationconnect::auth::step_t::state_e;
    nlohmann::json body;
    if (step.state == state_e::challenge) {
      body["state"] = "challenge";
      body["conversation_id"] = step.conversation_id;
      body["messages"] = nlohmann::json::array();
      for (const auto &prompt : step.prompts) {
        body["messages"].push_back({{"style", prompt.style}, {"text", prompt.text}});
      }
    } else if (step.state == state_e::authenticated) {
      body["state"] = "authenticated";
      body["session_token"] = step.session_token;
      body["expires_in"] = 300;
    } else {
      body["state"] = "denied";
      body["phase"] = static_cast<std::uint16_t>(step.phase);
      body["pam_status"] = step.pam_status;
    }
    return body;
  }

  /**
   * @brief Read a bounded JSON request body without logging it.
   *
   * @param request HTTPS request.
   * @return Parsed JSON object, or null on malformed input.
   */
  nlohmann::json read_auth_json(const req_https_t &request) {
    std::ostringstream stream;
    stream << request->content.rdbuf();
    std::string content = stream.str();
    if (content.size() > 64U * 1024U) {
      if (!content.empty()) {
        explicit_bzero(content.data(), content.size());
      }
      return nullptr;
    }
    auto body = nlohmann::json::parse(content, nullptr, false);
    if (!content.empty()) {
      explicit_bzero(content.data(), content.size());
    }
    return body;
  }

  /**
   * @brief Begin a network PAM conversation.
   *
   * @param response HTTPS response.
   * @param request HTTPS request carrying only a username.
   */
  void auth_start(const resp_https_t &response, const req_https_t &request) {
    if (!web_auth) {
      write_auth_json(response, SimpleWeb::StatusCode::server_error_service_unavailable,
                      {{"state", "unavailable"}});
      return;
    }
    const auto body = read_auth_json(request);
    if (!body.is_object() || !body.contains("username") || !body["username"].is_string()) {
      write_auth_json(response, SimpleWeb::StatusCode::client_error_bad_request,
                      {{"state", "invalid-request"}});
      return;
    }
    const auto username = body["username"].get<std::string>();
    const auto step = web_auth->begin(username, authentication_peer(request));
    write_auth_json(response, SimpleWeb::StatusCode::success_ok, auth_step_json(step));
  }

  /**
   * @brief Advance a network PAM conversation.
   *
   * @param response HTTPS response.
   * @param request HTTPS request carrying prompt responses.
   */
  void auth_respond(const resp_https_t &response, const req_https_t &request) {
    auto body = read_auth_json(request);
    if (!web_auth || !body.is_object() || !body.contains("conversation_id") ||
        !body["conversation_id"].is_string() || !body.contains("responses") ||
        !body["responses"].is_array() || body["responses"].size() > 64) {
      write_auth_json(response, SimpleWeb::StatusCode::client_error_bad_request,
                      {{"state", "invalid-request"}});
      return;
    }
    std::vector<std::string> responses;
    for (auto &item : body["responses"]) {
      if (!item.is_string()) {
        for (auto &value : responses) {
          explicit_bzero(value.data(), value.size());
        }
        write_auth_json(response, SimpleWeb::StatusCode::client_error_bad_request,
                        {{"state", "invalid-request"}});
        return;
      }
      responses.push_back(item.get<std::string>());
      auto &stored = item.get_ref<std::string &>();
      if (!stored.empty()) {
        explicit_bzero(stored.data(), stored.size());
      }
    }
    const auto conversation_id = body["conversation_id"].get<std::string>();
    const auto step = web_auth->respond(conversation_id, authentication_peer(request),
                                        std::move(responses));
    write_auth_json(response, SimpleWeb::StatusCode::success_ok, auth_step_json(step));
  }

  /**
   * @brief Extract a bearer token without authenticating it.
   *
   * @param request HTTPS request.
   * @return Token view backed by the request headers, or an empty view.
   */
  std::string_view bearer_token(const req_https_t &request) {
    const auto header = request->header.find("Authorization");
    constexpr std::string_view prefix = "Bearer ";
    if (header == request->header.end() || !header->second.starts_with(prefix)) {
      return {};
    }
    return std::string_view {header->second}.substr(prefix.size());
  }

  /**
   * @brief Extract and validate a peer-bound bearer token.
   *
   * @param request HTTPS request.
   * @return True when its token authorizes the peer.
   */
  bool authenticated(const req_https_t &request) {
    const auto token = bearer_token(request);
    return !token.empty() && web_auth &&
           web_auth->authorize(token, authentication_peer(request));
  }

  /**
   * @brief Retain the request's PAM session for a streaming launch.
   *
   * @param request Authorized HTTPS request.
   * @return Type-erased PAM session lifetime, or null on failure.
   */
  std::shared_ptr<void> claim_authentication_session(const req_https_t &request) {
    return web_auth ? web_auth->claim(bearer_token(request), authentication_peer(request)) : nullptr;
  }

  /**
   * @brief Verify that a request's PAM account owns this user-service process.
   *
   * @param request Authorized HTTPS request.
   * @return True when the authenticated account UID matches the active desktop.
   */
  std::optional<uid_t> authenticated_account_uid_for_desktop(
    const req_https_t &request
  ) {
    if (!web_auth) {
      return std::nullopt;
    }
    const auto token = bearer_token(request);
    const auto identity = web_auth->identity(token, authentication_peer(request));
    if (!identity) {
      return std::nullopt;
    }
    const auto uid = stationconnect::auth::account_uid(*identity);
    if (!uid ||
        !stationconnect::session::supervisor_attests_account_for_active_seat0(*uid)) {
      web_auth->cancel(token);
      BOOST_LOG(warning) << "Rejecting StationConnect stream for an account that is not authorized for the active desktop"sv;
      return std::nullopt;
    }
    return uid;
  }

  /**
   * @brief Return a GameStream-compatible authorization failure.
   *
   * @param response HTTPS response.
   * @param request Rejected request.
   * @return False for convenient handler guards.
   */
  bool require_authentication(const resp_https_t &response, const req_https_t &request) {
    if (authenticated(request)) {
      return true;
    }
    pt::ptree tree;
    tree.put("root.<xmlattr>.status_code", 401);
    tree.put("root.<xmlattr>.query", request->path);
    tree.put("root.<xmlattr>.status_message", "Operating-system authentication required.");
    std::ostringstream data;
    pt::write_xml(data, tree);
    response->write(data.str());
    response->close_connection_after_response = true;
    return false;
  }

  struct live_layout_t {
    std::string startup_kind;
    std::string kind;
    bool virtual_layout {};
    std::vector<std::string> virtual_modes;
    bool temporary_physical_lease {};
    uid_t lease_uid {};
  };

  live_layout_t live_display_layout(
    const std::vector<platf::display_info_t> &outputs
  ) {
    live_layout_t result;
    // The protocol field describes the concrete boot topology, while the
    // administrator setting is now a physical/virtual policy. Virtual hosts
    // always initialize one 1920x1080 output before bookmark negotiation.
    result.startup_kind = config::sunshine.startup_layout == "virtual" ?
      "single" : "physical";
    if (const auto runtime = stationconnect::session::read_runtime_display_state(
          runtime_display_state
        )) {
      result.kind = runtime->layout;
      result.virtual_layout = true;
      result.virtual_modes = {runtime->mode_1};
      if (!runtime->mode_2.empty()) result.virtual_modes.push_back(runtime->mode_2);
      result.temporary_physical_lease = true;
      result.lease_uid = runtime->lease_uid;
      return result;
    }
    result.virtual_layout = result.startup_kind != "physical";
    result.kind = !result.virtual_layout ? "physical" :
      outputs.size() == 1 ? "single" :
      outputs.size() == 2 ? "dual-horizontal" : "unhealthy";
    if (result.virtual_layout) {
      for (const auto &output : outputs) {
        result.virtual_modes.push_back(
          std::format("{}x{}", output.width, output.height)
        );
      }
    }
    return result;
  }

  nlohmann::json output_topology_json() {
    auto outputs = video::output_topology();
    std::sort(outputs.begin(), outputs.end(), [](const auto &left, const auto &right) {
      return std::tie(left.x, left.y, left.id) < std::tie(right.x, right.y, right.id);
    });
    int min_x = 0;
    int min_y = 0;
    int max_x = 0;
    int max_y = 0;
    bool first = true;
    for (const auto &output : outputs) {
      if (first) {
        min_x = output.x;
        min_y = output.y;
        max_x = output.x + output.width;
        max_y = output.y + output.height;
        first = false;
      } else {
        min_x = std::min(min_x, output.x);
        min_y = std::min(min_y, output.y);
        max_x = std::max(max_x, output.x + output.width);
        max_y = std::max(max_y, output.y + output.height);
      }
    }

    const auto live_layout = live_display_layout(outputs);
    nlohmann::json virtual_modes = live_layout.virtual_modes;
    nlohmann::json allowed_layouts = nlohmann::json::array();
    if (live_layout.startup_kind == "physical") {
      allowed_layouts.push_back("physical");
    }
    allowed_layouts.push_back("single");
    allowed_layouts.push_back("dual-horizontal");
    nlohmann::json body {
      {"schema_version", stationconnect_topology_version},
      {"feature_flags", stationconnect_topology_features},
      {"layout", {
        {"kind", live_layout.kind},
        {"virtual", live_layout.virtual_layout},
        {"virtual_modes", virtual_modes},
        {"output_count", outputs.size()},
        {"startup_kind", live_layout.startup_kind},
        {"allowed_kinds", allowed_layouts},
      }},
      {"outputs", nlohmann::json::array()},
    };
    for (std::size_t index = 0; index < outputs.size(); ++index) {
      const auto &output = outputs[index];
      const std::string configured_mode = !live_layout.virtual_layout ? std::string {} :
        index < live_layout.virtual_modes.size() ? live_layout.virtual_modes[index] :
                                                   std::string {};
      body["outputs"].push_back({
        {"id", output.id},
        {"name", output.name},
        {"x", output.x},
        {"y", output.y},
        {"width", output.width},
        {"height", output.height},
        {"rotation", output.rotation},
        {"refresh_millihz", output.refresh_millihz},
        {"primary", output.primary},
        {"virtual", live_layout.virtual_layout},
        {"configured_mode", configured_mode},
        {"source_rect", {
          {"x", output.x - min_x},
          {"y", output.y - min_y},
          {"width", output.width},
          {"height", output.height},
        }},
      });
    }
    body["desktop"] = {
      {"x", min_x}, {"y", min_y}, {"width", max_x - min_x}, {"height", max_y - min_y},
    };
    body["generation"] = video::output_topology_generation(outputs);
    return body;
  }

  bool bind_host_layout(rtsp_stream::launch_session_t &session,
                        const std::vector<platf::display_info_t> &outputs,
                        uid_t authenticated_uid,
                        pt::ptree &tree) {
    if (session.stationconnect_protocol_version != stationconnect_topology_version ||
        (session.stationconnect_feature_flags & stationconnect_feature_host_layout_binding) == 0 ||
        (session.stationconnect_feature_flags & stationconnect_feature_independent_virtual_modes) == 0 ||
        (session.stationconnect_feature_flags & stationconnect_feature_dynamic_host_layout) == 0 ||
        (session.stationconnect_feature_flags & stationconnect_feature_temporary_physical_layout) == 0 ||
        session.host_layout.empty()) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing StationConnect host-layout binding");
      return false;
    }

    std::vector<std::reference_wrapper<const platf::display_info_t>> ordered_outputs;
    ordered_outputs.reserve(outputs.size());
    for (const auto &output : outputs) {
      ordered_outputs.emplace_back(output);
    }
    std::sort(ordered_outputs.begin(), ordered_outputs.end(), [](const auto &left, const auto &right) {
      const auto &l = left.get();
      const auto &r = right.get();
      return std::tie(l.x, l.y, l.id) < std::tie(r.x, r.y, r.id);
    });

    const auto live_layout = live_display_layout(outputs);
    if (!stationconnect::topology::layout_allowed_by_startup_layout(
          session.host_layout, live_layout.startup_kind
        )) {
      tree.put("root.<xmlattr>.status_code", 409);
      tree.put(
        "root.<xmlattr>.status_message",
        "The requested display layout is not supported by this workstation"
      );
      return false;
    }
    const auto &actual_layout = live_layout.kind;
    const auto actual_mode_1 = live_layout.virtual_layout &&
      !live_layout.virtual_modes.empty() ? live_layout.virtual_modes[0] : std::string {};
    const auto actual_mode_2 = actual_layout == "dual-horizontal" ?
      live_layout.virtual_modes.size() > 1 ? live_layout.virtual_modes[1] : std::string {} :
      std::string {};
    const auto validation = stationconnect::topology::validate_layout_binding(
      session.host_layout,
      session.virtual_mode_1,
      session.virtual_mode_2,
      actual_layout,
      actual_mode_1,
      actual_mode_2,
      outputs.size()
    );
    if (validation == stationconnect::topology::layout_error::invalid_request) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Invalid StationConnect host-layout binding");
      return false;
    }
    if (validation == stationconnect::topology::layout_error::mismatch) {
      const auto transition = stationconnect::session::request_display_transition({
        stationconnect::session::display_request_t::action_t::acquire,
        session.host_layout, session.virtual_mode_1, session.virtual_mode_2,
        authenticated_uid
      });
      if (transition == stationconnect::session::display_request_status::submitted) {
        tree.put("root.<xmlattr>.status_code", 425);
        tree.put("root.<xmlattr>.status_message",
                 "StationConnect host display transition started");
        return false;
      }
      if (transition == stationconnect::session::display_request_status::wrong_user) {
        tree.put("root.<xmlattr>.status_code", 423);
        tree.put("root.<xmlattr>.status_message",
                 "Only the active desktop user may change its display layout");
        return false;
      }
      tree.put("root.<xmlattr>.status_code", 503);
      tree.put(
        "root.<xmlattr>.status_message",
        "Host display layout transition is currently unavailable"
      );
      return false;
    }
    if (validation == stationconnect::topology::layout_error::unhealthy) {
      tree.put("root.<xmlattr>.status_code", 409);
      tree.put("root.<xmlattr>.status_message", "Configured host display layout is not healthy");
      return false;
    }
    if (live_layout.virtual_layout) {
      const auto mode_1 = stationconnect::topology::virtual_mode_size(actual_mode_1);
      const bool first_matches = ordered_outputs[0].get().width == mode_1.width &&
                                 ordered_outputs[0].get().height == mode_1.height;
      bool second_matches = true;
      if (actual_layout == "dual-horizontal") {
        const auto mode_2 = stationconnect::topology::virtual_mode_size(actual_mode_2);
        second_matches = ordered_outputs[1].get().width == mode_2.width &&
                         ordered_outputs[1].get().height == mode_2.height &&
                         ordered_outputs[1].get().x ==
                           ordered_outputs[0].get().x + mode_1.width;
      }
      if (!first_matches || !second_matches) {
        tree.put("root.<xmlattr>.status_code", 409);
        tree.put("root.<xmlattr>.status_message", "Configured host display modes are not live");
        return false;
      }
    }
    if (live_layout.temporary_physical_lease) {
      if (live_layout.lease_uid != authenticated_uid) {
        tree.put("root.<xmlattr>.status_code", 423);
        tree.put("root.<xmlattr>.status_message",
                 "The temporary workstation display layout belongs to another account");
        return false;
      }
      session.stationconnect_display_lease = true;
      session.stationconnect_display_lease_uid = authenticated_uid;
    }
    return true;
  }

  void output_topology(const resp_https_t &response, const req_https_t &) {
    write_auth_json(response, SimpleWeb::StatusCode::success_ok, output_topology_json());
  }

  bool bind_topology_generation(rtsp_stream::launch_session_t &session,
                                const std::vector<platf::display_info_t> &outputs,
                                pt::ptree &tree) {
    // Bind the requested output layout atomically at launch. Do not poll the
    // display server from the capture callback: NVIDIA/X11 enumeration can
    // block physical presentation as well as the capture pipeline.
    if ((session.stationconnect_feature_flags & stationconnect_feature_topology_generation) == 0) {
      session.topology_generation.clear();
      return true;
    }
    if (session.stationconnect_protocol_version != stationconnect_topology_version ||
        session.topology_generation.empty()) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing StationConnect topology generation");
      return false;
    }
    const auto current_generation = video::output_topology_generation(outputs);
    if (session.topology_generation != current_generation) {
      tree.put("root.<xmlattr>.status_code", 409);
      tree.put("root.<xmlattr>.status_message", "Host output topology changed; refresh and retry");
      return false;
    }
    return true;
  }

  bool resolve_selected_output(rtsp_stream::launch_session_t &session,
                               uid_t authenticated_uid,
                               pt::ptree &tree) {
    const auto outputs = video::output_topology();
    if (!bind_host_layout(session, outputs, authenticated_uid, tree)) {
      return false;
    }
    if (session.display_mode == "scaled-span" || session.display_mode == "separate-displays") {
      if (session.stationconnect_protocol_version != stationconnect_topology_version ||
          (session.stationconnect_feature_flags & stationconnect_feature_scaled_span) == 0 ||
          (session.display_mode == "separate-displays" &&
           (session.stationconnect_feature_flags & stationconnect_feature_composite_source_regions) == 0) ||
          !session.output_id.empty()) {
        tree.put("root.<xmlattr>.status_code", 400);
        tree.put("root.<xmlattr>.status_message", "Invalid StationConnect composite-display negotiation");
        return false;
      }
      if (outputs.empty()) {
        tree.put("root.<xmlattr>.status_code", 409);
        tree.put("root.<xmlattr>.status_message", "Host desktop topology is unavailable");
        return false;
      }
      if (!bind_topology_generation(session, outputs, tree)) {
        return false;
      }
      session.output_name.clear();
      session.span_desktop = true;
      BOOST_LOG(info) << "StationConnect selected "sv << session.display_mode
                      << " virtual-desktop span"sv;
      return true;
    }
    if (!session.display_mode.empty() && session.display_mode != "single-output") {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Unknown StationConnect display mode");
      return false;
    }
    if (session.output_id.empty()) {
      session.output_name.clear();
      return true;
    }
    if (session.stationconnect_protocol_version != stationconnect_topology_version ||
        (session.stationconnect_feature_flags & stationconnect_feature_selected_output) == 0) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Invalid StationConnect output negotiation");
      return false;
    }
    if (!bind_topology_generation(session, outputs, tree)) {
      return false;
    }
    const auto capture_name = video::resolve_output_capture_name(outputs, session.output_id);
    if (!capture_name) {
      tree.put("root.<xmlattr>.status_code", 409);
      tree.put("root.<xmlattr>.status_message", "Selected host output is no longer available");
      return false;
    }
    session.output_name = *capture_name;
    BOOST_LOG(info) << "StationConnect selected output "sv << logging::bracket(session.output_id)
                    << " using capture name "sv << logging::bracket(session.output_name);
    return true;
  }

  bool validate_capture_source(rtsp_stream::launch_session_t &session,
                               pt::ptree &tree) {
    if (session.stationconnect_protocol_version != stationconnect_topology_version ||
        (session.stationconnect_feature_flags &
         stationconnect_feature_capture_source_selection) == 0) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message",
               "StationConnect capture-source negotiation is required");
      return false;
    }
    if (session.capture_source != "nvfbc" &&
        session.capture_source != "x11-native10") {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message",
               "Unsupported StationConnect capture source");
      return false;
    }
    if (!video::capture_source_available(session.capture_source)) {
      tree.put("root.<xmlattr>.status_code", 503);
      tree.put("root.<xmlattr>.status_message",
               "Requested StationConnect capture source is unavailable");
      return false;
    }
    return true;
  }

  bool validate_data_plane(rtsp_stream::launch_session_t &session,
                           pt::ptree &tree) {
    if (session.data_plane == "legacy") {
      return true;
    }
#ifdef STATIONCONNECT_DATASMASH
    if (session.data_plane == "datasmash") {
      return true;
    }
#endif
    tree.put("root.<xmlattr>.status_code", 400);
    tree.put("root.<xmlattr>.status_message",
             "Unsupported StationConnect data plane");
    return false;
  }

  bool validate_encoder_backend(rtsp_stream::launch_session_t &session,
                                pt::ptree &tree) {
    if (session.stationconnect_protocol_version != stationconnect_topology_version ||
        (session.stationconnect_feature_flags &
         stationconnect_feature_encoder_backend_selection) == 0) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message",
               "StationConnect encoder-backend negotiation is required");
      return false;
    }
    const bool nvenc_hevc10_mode = session.encoding_mode == "hevc-10-444-nvenc";
    if (!stationconnect::topology::valid_encoding_tuple(
          session.capture_source,
          session.encoder_backend,
          session.encoding_mode)) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message",
               "Unsupported StationConnect capture and encoding mode combination");
      return false;
    }
    if (session.capture_source == "nvfbc" && nvenc_hevc10_mode &&
        (session.stationconnect_feature_flags &
         stationconnect_feature_nvfbc_hevc10_nvenc) == 0) {
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message",
               "NvFBC HEVC 10-bit NVENC negotiation is required");
      return false;
    }
    const bool exact_mode_available =
      video::encoding_mode_available(session.encoding_mode);
    if (!exact_mode_available) {
      tree.put("root.<xmlattr>.status_code", 503);
      tree.put("root.<xmlattr>.status_message",
               "Requested StationConnect encoding mode is unavailable");
      return false;
    }
    return true;
  }

  /**
   * @brief Read a named query argument from the HTTP request map.
   *
   * @param args Parsed query-string argument map.
   * @param name Query parameter name to read.
   * @param default_value Value returned when the parameter is absent.
   * @return Query parameter value, default value, or an empty string.
   */
  std::string get_arg(const args_t &args, const char *name, const char *default_value = nullptr) {
    auto it = args.find(name);
    if (it == std::end(args)) {
      if (default_value != nullptr) {
        return std::string(default_value);
      }

      throw std::out_of_range(name);
    }
    return it->second;
  }

  /**
   * @brief Persist the current state to its backing store.
   */
  void save_state() {
    pt::ptree root;
    root.put("root.uniqueid", http::unique_id);

    try {
      pt::write_json(config::nvhttp.file_state, root);
    } catch (std::exception &e) {
      BOOST_LOG(error) << "Couldn't write "sv << config::nvhttp.file_state << ": "sv << e.what();
      return;
    }
  }

  /**
   * @brief Load state from its backing store.
   */
  void load_state() {
    if (!fs::exists(config::nvhttp.file_state)) {
      BOOST_LOG(info) << "File "sv << config::nvhttp.file_state << " doesn't exist"sv;
      http::unique_id = uuid_util::uuid_t::generate().string();
      save_state();
      return;
    }

    pt::ptree tree;
    try {
      pt::read_json(config::nvhttp.file_state, tree);
    } catch (std::exception &e) {
      BOOST_LOG(error) << "Couldn't read "sv << config::nvhttp.file_state << ": "sv << e.what();
      http::unique_id = uuid_util::uuid_t::generate().string();
      return;
    }

    auto unique_id_p = tree.get_optional<std::string>("root.uniqueid");
    if (!unique_id_p) {
      http::unique_id = uuid_util::uuid_t::generate().string();
      save_state();
      return;
    }
    http::unique_id = std::move(*unique_id_p);
  }

  /**
   * @brief Create launch session.
   *
   * @param host_audio Host audio.
   * @param args Arguments forwarded to the callable or parser.
   * @return Constructed launch session object.
   */
  std::shared_ptr<rtsp_stream::launch_session_t> make_launch_session(bool host_audio, const args_t &args) {
    auto launch_session = std::make_shared<rtsp_stream::launch_session_t>();

    launch_session->id = ++session_id_counter;

    auto rikey = util::from_hex_vec(get_arg(args, "rikey"), true);
    std::copy(rikey.cbegin(), rikey.cend(), std::back_inserter(launch_session->gcm_key));

    launch_session->host_audio = host_audio;
    std::stringstream mode = std::stringstream(get_arg(args, "mode", "0x0x0"));
    // Split mode by the char "x", to populate width/height/fps
    int x = 0;
    std::string segment;
    while (std::getline(mode, segment, 'x')) {
      if (x == 0) {
        launch_session->width = atoi(segment.c_str());
      }
      if (x == 1) {
        launch_session->height = atoi(segment.c_str());
      }
      if (x == 2) {
        launch_session->fps = atoi(segment.c_str());
      }
      x++;
    }
    launch_session->unique_id = (get_arg(args, "uniqueid", "unknown"));
    launch_session->appid = (int) util::from_view(get_arg(args, "appid", "unknown"));
    launch_session->surround_info = (int) util::from_view(get_arg(args, "surroundAudioInfo", "196610"));
    launch_session->surround_params = (get_arg(args, "surroundParams", ""));
    launch_session->continuous_audio = util::from_view(get_arg(args, "continuousAudio", "0"));
    launch_session->enable_hdr = util::from_view(get_arg(args, "hdrMode", "0"));
    launch_session->output_id = get_arg(args, "scOutputId", "");
    launch_session->display_mode = get_arg(args, "scDisplayMode", "");
    launch_session->topology_generation = get_arg(args, "scTopologyGeneration", "");
    launch_session->host_layout = get_arg(args, "scHostLayout", "");
    launch_session->virtual_mode_1 = get_arg(args, "scVirtualMode1", "");
    launch_session->virtual_mode_2 = get_arg(args, "scVirtualMode2", "");
    launch_session->data_plane = get_arg(args, "scDataPlane", "");
    launch_session->capture_source = get_arg(args, "scCaptureSource", "");
    launch_session->encoder_backend = get_arg(args, "scEncoderBackend", "");
    launch_session->encoding_mode = get_arg(args, "scEncodingMode", "");
    launch_session->stationconnect_protocol_version =
      static_cast<std::uint32_t>(util::from_view(get_arg(args, "scProtocolVersion", "0")));
    launch_session->stationconnect_feature_flags =
      static_cast<std::uint32_t>(util::from_view(get_arg(args, "scFeatureFlags", "0")));

    // Encrypted RTSP is enabled with client reported corever >= 1
    auto corever = util::from_view(get_arg(args, "corever", "0"));
    if (corever >= 1) {
      launch_session->rtsp_cipher = crypto::cipher::gcm_t {
        launch_session->gcm_key,
        false
      };
      launch_session->rtsp_iv_counter = 0;
    }
    launch_session->rtsp_url_scheme = launch_session->rtsp_cipher ? "rtspenc://"s : "rtsp://"s;
    // Generate the unique identifiers for this connection that we will send later during RTSP handshake
    unsigned char raw_payload[8];
    RAND_bytes(raw_payload, sizeof(raw_payload));
    launch_session->av_ping_payload = util::hex_vec(raw_payload);
    RAND_bytes((unsigned char *) &launch_session->control_connect_data, sizeof(launch_session->control_connect_data));

    launch_session->iv.resize(16);
    uint32_t prepend_iv = util::endian::big<uint32_t>((int) util::from_view(get_arg(args, "rikeyid")));
    auto prepend_iv_p = (uint8_t *) &prepend_iv;
    std::copy(prepend_iv_p, prepend_iv_p + sizeof(prepend_iv), std::begin(launch_session->iv));
    return launch_session;
  }

  template<class T>
  struct tunnel;

  /**
   * @brief HTTPS tunnel session used for encrypted client requests.
   */
  template<>
  struct tunnel<SunshineHTTPS> {
    static auto constexpr to_string = "HTTPS"sv;  ///< To string.
  };

  /**
   * @brief Plain HTTP server wrapper used for non-TLS endpoints.
   */
  template<>
  struct tunnel<SimpleWeb::HTTP> {
    static auto constexpr to_string = "NONE"sv;  ///< To string.
  };

  /**
   * @brief Write req details to the log.
   *
   * @param request HTTP request data from the client.
   */
  template<class T>
  void print_req(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    BOOST_LOG(debug) << "TUNNEL :: "sv << tunnel<T>::to_string;

    BOOST_LOG(debug) << "METHOD :: "sv << request->method;
    BOOST_LOG(debug) << "DESTINATION :: "sv << request->path;

    for (auto &[name, val] : request->header) {
      if (boost::iequals(name, "Authorization") || boost::iequals(name, "Cookie")) {
        BOOST_LOG(debug) << name << " -- <redacted>"sv;
      } else {
        BOOST_LOG(debug) << name << " -- " << val;
      }
    }

    BOOST_LOG(debug) << " [--] "sv;

    for (auto &[name, val] : request->parse_query_string()) {
      BOOST_LOG(debug) << name << " -- " << val;
    }

    BOOST_LOG(debug) << " [--] "sv;
  }

  /**
   * @brief Return a GameStream HTTP not-found response.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  template<class T>
  void not_found(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    print_req<T>(request);

    pt::ptree tree;
    tree.put("root.<xmlattr>.status_code", 404);

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());

    *response
      << "HTTP/1.1 404 NOT FOUND\r\n"
      << data.str();

    response->close_connection_after_response = true;
  }

  /**
   * @brief Get codec mode flags.
   *
   * @return Codec capability bitmask for the exact StationConnect profiles.
   */
  uint32_t get_codec_mode_flags() {
    uint32_t codec_mode_flags = SCM_H264;
    if (video::last_encoder_probe_supported_yuv444_for_codec[0] ||
        video::nvenc_direct_supports_h264_444_8bit()) {
      codec_mode_flags |= SCM_H264_HIGH8_444;
    }
    if (video::last_encoder_probe_supported_h264_10bit_444) {
      codec_mode_flags |= SCM_H264_HIGH10_444;
    }
    if (video::last_encoder_probe_supported_yuv444_for_codec[0] ||
        video::last_encoder_probe_supported_h264_10bit_444 ||
        video::nvenc_direct_supports_h264_444_8bit() ||
        video::nvenc_direct_supports_hevc_444_8bit() ||
        video::nvenc_direct_supports_hevc_444_10bit()) {
#if defined(SUNSHINE_BUILD_CUDA)
      codec_mode_flags |= SCM_IDENTITY_GBR_444;
#endif
    }
    if (video::last_encoder_probe_supported_h264_8bit_422) {
      codec_mode_flags |= SCM_H264_HIGH8_422;
    }
    if (video::last_encoder_probe_supported_h264_10bit_422) {
      codec_mode_flags |= SCM_H264_HIGH10_422;
    }
    if (video::nvenc_direct_supports_hevc_444_8bit() ||
        video::nvenc_direct_supports_hevc_444_10bit()) {
      codec_mode_flags |= SCM_HEVC;
      if (video::nvenc_direct_supports_hevc_444_8bit()) {
        codec_mode_flags |= SCM_HEVC_REXT8_444;
      }
    }
    if (video::nvenc_direct_supports_hevc_444_10bit()) {
      codec_mode_flags |= SCM_HEVC_REXT10_444;
    }
    return codec_mode_flags;
  }

  std::string get_stationconnect_encoding_modes() {
    static constexpr std::array modes {
      "h264-8-422-software"sv,
      "h264-8-444-software"sv,
      "h264-10-422-software"sv,
      "h264-10-444-software"sv,
      "h264-8-444-nvenc"sv,
      "hevc-8-444-nvenc"sv,
      "hevc-10-444-nvenc"sv,
    };
    std::string result;
    for (const auto mode : modes) {
      if (!video::encoding_mode_available(mode)) {
        continue;
      }
      if (!result.empty()) {
        result += ',';
      }
      result += mode;
    }
    return result;
  }

  /**
   * @brief Build the GameStream server-info response.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  template<class T>
  void serverinfo(std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response> response, std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request) {
    print_req<T>(request);

    int authorization_status = 0;
    if constexpr (std::is_same_v<SunshineHTTPS, T>) {
      authorization_status = authenticated(request) ? 1 : 0;
    }

    auto local_endpoint = request->local_endpoint();

    pt::ptree tree;

    tree.put("root.<xmlattr>.status_code", 200);
    tree.put("root.hostname", config::nvhttp.sunshine_name);

    tree.put("root.appversion", VERSION);
    tree.put("root.GfeVersion", GFE_VERSION);
    tree.put("root.uniqueid", http::unique_id);
    tree.put("root.HttpsPort", net::map_port(PORT_HTTPS));
    tree.put("root.ExternalPort", net::map_port(PORT_HTTP));
    tree.put("root.StationConnectAuth", 1);
    tree.put("root.StationConnectHostMetadataVersion", stationconnect_host_metadata_version);
    tree.put("root.StationConnectHostVersion", PROJECT_VERSION);
    tree.put("root.StationConnectTopologyVersion", stationconnect_topology_version);
    tree.put("root.StationConnectFeatureFlags", stationconnect_topology_features);
    tree.put("root.StationConnectCaptureSources", "nvfbc,x11-native10");
#ifdef STATIONCONNECT_DATASMASH
    tree.put("root.StationConnectDataPlanes", "legacy,datasmash");
#else
    tree.put("root.StationConnectDataPlanes", "legacy");
#endif
    tree.put("root.StationConnectEncoderBackends", "software-cuda,nvenc-direct");
    tree.put("root.StationConnectEncodingModes", get_stationconnect_encoding_modes());
    tree.put("root.MaxLumaPixelsHEVC",
             video::nvenc_direct_supports_hevc_444_8bit() ||
                 video::nvenc_direct_supports_hevc_444_10bit() ?
               "1869449984" : "0");

    // Moonlight clients track LAN IPv6 addresses separately from LocalIP which is expected to
    // always be an IPv4 address. If we return that same IPv6 address here, it will clobber the
    // stored LAN IPv4 address. To avoid this, we need to return an IPv4 address in this field
    // when we get a request over IPv6.
    //
    // HACK: We should return the IPv4 address of local interface here, but we don't currently
    // have that implemented. For now, we will emulate the behavior of GFE+GS-IPv6-Forwarder,
    // which returns 127.0.0.1 as LocalIP for IPv6 connections. Moonlight clients with IPv6
    // support know to ignore this bogus address.
    if (local_endpoint.address().is_v6() && !local_endpoint.address().to_v6().is_v4_mapped()) {
      tree.put("root.LocalIP", "127.0.0.1");
    } else {
      tree.put("root.LocalIP", net::addr_to_normalized_string(local_endpoint.address()));
    }

    const uint32_t codec_mode_flags = get_codec_mode_flags();
    tree.put("root.ServerCodecModeSupport", codec_mode_flags);

    auto current_appid = authorization_status == 1 ? proc::proc.running() : 0;
    // This compatibility-shaped field reports PAM bearer authorization.
    tree.put("root.PairStatus", authorization_status);
    tree.put("root.currentgame", current_appid);
    tree.put("root.state", current_appid > 0 ? "SUNSHINE_SERVER_BUSY" : "SUNSHINE_SERVER_FREE");

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());
    response->close_connection_after_response = true;
  }

  /**
   * @brief Build the GameStream application list response.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void applist(resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);

    pt::ptree tree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    auto &apps = tree.add_child("root", pt::ptree {});

    apps.put("<xmlattr>.status_code", 200);

    pt::ptree app;
    app.put("IsHdrSupported"s, 0);
    app.put("AppTitle"s, proc::desktop_app_name);
    app.put("ID", proc::desktop_app_id);
    apps.push_back(std::make_pair("App", std::move(app)));
  }

  /**
   * @brief Launch the requested application for a GameStream session.
   *
   * @param host_audio Host audio.
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void launch(bool &host_audio, resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);

    std::scoped_lock session_start_lock {session_start_mutex};

    pt::ptree tree;
    bool revert_display_configuration {false};
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      if (tree.empty()) {
        BOOST_LOG(error) << EMPTY_PROPERTY_TREE_ERROR_MSG;
      }

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;

      if (revert_display_configuration) {
        display_device::revert_configuration();
      }
    });

    auto args = request->parse_query_string();
    if (
      args.find("rikey"s) == std::end(args) ||
      args.find("rikeyid"s) == std::end(args) ||
      args.find("localAudioPlayMode"s) == std::end(args) ||
      args.find("appid"s) == std::end(args)
    ) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing a required launch parameter");

      return;
    }

    auto appid = util::from_view(get_arg(args, "appid"));

    const auto authenticated_uid = authenticated_account_uid_for_desktop(request);
    if (!authenticated_uid) {
      tree.put("root.gamesession", 0);
      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "The authenticated account does not own this desktop session");
      return;
    }

    if (!proc::is_desktop_app((int) appid)) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "StationConnect permits only the Desktop session");
      return;
    }

    auto current_appid = proc::proc.running();
    if (current_appid > 0 &&
        rtsp_stream::session_count() == 0 &&
        !rtsp_stream::launch_session_pending()) {
      // The Desktop application is a process-less reservation. A normal
      // disconnect stops and joins the media session, but the reservation can
      // outlive it and make a rapid reconnect look like a competing launch.
      // session_count() above synchronously removes STOPPING sessions. Once no
      // active or pending RTSP session owns this reservation, clear it before
      // admitting the replacement launch.
      BOOST_LOG(info) << "Clearing orphaned StationConnect Desktop reservation before launch"sv;
      proc::proc.terminate();
      current_appid = 0;
    }
    if (current_appid > 0) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "An app is already running on this host");

      return;
    }

    host_audio = util::from_view(get_arg(args, "localAudioPlayMode"));
    auto launch_session = make_launch_session(host_audio, args);
    if (!validate_data_plane(*launch_session, tree)) {
      tree.put("root.gamesession", 0);
      return;
    }
    if (!validate_capture_source(*launch_session, tree)) {
      tree.put("root.gamesession", 0);
      return;
    }
    if (!validate_encoder_backend(*launch_session, tree)) {
      tree.put("root.gamesession", 0);
      return;
    }
    if (!resolve_selected_output(*launch_session, *authenticated_uid, tree)) {
      tree.put("root.gamesession", 0);
      return;
    }

    if (rtsp_stream::session_count() == 0) {
      if (!video::select_encoder_backend_for_session(
              launch_session->encoder_backend)) {
        tree.put("root.<xmlattr>.status_code", 503);
        tree.put("root.<xmlattr>.status_message",
                 "Requested StationConnect encoder backend is unavailable");
        tree.put("root.gamesession", 0);
        return;
      }
      // The display should be restored in case something fails as there are no other sessions.
      revert_display_configuration = true;

      // We want to prepare display only if there are no active sessions at
      // the moment. This should be done before probing encoders as it could
      // change the active displays.
      display_device::configure_display(config::video, *launch_session);

      // The media worker probes capture and encoding before its HTTP interface
      // starts. Reprobing here can race a reconnecting NvFBC capture thread.
    }

    auto encryption_mode = net::encryption_mode_for_address(request->remote_endpoint().address());
    if (!launch_session->rtsp_cipher && encryption_mode == config::ENCRYPTION_MODE_MANDATORY) {
      BOOST_LOG(error) << "Rejecting client that cannot comply with mandatory encryption requirement"sv;

      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Encryption is mandatory for this host but unsupported by the client");
      tree.put("root.gamesession", 0);

      return;
    }

    if (appid > 0) {
      auto err = proc::proc.execute((int) appid);
      if (err) {
        tree.put("root.<xmlattr>.status_code", err);
        tree.put("root.<xmlattr>.status_message", "Failed to start the specified application");
        tree.put("root.gamesession", 0);

        return;
      }
    }

    launch_session->authentication_session = claim_authentication_session(request);
    if (!launch_session->authentication_session) {
      tree.put("root.<xmlattr>.status_code", 401);
      tree.put("root.<xmlattr>.status_message", "A new operating-system login is required.");
      tree.put("root.gamesession", 0);
      return;
    }

#ifdef STATIONCONNECT_DATASMASH
    if (!start_datasmash_data_plane(*launch_session, tree)) {
      tree.put("root.gamesession", 0);
      return;
    }
#endif

    tree.put("root.<xmlattr>.status_code", 200);
    tree.put(
      "root.sessionUrl0",
      std::format(
        "{}{}:{}",
        launch_session->rtsp_url_scheme,
        net::addr_to_url_escaped_string(request->local_endpoint().address()),
        static_cast<int>(net::map_port(rtsp_stream::RTSP_SETUP_PORT))
      )
    );
    tree.put("root.gamesession", 1);
    tree.put("root.StationConnectDataPlane", launch_session->data_plane);
    tree.put("root.StationConnectCaptureSource", launch_session->capture_source);
    tree.put("root.StationConnectEncoderBackend", launch_session->encoder_backend);
    tree.put("root.StationConnectEncodingMode", launch_session->encoding_mode);

    rtsp_stream::launch_session_raise(launch_session);

    // Stream was started successfully, we will revert the config when the app or session terminates
    revert_display_configuration = false;
  }

  /**
   * @brief Resume an existing GameStream session.
   *
   * @param host_audio Host audio.
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void resume(bool &host_audio, resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);

    std::scoped_lock session_start_lock {session_start_mutex};

    pt::ptree tree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      if (tree.empty()) {
        BOOST_LOG(error) << EMPTY_PROPERTY_TREE_ERROR_MSG;
      }

      pt::write_xml(data, tree);
      response->write(data.str());
      response->close_connection_after_response = true;
    });

    const auto authenticated_uid = authenticated_account_uid_for_desktop(request);
    if (!authenticated_uid) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "The authenticated account does not own this desktop session");
      return;
    }

    auto current_appid = proc::proc.running();
    if (current_appid == 0) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 503);
      tree.put("root.<xmlattr>.status_message", "No running app to resume");

      return;
    }

    if (!proc::is_desktop_app(current_appid)) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "StationConnect permits only the Desktop session");
      return;
    }

    auto args = request->parse_query_string();
    if (
      args.find("rikey"s) == std::end(args) ||
      args.find("rikeyid"s) == std::end(args)
    ) {
      tree.put("root.resume", 0);
      tree.put("root.<xmlattr>.status_code", 400);
      tree.put("root.<xmlattr>.status_message", "Missing a required resume parameter");

      return;
    }

    // Newer Moonlight clients send localAudioPlayMode on /resume too,
    // so we should use it if it's present in the args and there are
    // no active sessions we could be interfering with.
    const bool no_active_sessions {rtsp_stream::session_count() == 0};
    if (no_active_sessions && args.find("localAudioPlayMode"s) != std::end(args)) {
      host_audio = util::from_view(get_arg(args, "localAudioPlayMode"));
    }
    const auto launch_session = make_launch_session(host_audio, args);
    if (!validate_data_plane(*launch_session, tree)) {
      tree.put("root.resume", 0);
      return;
    }
    if (!validate_capture_source(*launch_session, tree)) {
      tree.put("root.resume", 0);
      return;
    }
    if (!validate_encoder_backend(*launch_session, tree)) {
      tree.put("root.resume", 0);
      return;
    }
    if (!resolve_selected_output(*launch_session, *authenticated_uid, tree)) {
      tree.put("root.resume", 0);
      return;
    }

    if (no_active_sessions) {
      if (!video::select_encoder_backend_for_session(
              launch_session->encoder_backend)) {
        tree.put("root.<xmlattr>.status_code", 503);
        tree.put("root.<xmlattr>.status_message",
                 "Requested StationConnect encoder backend is unavailable");
        tree.put("root.resume", 0);
        return;
      }
      // We want to prepare display only if there are no active sessions at
      // the moment. This should be done before probing encoders as it could
      // change the active displays.
      display_device::configure_display(config::video, *launch_session);

      // Worker startup probing remains authoritative; avoid racing NvFBC
      // probing with a prior stream's capture teardown.
    }

    auto encryption_mode = net::encryption_mode_for_address(request->remote_endpoint().address());
    if (!launch_session->rtsp_cipher && encryption_mode == config::ENCRYPTION_MODE_MANDATORY) {
      BOOST_LOG(error) << "Rejecting client that cannot comply with mandatory encryption requirement"sv;

      tree.put("root.<xmlattr>.status_code", 403);
      tree.put("root.<xmlattr>.status_message", "Encryption is mandatory for this host but unsupported by the client");
      tree.put("root.gamesession", 0);

      return;
    }

    launch_session->authentication_session = claim_authentication_session(request);
    if (!launch_session->authentication_session) {
      tree.put("root.<xmlattr>.status_code", 401);
      tree.put("root.<xmlattr>.status_message", "A new operating-system login is required.");
      tree.put("root.resume", 0);
      return;
    }

#ifdef STATIONCONNECT_DATASMASH
    if (!start_datasmash_data_plane(*launch_session, tree)) {
      tree.put("root.resume", 0);
      return;
    }
#endif

    tree.put("root.<xmlattr>.status_code", 200);
    tree.put(
      "root.sessionUrl0",
      std::format(
        "{}{}:{}",
        launch_session->rtsp_url_scheme,
        net::addr_to_url_escaped_string(request->local_endpoint().address()),
        static_cast<int>(net::map_port(rtsp_stream::RTSP_SETUP_PORT))
      )
    );
    tree.put("root.resume", 1);
    tree.put("root.StationConnectDataPlane", launch_session->data_plane);
    tree.put("root.StationConnectCaptureSource", launch_session->capture_source);
    tree.put("root.StationConnectEncoderBackend", launch_session->encoder_backend);
    tree.put("root.StationConnectEncodingMode", launch_session->encoding_mode);

    rtsp_stream::launch_session_raise(launch_session);
  }

  /**
   * @brief Return an application asset requested by the client.
   *
   * @param response HTTP response object to populate.
   * @param request HTTP request data from the client.
   */
  void appasset(resp_https_t response, req_https_t request) {
    print_req<SunshineHTTPS>(request);

    std::ifstream in(proc::desktop_image_path, std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/png");
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
    response->close_connection_after_response = true;
  }

  void start() {
    platf::set_thread_name("nvhttp");
    auto shutdown_event = mail::man->event<bool>(mail::shutdown);

    auto port_http = net::map_port(PORT_HTTP);
    auto port_https = net::map_port(PORT_HTTPS);
    auto address_family = net::af_from_enum_string(config::sunshine.address_family);

    bool clean_slate = config::sunshine.flags[config::flag::FRESH_STATE];

    if (!clean_slate) {
      load_state();
    }

    // resume doesn't always get the parameter "localAudioPlayMode"
    // launch will store it in host_audio
    bool host_audio {};

    if (access(pam_broker_socket.data(), R_OK | W_OK) != 0) {
      BOOST_LOG(fatal) << "StationConnect PAM broker is unavailable; refusing to start session negotiation"sv;
      shutdown_event->raise(true);
      return;
    }
    web_auth = std::make_unique<stationconnect::auth::web_auth_manager_t>(
      stationconnect::auth::pam_conversation_factory(std::filesystem::path {pam_broker_socket}),
      stationconnect::auth::secure_random_hex
    );
    BOOST_LOG(info) << "StationConnect PAM authentication active"sv;

    https_server_t https_server {
      config::nvhttp.cert,
      config::nvhttp.pkey,
      true,
    };
    http_server_t http_server;

    https_server.default_resource["GET"] = not_found<SunshineHTTPS>;
    https_server.resource["^/serverinfo$"]["GET"] = serverinfo<SunshineHTTPS>;
    https_server.resource["^/stationconnect/auth/start$"]["POST"] = auth_start;
    https_server.resource["^/stationconnect/auth/respond$"]["POST"] = auth_respond;
    https_server.resource["^/stationconnect/topology$"]["GET"] = [](auto resp, auto req) {
      if (require_authentication(resp, req)) {
        output_topology(resp, req);
      }
    };
    https_server.resource["^/applist$"]["GET"] = [](auto resp, auto req) {
      if (require_authentication(resp, req)) {
        applist(resp, req);
      }
    };
    https_server.resource["^/appasset$"]["GET"] = [](auto resp, auto req) {
      if (require_authentication(resp, req)) {
        appasset(resp, req);
      }
    };
    https_server.resource["^/launch$"]["GET"] = [&host_audio](auto resp, auto req) {
      if (require_authentication(resp, req)) {
        launch(host_audio, resp, req);
      }
    };
    https_server.resource["^/resume$"]["GET"] = [&host_audio](auto resp, auto req) {
      if (require_authentication(resp, req)) {
        resume(host_audio, resp, req);
      }
    };

    https_server.config.reuse_address = true;
    https_server.config.address = net::get_bind_address(address_family);
    https_server.config.port = port_https;

    http_server.default_resource["GET"] = not_found<SimpleWeb::HTTP>;
    http_server.resource["^/serverinfo$"]["GET"] = serverinfo<SimpleWeb::HTTP>;
    http_server.config.reuse_address = true;
    http_server.config.address = net::get_bind_address(address_family);
    http_server.config.port = port_http;

    auto accept_and_run = [&](auto *http_server) {
      try {
        std::string name = "nvhttp::" + std::to_string(http_server->config.port);
        platf::set_thread_name(name);
        http_server->start();
      } catch (boost::system::system_error &err) {
        // It's possible the exception gets thrown after calling http_server->stop() from a different thread
        if (shutdown_event->peek()) {
          return;
        }

        BOOST_LOG(fatal) << "Couldn't start http server on ports ["sv << port_https << ", "sv << port_https << "]: "sv << err.what();
        shutdown_event->raise(true);
        return;
      }
    };
    std::jthread ssl {accept_and_run, &https_server};
    std::jthread tcp {accept_and_run, &http_server};

    // Wait for any event
    shutdown_event->view();

    https_server.stop();
    http_server.stop();

    ssl.join();
    tcp.join();
  }

}  // namespace nvhttp
