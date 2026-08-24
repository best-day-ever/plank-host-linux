/**
 * @file src/nvhttp.h
 * @brief Declarations for the StationConnect session-negotiation server.
 */
#pragma once

#include <Simple-Web-Server/server_https.hpp>

namespace nvhttp {

  constexpr auto VERSION = "7.1.431.-1";
  constexpr auto GFE_VERSION = "3.23.0.74";
  constexpr auto PORT_HTTP = 0;
  constexpr auto PORT_HTTPS = -5;

  /**
   * @brief Start the StationConnect authentication and session-negotiation server.
   */
  void start();

  /**
   * @brief Simple-Web-Server HTTPS transport used by StationConnect.
   */
  class SunshineHTTPS: public SimpleWeb::HTTPS {
  public:
    SunshineHTTPS(boost::asio::io_context &io_context, boost::asio::ssl::context &ctx):
        SimpleWeb::HTTPS(io_context, ctx) {
    }

    virtual ~SunshineHTTPS() {
      SimpleWeb::error_code ec;
      shutdown(ec);
    }
  };

}  // namespace nvhttp
