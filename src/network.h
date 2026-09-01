/**
 * @file src/network.h
 * @brief Declarations for networking related functions.
 */
#pragma once

// standard includes
// lib includes
#include <boost/asio.hpp>

namespace net {
  /**
   * @brief Map a specified port based on the base port.
   * @param port The port to map as a difference from the base port.
   * @return The mapped port number.
   * @examples
   * std::uint16_t mapped_port = net::map_port(1);
   * @examples_end
   * @todo Ensure port is not already in use by another application.
   */
  std::uint16_t map_port(int port);

  /**
   * @brief Enumerates supported net options.
   */
  enum net_e : int {
    PC,  ///< PC
    LAN,  ///< LAN
    WAN  ///< WAN
  };

  /**
   * @brief Convert configuration text to a network enum value.
   *
   * @param view Boost.Log record view being formatted.
   * @return Value converted from enum string.
   */
  net_e from_enum_string(const std::string_view &view);
  /**
   * @brief Convert a network enum value to configuration text.
   *
   * @param net Network scope to convert or format.
   * @return Value converted to enum string.
   */
  std::string_view to_enum_string(net_e net);

  /**
   * @brief Convert a Boost address family to Sunshine network enum value.
   *
   * @param view Boost.Log record view being formatted.
   * @return Value converted from address.
   */
  net_e from_address(const std::string_view &view);

  /**
   * @brief Convert an address to a normalized form.
   * @details Normalization converts IPv4-mapped IPv6 addresses into IPv4 addresses.
   * @param address The address to normalize.
   * @return Normalized address.
   */
  boost::asio::ip::address normalize_address(boost::asio::ip::address address);

  /**
   * @brief Get the given address in normalized string form.
   * @details Normalization converts IPv4-mapped IPv6 addresses into IPv4 addresses.
   * @param address The address to normalize.
   * @return Normalized address in string form.
   */
  std::string addr_to_normalized_string(boost::asio::ip::address address);

  /**
   * @brief Get the given address in a normalized form for the host portion of a URL.
   * @details Normalization converts IPv4-mapped IPv6 addresses into IPv4 addresses.
   * @param address The address to normalize and escape.
   * @return Normalized address in URL-escaped string.
   */
  std::string addr_to_url_escaped_string(boost::asio::ip::address address);

  /**
   * @brief Returns a string for use as the instance name for mDNS.
   * @param hostname The hostname to use for instance name generation.
   * @return Hostname-based instance name or "PLANK" if hostname is invalid.
   */
  std::string mdns_instance_name(const std::string_view &hostname);
}  // namespace net
