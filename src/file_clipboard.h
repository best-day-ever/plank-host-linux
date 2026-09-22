/**
 * @file src/file_clipboard.h
 * @brief Session-scoped PLANK file clipboard receiver declarations.
 */
#pragma once

#include <functional>
#include <stop_token>
#include <string>
#include <string_view>
#include <optional>
#include <vector>

struct PlankTransportNativeEndpoint;

namespace stream::file_clipboard {
  using publish_files_t = std::function<bool(const std::vector<std::string> &)>;
  using take_files_t = std::function<std::optional<std::vector<std::string>>() >;
  /**
   * @brief Return whether policy permits files from Client to Host.
   * @param mode Immutable negotiated direction policy.
   * @return True for client-to-host and bidirectional policies.
   */
  bool client_to_host_allowed(std::string_view mode);
  /**
   * @brief Return whether policy permits files from Host to Client.
   * @param mode Immutable negotiated direction policy.
   * @return True for host-to-client and bidirectional policies.
   */
  bool host_to_client_allowed(std::string_view mode);

  /**
   * @brief Receive, validate, stage, and publish Client file clipboard offers.
   * @param stop_token Session cancellation token.
   * @param endpoint Authenticated native transport endpoint.
   * @param publish_files Serialized X11 publication callback.
   * @param mode Immutable negotiated direction policy.
   */
  void worker(
    std::stop_token stop_token,
    PlankTransportNativeEndpoint *endpoint,
    publish_files_t publish_files,
    take_files_t take_files,
    std::string_view mode
  );
}  // namespace stream::file_clipboard
