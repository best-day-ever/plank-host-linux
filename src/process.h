/**
 * @file src/process.h
 * @brief StationConnect Desktop stream reservation state.
 */
#pragma once

// standard includes
#include <atomic>
#include <memory>
#include <string_view>

// local includes
#include "platform/common.h"

namespace proc {
  /**
   * Stable GameStream application identity for the one StationConnect stream.
   *
   * The value preserves the ID previously derived from the packaged Desktop
   * name and image. Keeping it independent from mutable artwork prevents an
   * image replacement from changing the protocol identity.
   */
  inline constexpr int desktop_app_id = 881448767;
  inline constexpr std::string_view desktop_app_name = "Desktop";

  /**
   * @brief Return whether a GameStream application ID is StationConnect Desktop.
   */
  bool is_desktop_app(int app_id) noexcept;

  /**
   * @brief Track the process-less Desktop reservation used by launch/resume.
   */
  class proc_t {
  public:
    /**
     * @brief Replace any previous reservation with StationConnect Desktop.
     * @return Zero on success or the GameStream not-found status.
     */
    int execute(int app_id);

    /**
     * @return The reserved Desktop application ID, or zero when idle.
     */
    int running() const noexcept;

    /**
     * @brief Release the Desktop reservation and retained input state.
     */
    void terminate();

  private:
    std::atomic<int> _app_id {0};
  };

  /**
   * @brief Initialize reservation cleanup for host shutdown.
   */
  std::unique_ptr<platf::deinit_t> init();

  extern proc_t proc;
}  // namespace proc
