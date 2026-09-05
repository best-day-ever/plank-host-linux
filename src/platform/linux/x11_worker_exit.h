/**
 * @file src/platform/linux/x11_worker_exit.h
 * @brief Retire a worker whose X server has closed without unsafe global teardown.
 */
#pragma once

#include <cstdlib>
#include <unistd.h>

struct _XDisplay;

namespace platf::x11 {
  constexpr int lost_display_exit_status = 74;  ///< Fatal display I/O, not a clean stream disconnect.

  /**
   * @brief End only the media process after an unrecoverable Xlib I/O failure.
   *
   * Xlib's default handler calls exit() from whichever thread observed EOF.
   * NVIDIA atexit handlers can then deadlock against still-running encoding.
   * The supervisor owns graphical-session replacement and display leases;
   * kernel descriptor cleanup also closes PAM and virtual input endpoints.
   * Do not take logging locks, call Xlib, unwind, or run process destructors here.
   * Ordinary X protocol errors and normal disconnect retain normal cleanup.
   * @param display Failed Xlib connection; deliberately never dereferenced.
   * @return Never returns, as required for a fatal Xlib I/O handler.
   */
  [[noreturn]] inline int retire_failed_x11_worker(_XDisplay * /* display */) noexcept {
    constexpr char message[] =
      "PLANK media worker lost its X server; retiring without driver exit handlers\n";
    (void) write(STDERR_FILENO, message, sizeof(message) - 1);
    std::_Exit(lost_display_exit_status);
  }
}  // namespace platf::x11
