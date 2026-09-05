/**
 * @file src/session/worker_control.h
 * @brief Bounded nonblocking reads from a supervised worker's control socket.
 */
#pragma once

#include <cerrno>
#include <cstddef>
#include <sys/socket.h>
#include <unistd.h>

namespace plank::session {
  /**
   * @brief Receive one record, retiring EOF/error descriptors from the poll set.
   *
   * Worker reaping and display-lease recovery remain the supervisor's job.
   * Closing this channel must not skip processing a pending SIGCHLD event.
   * @param descriptor Owned socket, set to -1 on EOF or permanent error.
   * @param buffer Destination for the record's bounded prefix.
   * @param capacity Size of the destination buffer.
   * @return Positive record length (possibly larger than capacity on truncation),
   * or -1 for no record. Callers must reject oversized records before parsing.
   */
  inline ssize_t receive_worker_control(int &descriptor, char *buffer, std::size_t capacity) {
    if (descriptor < 0) return -1;
    const auto size = recv(descriptor, buffer, capacity, MSG_DONTWAIT | MSG_TRUNC);
    if (size > 0) return size;
    if (size == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
      close(descriptor);
      descriptor = -1;
    }
    return -1;
  }
}  // namespace plank::session
