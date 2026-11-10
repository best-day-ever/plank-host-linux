/**
 * @file src/platform/linux/cuda_stream_work.h
 * @brief Drain submitted conversion work before its borrowed input can be released.
 */
#pragma once

#include <utility>

namespace cuda {
  /**
   * @brief Keep asynchronous conversion within the lifetime of the caller's frame.
   * @tparam Api CUDA driver function table.
   * @tparam Stream CUDA stream handle type.
   * @tparam Report Cleanup status reporter.
   *
   * Construct inside convert(), while its borrowed frame is alive. Every early
   * return drains submitted work before control returns to the frame's owner.
   */
  template<class Api, class Stream, class Report>
  class stream_work_t {
  public:
    /**
     * @brief Guard work submitted to the supplied conversion stream.
     * @param api Driver function table outliving this scope.
     * @param stream Stream whose work may reference the caller's frame.
     * @param report Reporter for an early-return synchronization status.
     */
    stream_work_t(Api &api, Stream stream, Report report):
        api(api),
        stream(stream),
        report(std::move(report)) {}

    stream_work_t(const stream_work_t &) = delete;
    stream_work_t &operator=(const stream_work_t &) = delete;

    /** @brief Finish work on early returns before the borrowed source can die. */
    ~stream_work_t() {
      if (!synchronized) {
        report(api.cuStreamSynchronize(stream));
      }
    }

    /**
     * @brief Synchronize on the normal path and return the driver's status.
     * @return CUDA status, including asynchronous conversion failures.
     */
    int synchronize() {
      synchronized = true;
      return api.cuStreamSynchronize(stream);
    }

  private:
    Api &api;  ///< Driver table used by the conversion.
    Stream stream;  ///< Stream borrowing the input frame.
    Report report;  ///< Early-return synchronization diagnostics.
    bool synchronized = false;  ///< Whether the normal path performed the barrier.
  };
}  // namespace cuda
