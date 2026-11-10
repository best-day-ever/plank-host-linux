/**
 * @file src/platform/linux/cuda_primary_context.h
 * @brief Per-session ownership of a thread's CUDA primary-context binding.
 */
#pragma once

#include <functional>
#include <utility>

namespace cuda {
  /**
   * @brief Retain and bind a primary context until all session resources are gone.
   * @tparam Api CUDA driver function table (also injectable for lifecycle tests).
   * @tparam Context CUDA context handle type.
   * @tparam Device CUDA device ordinal type.
   *
   * This object and its resources must be destroyed on the creating thread.
   * Each session retains independently, even when that context is already current.
   */
  template<class Api, class Context, class Device = int>
  class primary_context_t {
  public:
    /**
     * @brief Store the driver and cleanup error reporter without acquiring resources.
     * @param api CUDA driver function table, outliving this object.
     * @param report Cleanup error reporter; receives the CUDA status and operation.
     */
    primary_context_t(Api &api, std::function<void(int, const char *)> report):
        api(api),
        report(std::move(report)) {}

    primary_context_t(const primary_context_t &) = delete;
    primary_context_t &operator=(const primary_context_t &) = delete;

    /** @brief Restore the previous binding before releasing this session's reference. */
    ~primary_context_t() {
      if (pushed) {
        Context popped = nullptr;
        report(api.cuCtxPopCurrent(&popped), "Couldn't pop encoder CUDA primary context: ");
      }
      if (retained) {
        report(api.cuDevicePrimaryCtxRelease(device), "Couldn't release encoder CUDA primary context: ");
      }
    }

    /**
     * @brief Acquire the current device's primary context, or device zero if unbound.
     * @return CUDA status; partial acquisition is unwound by the destructor.
     */
    int init() {
      Context current = nullptr;
      int status = api.cuCtxGetCurrent(&current);
      if (status) {
        return status;
      }
      status = current ? api.cuCtxGetDevice(&device) : api.cuDeviceGet(&device, 0);
      if (status) {
        return status;
      }
      status = api.cuDevicePrimaryCtxRetain(&context, device);
      if (status) {
        return status;
      }
      retained = true;
      status = api.cuCtxPushCurrent(context);
      pushed = !status;
      return status;
    }

    /** @brief Return the retained primary context passed to NVENC. */
    Context get() const {
      return context;
    }

  private:
    Api &api;  ///< Driver function table with session-independent lifetime.
    std::function<void(int, const char *)> report;  ///< Cleanup diagnostics.
    Context context = nullptr;  ///< Independently retained primary context.
    Device device = 0;  ///< Device whose primary reference must be released.
    bool retained = false;  ///< Whether retain succeeded, including push failures.
    bool pushed = false;  ///< Whether this thread owns a matching context push.
  };
}  // namespace cuda
