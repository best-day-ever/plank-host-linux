/**
 * @file tests/unit/test_cuda_primary_context.cpp
 * @brief Exercise the actual encoder context owner against a stateful CUDA driver fake.
 */
#include "src/platform/linux/cuda_primary_context.h"

#include <gtest/gtest.h>
#include <algorithm>
#include <string>
#include <vector>

namespace {
  /** @brief Stateful CUDA API fake: contexts have references and a thread-local stack. */
  struct driver_t {
    int token = 0;  ///< Stable primary-context identity.
    int other = 0;  ///< An unrelated caller context.
    int refs = 0;  ///< Live primary-context references.
    int device = -1;  ///< Device selected by retain/release.
    std::string fail;  ///< Injected failing API boundary.
    std::vector<void *> stack;  ///< Current thread's context stack.
    std::vector<std::string> calls;  ///< Ordered API side effects.

    /** @brief Record an API boundary and optionally fail it. */
    int call(const char *name) {
      calls.emplace_back(name);
      return fail == name ? 17 : 0;
    }
    /** @brief Read this thread's binding without acquiring ownership. */
    int cuCtxGetCurrent(void **out) {
      if (auto status = call("current")) return status;
      *out = stack.empty() ? nullptr : stack.back();
      return 0;
    }
    /** @brief Select the current context's device, which need not be ordinal zero. */
    int cuCtxGetDevice(int *out) {
      if (auto status = call("context-device")) return status;
      *out = stack.back() == &other ? 3 : device;
      return 0;
    }
    /** @brief Select the default device on an unbound thread. */
    int cuDeviceGet(int *out, int ordinal) {
      if (auto status = call("default-device")) return status;
      *out = ordinal;
      return 0;
    }
    /** @brief Acquire one independent primary-context reference. */
    int cuDevicePrimaryCtxRetain(void **out, int ordinal) {
      if (auto status = call("retain")) return status;
      device = ordinal;
      ++refs;
      *out = &token;
      return 0;
    }
    /** @brief Bind while preserving the caller's context below it. */
    int cuCtxPushCurrent(void *context) {
      if (auto status = call("push")) return status;
      EXPECT_GT(refs, 0);
      stack.push_back(context);
      return 0;
    }
    /** @brief Restore the previous binding while the primary context is alive. */
    int cuCtxPopCurrent(void **out) {
      if (auto status = call("pop")) return status;
      EXPECT_GT(refs, 0);
      EXPECT_FALSE(stack.empty());
      *out = stack.back();
      stack.pop_back();
      return 0;
    }
    /** @brief Release the reference after restoring thread state. */
    int cuDevicePrimaryCtxRelease(int ordinal) {
      EXPECT_EQ(ordinal, device);
      EXPECT_GT(refs, 0);
      --refs;
      return call("release");
    }
  };

  using owner_t = cuda::primary_context_t<driver_t, void *>;

  TEST(CudaPrimaryContext, RetainsAndRestoresUnboundThread) {
    driver_t driver;
    {
      owner_t context(driver, [](int status, const char *) { EXPECT_EQ(status, 0); });
      ASSERT_EQ(context.init(), 0);
      EXPECT_EQ(context.get(), &driver.token);
      EXPECT_EQ(driver.refs, 1);
      EXPECT_EQ(driver.device, 0);
    }
    EXPECT_EQ(driver.refs, 0);
    EXPECT_TRUE(driver.stack.empty());
    EXPECT_EQ(driver.calls, (std::vector<std::string>{"current", "default-device", "retain", "push", "pop", "release"}));
  }

  TEST(CudaPrimaryContext, PreservesCallerContextAndDevice) {
    driver_t driver;
    driver.stack.push_back(&driver.other);
    {
      owner_t context(driver, [](int status, const char *) { EXPECT_EQ(status, 0); });
      ASSERT_EQ(context.init(), 0);
      EXPECT_EQ(driver.device, 3);
      EXPECT_EQ(driver.stack.back(), &driver.token);
    }
    EXPECT_EQ(driver.stack, (std::vector<void *>{&driver.other}));
    EXPECT_EQ(driver.refs, 0);
  }

  TEST(CudaPrimaryContext, ExistingPrimaryBindingStillGetsIndependentReference) {
    driver_t driver;
    driver.refs = 1;
    driver.stack.push_back(&driver.token);
    {
      owner_t context(driver, [](int status, const char *) { EXPECT_EQ(status, 0); });
      ASSERT_EQ(context.init(), 0);
      EXPECT_EQ(driver.refs, 2);
      EXPECT_EQ(driver.stack.size(), 2);
    }
    EXPECT_EQ(driver.refs, 1);
    EXPECT_EQ(driver.stack, (std::vector<void *>{&driver.token}));
  }

  TEST(CudaPrimaryContext, NestedSessionsCannotReleaseEachOthersContext) {
    driver_t driver;
    {
      owner_t first(driver, [](int status, const char *) { EXPECT_EQ(status, 0); });
      ASSERT_EQ(first.init(), 0);
      {
        owner_t second(driver, [](int status, const char *) { EXPECT_EQ(status, 0); });
        ASSERT_EQ(second.init(), 0);
        EXPECT_EQ(driver.refs, 2);
      }
      EXPECT_EQ(driver.refs, 1);
      EXPECT_EQ(driver.stack, (std::vector<void *>{&driver.token}));
    }
    EXPECT_EQ(driver.refs, 0);
    EXPECT_TRUE(driver.stack.empty());
  }

  TEST(CudaPrimaryContext, UninitializedOwnerHasNoSideEffects) {
    driver_t driver;
    { owner_t context(driver, [](int, const char *) { FAIL(); }); }
    EXPECT_TRUE(driver.calls.empty());
  }

  TEST(CudaPrimaryContext, AcquisitionFailuresUnwindOnlyOwnedResources) {
    for (const auto *boundary : {"current", "default-device", "retain", "push"}) {
      SCOPED_TRACE(boundary);
      driver_t driver;
      driver.fail = boundary;
      {
        owner_t context(driver, [](int status, const char *) { EXPECT_EQ(status, 0); });
        EXPECT_EQ(context.init(), 17);
      }
      EXPECT_EQ(driver.refs, 0);
      EXPECT_TRUE(driver.stack.empty());
      EXPECT_EQ(std::count(driver.calls.begin(), driver.calls.end(), "release"), std::string(boundary) == "push" ? 1 : 0);
      EXPECT_EQ(std::count(driver.calls.begin(), driver.calls.end(), "pop"), 0);
    }
  }

  TEST(CudaPrimaryContext, CurrentDeviceLookupFailurePreservesCaller) {
    driver_t driver;
    driver.stack.push_back(&driver.other);
    driver.fail = "context-device";
    {
      owner_t context(driver, [](int, const char *) { FAIL(); });
      EXPECT_EQ(context.init(), 17);
    }
    EXPECT_EQ(driver.stack, (std::vector<void *>{&driver.other}));
    EXPECT_EQ(driver.refs, 0);
  }

  TEST(CudaPrimaryContext, ReportsCleanupFailureAndStillReleasesReference) {
    driver_t driver;
    std::vector<int> statuses;
    {
      owner_t context(driver, [&](int status, const char *) { statuses.push_back(status); });
      ASSERT_EQ(context.init(), 0);
      driver.fail = "pop";
    }
    EXPECT_EQ(statuses, (std::vector<int>{17, 0}));
    EXPECT_EQ(driver.refs, 0);
  }

  TEST(CudaPrimaryContext, RepeatedReplacementLeavesNoReferenceOrBinding) {
    driver_t driver;
    for (int iteration = 0; iteration != 100; ++iteration) {
      owner_t context(driver, [](int status, const char *) { EXPECT_EQ(status, 0); });
      ASSERT_EQ(context.init(), 0);
      EXPECT_EQ(driver.refs, 1);
      EXPECT_EQ(driver.stack.size(), 1);
    }
    EXPECT_EQ(driver.refs, 0);
    EXPECT_TRUE(driver.stack.empty());
  }
}  // namespace
