/**
 * @file tests/unit/test_nvfbc_capture_retry.cpp
 * @brief Cover capture readiness during first-login display modesets.
 */
#include <gtest/gtest.h>
#include <src/platform/linux/nvfbc_capture_retry.h>

using namespace std::chrono_literals;

TEST(NvfbcCaptureRetry, ModesetWaitDoesNotSlideItsDeadline) {
  nvfbc::capture_start_retry_t retry;
  const std::chrono::steady_clock::time_point start {};
  const char *reason = "Cannot create capture session: the display server is in modeset";
  EXPECT_TRUE(retry.retry(reason, start));
  EXPECT_TRUE(retry.retry(reason, start + 100ms));
  EXPECT_TRUE(retry.retry(reason, start + 4999ms));
  EXPECT_FALSE(retry.retry(reason, start + 5s));
  EXPECT_FALSE(retry.retry(reason, start + 10s));
}

TEST(NvfbcCaptureRetry, RealFailuresDoNotBecomePendingCapture) {
  nvfbc::capture_start_retry_t retry;
  const std::chrono::steady_clock::time_point start {};
  for (const auto *reason : {"", "Invalid handle", "X server terminated", "Out of memory", "Unsupported capture mode"}) {
    EXPECT_FALSE(retry.retry(reason, start));
  }
  EXPECT_TRUE(retry.retry("display server is in modeset", start));
  EXPECT_FALSE(retry.retry("Unable to register an OpenGL buffer", start + 1ms));
}

TEST(NvfbcCaptureRetry, SuccessfulCreationResetsTheNextModesetBudget) {
  nvfbc::capture_start_retry_t retry;
  const std::chrono::steady_clock::time_point start {};
  const char *reason = "Cannot create capture session: the display server is in modeset";
  EXPECT_TRUE(retry.retry(reason, start));
  retry.reset();
  EXPECT_TRUE(retry.retry(reason, start + 1h));
  EXPECT_TRUE(retry.retry(reason, start + 1h + 4999ms));
  EXPECT_FALSE(retry.retry(reason, start + 1h + 5s));
}
