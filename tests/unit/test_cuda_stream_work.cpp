/**
 * @file tests/unit/test_cuda_stream_work.cpp
 * @brief Prove failed GPU submissions finish before borrowed frame reuse.
 */
#include "src/platform/linux/cuda_stream_work.h"

#include <gtest/gtest.h>
#include <vector>

namespace {
  /** @brief Stateful asynchronous stream fake with a borrowed source frame. */
  struct stream_api_t {
    int pending = 0;  ///< Work still referencing the caller's frame.
    int barriers = 0;  ///< Completed synchronization attempts.
    int status = 0;  ///< Injected synchronization result.
    bool source_alive = true;  ///< Whether the frame is still valid.

    /** @brief Complete submitted work while its source remains valid. */
    int cuStreamSynchronize(int stream) {
      EXPECT_EQ(stream, 42);
      EXPECT_TRUE(source_alive);
      ++barriers;
      pending = 0;
      return status;
    }
  };

  /** @brief Caller-owned input whose destruction must follow GPU completion. */
  struct frame_t {
    stream_api_t &api;  ///< Stream that may still borrow this frame.

    /** @brief Reject releasing an input frame while GPU work can still read it. */
    ~frame_t() {
      EXPECT_EQ(api.pending, 0);
      api.source_alive = false;
    }
  };

  /**
   * @brief Exercise the production work guard with partial asynchronous submissions.
   * @param api Stream whose work borrows the caller's frame.
   * @param submissions Number of queued upload/conversion operations.
   * @param fail Whether dispatch fails before the normal completion barrier.
   * @param cleanup_statuses Results reported by the early-return path.
   * @return Original dispatch error, or the normal synchronization result.
   */
  int convert(stream_api_t &api, int submissions, bool fail, std::vector<int> &cleanup_statuses) {
    cuda::stream_work_t work(api, 42, [&](int status) {
      cleanup_statuses.push_back(status);
    });
    api.pending += submissions;
    if (fail) {
      return 17;
    }
    return work.synchronize();
  }

  TEST(CudaStreamWork, FailedUploadIsDrainedBeforeCallerCanFreeInput) {
    stream_api_t api;
    std::vector<int> statuses;
    {
      frame_t frame {api};
      EXPECT_EQ(convert(api, 1, true, statuses), 17);
      EXPECT_EQ(api.pending, 0);
    }
    EXPECT_EQ(api.barriers, 1);
    EXPECT_EQ(statuses, (std::vector<int> {0}));
  }

  TEST(CudaStreamWork, PartialKernelFailureIsDrainedBeforeFrameReuse) {
    stream_api_t api;
    std::vector<int> statuses;
    frame_t frame {api};
    EXPECT_EQ(convert(api, 3, true, statuses), 17);
    EXPECT_EQ(api.pending, 0);
    EXPECT_EQ(convert(api, 2, false, statuses), 0);
    EXPECT_EQ(api.pending, 0);
    EXPECT_EQ(api.barriers, 2);
    EXPECT_EQ(statuses.size(), 1);
  }

  TEST(CudaStreamWork, NormalCompletionDoesNotInsertASecondBarrier) {
    stream_api_t api;
    std::vector<int> statuses;
    frame_t frame {api};
    EXPECT_EQ(convert(api, 2, false, statuses), 0);
    EXPECT_EQ(api.barriers, 1);
    EXPECT_TRUE(statuses.empty());
  }

  TEST(CudaStreamWork, NormalSynchronizationFailureIsReturnedToCaller) {
    stream_api_t api;
    api.status = 31;
    std::vector<int> statuses;
    frame_t frame {api};
    EXPECT_EQ(convert(api, 2, false, statuses), 31);
    EXPECT_EQ(api.barriers, 1);
    EXPECT_TRUE(statuses.empty());
  }

  TEST(CudaStreamWork, CleanupFailureIsReportedWithoutReplacingDispatchFailure) {
    stream_api_t api;
    api.status = 31;
    std::vector<int> statuses;
    frame_t frame {api};
    EXPECT_EQ(convert(api, 2, true, statuses), 17);
    EXPECT_EQ(api.barriers, 1);
    EXPECT_EQ(statuses, (std::vector<int> {31}));
  }
}  // namespace
