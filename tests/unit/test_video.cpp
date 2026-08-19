/**
 * @file tests/unit/test_video.cpp
 * @brief Test src/video.*.
 */
// test includes
#include "../tests_common.h"

// standard includes
#include <algorithm>
#include <tuple>
#include <utility>

// local includes
#include <src/config.h>
#if defined(__linux__) && defined(SUNSHINE_BUILD_CUDA)
  #include <src/platform/linux/cuda.h>
#endif
#include <src/video.h>
#include <src/video_colorspace.h>

using namespace std::literals;

TEST(VideoColorspaceTest, IdentityGbrUsesExactPlaneMapping) {
  const video::sunshine_colorspace_t colorspace {
    video::colorspace_e::identity_gbr,
    true,
    10,
  };

  const auto *unorm = video::color_vectors_from_colorspace(colorspace, true);
  EXPECT_FLOAT_EQ(unorm->color_vec_y[0], 0.0f);
  EXPECT_FLOAT_EQ(unorm->color_vec_y[1], 1.0f);
  EXPECT_FLOAT_EQ(unorm->color_vec_y[2], 0.0f);
  EXPECT_FLOAT_EQ(unorm->color_vec_u[0], 0.0f);
  EXPECT_FLOAT_EQ(unorm->color_vec_u[1], 0.0f);
  EXPECT_FLOAT_EQ(unorm->color_vec_u[2], 1.0f);
  EXPECT_FLOAT_EQ(unorm->color_vec_v[0], 1.0f);
  EXPECT_FLOAT_EQ(unorm->color_vec_v[1], 0.0f);
  EXPECT_FLOAT_EQ(unorm->color_vec_v[2], 0.0f);

  const auto *integer = video::color_vectors_from_colorspace(colorspace, false);
  EXPECT_FLOAT_EQ(integer->color_vec_y[1], 1023.0f);
  EXPECT_FLOAT_EQ(integer->color_vec_u[2], 1023.0f);
  EXPECT_FLOAT_EQ(integer->color_vec_v[0], 1023.0f);
}

TEST(VideoColorspaceTest, IdentityGbrUsesMatrixZeroMetadata) {
  const video::sunshine_colorspace_t colorspace {
    video::colorspace_e::identity_gbr,
    true,
    10,
  };

  const auto avcodec = video::avcodec_colorspace_from_sunshine_colorspace(colorspace);
  EXPECT_EQ(avcodec.primaries, AVCOL_PRI_BT709);
  EXPECT_EQ(avcodec.transfer_function, AVCOL_TRC_IEC61966_2_1);
  EXPECT_EQ(avcodec.matrix, AVCOL_SPC_RGB);
  EXPECT_EQ(avcodec.range, AVCOL_RANGE_JPEG);
  EXPECT_FALSE(video::colorspace_is_hdr(colorspace));
}

TEST(VideoColorspaceTest, IdentityGbrRequiresFullRange10Bit444) {
  video::config_t config {};
  config.encoderCscMode = COLORSPACE_IDENTITY_GBR << 1;
  config.dynamicRange = 1;
  config.chromaSamplingType = 1;
  EXPECT_EQ(video::colorspace_from_client_config(config, false).colorspace, video::colorspace_e::rec709);

  config.encoderCscMode |= 1;
  config.dynamicRange = 0;
  EXPECT_EQ(video::colorspace_from_client_config(config, false).colorspace, video::colorspace_e::rec709);

  config.dynamicRange = 1;
  config.chromaSamplingType = 0;
  EXPECT_EQ(video::colorspace_from_client_config(config, false).colorspace, video::colorspace_e::rec709);

  config.chromaSamplingType = 1;
  EXPECT_EQ(video::colorspace_from_client_config(config, false).colorspace, video::colorspace_e::identity_gbr);
}

#if defined(__linux__) && defined(SUNSHINE_BUILD_CUDA)
TEST(VideoColorspaceTest, IdentityGbrCudaKernelProducesExact10BitPlanes) {
  EXPECT_TRUE(cuda::test_identity_gbr_10bit_conversion());
}
#endif

struct EncoderTest: PlatformTestSuite, testing::WithParamInterface<video::encoder_t *> {
  void SetUp() override {
    BaseTest::SetUp();
    auto &encoder = *GetParam();
    if (!video::validate_encoder(encoder, false)) {
      // Encoder failed validation,
      // if it's software - fail, otherwise skip
      if (encoder.name == "software") {
        FAIL() << "Software encoder not available";
      } else {
        GTEST_SKIP() << "Encoder not available";
      }
    }
  }
};

INSTANTIATE_TEST_SUITE_P(
  EncoderVariants,
  EncoderTest,
  testing::Values(
#if !defined(__APPLE__)
    &video::nvenc,
#endif
#ifdef _WIN32
    &video::amdvce,
    &video::quicksync,
#endif
#if defined(__linux__) || defined(__FreeBSD__)
    &video::vaapi,
#endif
#ifdef __APPLE__
    &video::videotoolbox,
#endif
    &video::software
  ),
  [](const auto &info) {
    return std::string(info.param->name);
  }
);

TEST_P(EncoderTest, ValidateEncoder) {
  // todo:: test something besides fixture setup
}

/**
 * @brief Parameterized coverage for effective H.264 profile selection.
 */
struct H264ProfileTest: testing::TestWithParam<std::tuple<std::string_view, video::amf::coder_e, int, int>> {};

TEST_P(H264ProfileTest, SelectProfile) {
  const auto &[encoder_name, coder, chroma_sampling_type, expected_profile] = GetParam();
  video::config_t config {};
  config.chromaSamplingType = chroma_sampling_type;

  EXPECT_EQ(expected_profile, video::select_h264_profile(encoder_name, config, std::to_underlying(coder)));
}

INSTANTIATE_TEST_SUITE_P(
  H264ProfileTests,
  H264ProfileTest,
  testing::Values(
    std::make_tuple("h264_amf"sv, video::amf::coder_e::auto_, 0, AV_PROFILE_H264_HIGH),
    std::make_tuple("h264_amf"sv, video::amf::coder_e::cabac, 0, AV_PROFILE_H264_HIGH),
    std::make_tuple("h264_amf"sv, video::amf::coder_e::cavlc, 0, AV_PROFILE_H264_CONSTRAINED_BASELINE),
    std::make_tuple("h264_amf"sv, video::amf::coder_e::cavlc, 1, AV_PROFILE_H264_HIGH_444_PREDICTIVE),
    std::make_tuple("h264_nvenc"sv, video::amf::coder_e::cavlc, 0, AV_PROFILE_H264_HIGH)
  )
);

#ifdef _WIN32
TEST(AmfH264OptionsTest, CoderUsesConfiguredValue) {
  const auto coder_option = std::ranges::find(video::amdvce.h264.common_options, "coder"sv, &video::encoder_t::option_t::name);

  ASSERT_NE(video::amdvce.h264.common_options.end(), coder_option);
  ASSERT_TRUE(std::holds_alternative<int *>(coder_option->value));
  EXPECT_EQ(&config::video.amd.amd_coder, std::get<int *>(coder_option->value));
}
#endif

struct FramerateX100Test: BaseTest, testing::WithParamInterface<std::tuple<std::int32_t, AVRational>> {};

TEST_P(FramerateX100Test, Run) {
  const auto &[x100, expected] = GetParam();
  auto res = video::framerateX100_to_rational(x100);
  ASSERT_EQ(0, av_cmp_q(res, expected)) << "expected "
                                        << expected.num << "/" << expected.den
                                        << ", got "
                                        << res.num << "/" << res.den;
}

INSTANTIATE_TEST_SUITE_P(
  FramerateX100Tests,
  FramerateX100Test,
  testing::Values(
    std::make_tuple(2397, AVRational {24000, 1001}),
    std::make_tuple(2398, AVRational {24000, 1001}),
    std::make_tuple(2500, AVRational {25, 1}),
    std::make_tuple(2997, AVRational {30000, 1001}),
    std::make_tuple(3000, AVRational {30, 1}),
    std::make_tuple(5994, AVRational {60000, 1001}),
    std::make_tuple(6000, AVRational {60, 1}),
    std::make_tuple(11988, AVRational {120000, 1001}),
    std::make_tuple(23976, AVRational {240000, 1001}),  // future NTSC 240hz?
    std::make_tuple(9498, AVRational {4749, 50})  // from my LG 27GN950
  )
);

struct FramerateToRationalTest: testing::TestWithParam<std::tuple<int, int, AVRational>> {};

TEST_P(FramerateToRationalTest, Run) {
  const auto &[framerate, framerateX100, expected] = GetParam();
  video::config_t config {};
  config.framerate = framerate;
  config.framerateX100 = framerateX100;
  auto res = video::framerate_to_rational(config);
  ASSERT_EQ(0, av_cmp_q(res, expected)) << "expected "
                                        << expected.num << "/" << expected.den
                                        << ", got "
                                        << res.num << "/" << res.den;
}

INSTANTIATE_TEST_SUITE_P(
  FramerateToRationalTests,
  FramerateToRationalTest,
  testing::Values(
    std::make_tuple(60, 0, AVRational {60, 1}),  // no X100 value, fall back to integer framerate
    std::make_tuple(60, 5994, AVRational {60000, 1001}),
    std::make_tuple(120, 11988, AVRational {120000, 1001}),
    std::make_tuple(24, 2398, AVRational {24000, 1001})
  )
);

struct CaptureFrameIntervalTest: testing::TestWithParam<std::tuple<int, int, std::chrono::nanoseconds>> {};

TEST_P(CaptureFrameIntervalTest, Run) {
  const auto &[framerate, framerateX100, expected] = GetParam();
  video::config_t config {};
  config.framerate = framerate;
  config.framerateX100 = framerateX100;
  ASSERT_EQ(expected, video::capture_frame_interval(config));
}

INSTANTIATE_TEST_SUITE_P(
  CaptureFrameIntervalTests,
  CaptureFrameIntervalTest,
  testing::Values(
    std::make_tuple(60, 0, std::chrono::nanoseconds {16666666}),
    std::make_tuple(60, 5994, std::chrono::nanoseconds {16683333}),  // 1e9 * 1001 / 60000
    std::make_tuple(120, 11988, std::chrono::nanoseconds {8341666})  // 1e9 * 1001 / 120000
  )
);
