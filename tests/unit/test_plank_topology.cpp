/**
 * @file tests/unit/test_plank_topology.cpp
 * @brief Tests for exact PLANK host-layout binding.
 */
#include "src/plank_topology.h"

#include "src/plank_arrangement_json.h"
#include "src/plank_topology_json.h"

#include <fstream>
#include <iterator>
#include <set>

#include <gtest/gtest.h>

namespace topology = plank::topology;

TEST(PlankTopology, PublishesVersionThirteenFeatureContract) {
  EXPECT_EQ(topology::protocol_version, 13U);
#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)
  EXPECT_EQ(topology::feature_flags, 0x6C7FFFFU);
  EXPECT_NE(topology::feature_flags & topology::feature_clipboard_sync, 0U);
  EXPECT_EQ(topology::feature_platform_file_clipboard,
            topology::feature_file_clipboard);
#else
  EXPECT_EQ(topology::feature_flags, 0x647FFFFU);
  EXPECT_EQ(topology::feature_flags & topology::feature_clipboard_sync, 0U);
  EXPECT_EQ(topology::feature_platform_file_clipboard, 0U);
#endif
  EXPECT_EQ(topology::feature_flags & topology::feature_file_clipboard, 0U);
  EXPECT_NE(topology::feature_flags & topology::feature_nvfbc_nvenc_420, 0U);
  EXPECT_NE(topology::feature_flags & topology::feature_desktop_sign_out, 0U);
  EXPECT_EQ(topology::feature_nvfbc_nvenc_420, 0x2000000U);
  EXPECT_NE(topology::feature_flags & topology::feature_notch_safe_laptop_modes, 0U);
  EXPECT_EQ(topology::feature_notch_safe_laptop_modes, 0x4000000U);
  EXPECT_NE(topology::feature_flags & topology::feature_nvfbc_hevc10_nvenc, 0U);
  EXPECT_NE(topology::feature_flags & topology::feature_fixed_transport_mtu, 0U);
  EXPECT_NE(topology::feature_flags & topology::feature_session_takeover, 0U);
  EXPECT_TRUE(topology::valid_virtual_mode("1024x2160"));
  EXPECT_TRUE(topology::valid_virtual_mode("2560x2160"));
  EXPECT_TRUE(topology::valid_virtual_mode("4096x2160"));
  EXPECT_TRUE(topology::valid_virtual_mode("5120x2160"));
  EXPECT_FALSE(topology::valid_virtual_mode("1280x720"));
  EXPECT_FALSE(topology::valid_virtual_mode("1280x1024"));
  EXPECT_TRUE(topology::valid_virtual_layout_modes(
    "dual-horizontal", "4096x2160", "1024x2160"
  ));
  EXPECT_TRUE(topology::valid_virtual_layout_modes(
    "dual-horizontal", "4096x2160", "1280x2160"
  ));
  EXPECT_TRUE(topology::valid_virtual_layout_modes(
    "dual-horizontal", "4096x2160", "4096x2160"
  ));
}

TEST(PlankTopology, OffersNotchSafeLaptopModesOnlyWhenNegotiated) {
  const auto size = topology::virtual_mode_size("3024x1890");
  EXPECT_EQ(size.width, 3024);
  EXPECT_EQ(size.height, 1890);
  EXPECT_TRUE(topology::valid_virtual_mode("3024x1890"));
  // The panel size is not a mode: fullscreen stops at the camera housing.
  EXPECT_FALSE(topology::valid_virtual_mode("3024x1964"));
  EXPECT_TRUE(topology::valid_virtual_layout_modes(
    "dual-horizontal", "3024x1890", "5120x2160"
  ));

  constexpr auto without = topology::feature_flags &
    ~topology::feature_notch_safe_laptop_modes;
  EXPECT_TRUE(topology::virtual_modes_negotiated(
    topology::feature_flags, "3024x1890", ""
  ));
  EXPECT_TRUE(topology::virtual_modes_negotiated(
    topology::feature_flags, "3840x2160", "3024x1890"
  ));
  EXPECT_FALSE(topology::virtual_modes_negotiated(without, "3024x1890", ""));
  EXPECT_FALSE(topology::virtual_modes_negotiated(without, "3840x2160", "3024x1890"));
  EXPECT_TRUE(topology::virtual_modes_negotiated(without, "2560x1600", ""));
  EXPECT_TRUE(topology::virtual_modes_negotiated(without, "", ""));
}

TEST(PlankTopology, AcceptsOnlyValidFixedQuicPayloadCeilings) {
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(1200));
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(1344));
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(1452));
  EXPECT_TRUE(topology::valid_quic_udp_payload_mtu(65527));
  EXPECT_FALSE(topology::valid_quic_udp_payload_mtu(0));
  EXPECT_FALSE(topology::valid_quic_udp_payload_mtu(1199));
  EXPECT_FALSE(topology::valid_quic_udp_payload_mtu(65528));
}

TEST(PlankTopology, AcceptsOnlyExactEncodingTuples) {
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "software-cuda", "h264-10-444-software"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "h264-8-444-nvenc"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "hevc-8-444-nvenc"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "hevc-10-444-nvenc"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "x11-native10", "software-cuda", "h264-10-444-software"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "x11-native10", "nvenc-direct", "hevc-10-444-nvenc"
  ));

  EXPECT_FALSE(topology::valid_encoding_tuple(
    "x11-native10", "nvenc-direct", "hevc-8-444-nvenc"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "x11-native10", "software-cuda", "h264-8-444-software"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "nvfbc", "software-cuda", "hevc-8-444-nvenc"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "nvfbc", "ffmpeg-nvenc", "h264-8-444-nvenc"
  ));
}

TEST(PlankTopology, AcceptsNvenc420OnlyFromNvfbcDirectNvenc) {
  EXPECT_TRUE(topology::nvenc_420_mode("h264-8-420-nvenc"));
  EXPECT_TRUE(topology::nvenc_420_mode("hevc-10-420-nvenc"));
  EXPECT_FALSE(topology::nvenc_420_mode("hevc-8-420-nvenc"));
  EXPECT_FALSE(topology::nvenc_420_mode("h264-10-420-nvenc"));
  EXPECT_FALSE(topology::nvenc_420_mode("hevc-10-420-videotoolbox"));
  EXPECT_FALSE(topology::nvenc_420_mode("hevc-10-444-nvenc"));
  EXPECT_EQ(topology::nvenc_420_encoder_csc_mode, 2);

  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "h264-8-420-nvenc"
  ));
  EXPECT_TRUE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "hevc-10-420-nvenc"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "x11-native10", "nvenc-direct", "hevc-10-420-nvenc"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "x11-native10", "nvenc-direct", "h264-8-420-nvenc"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "nvfbc", "software-cuda", "h264-8-420-nvenc"
  ));
  EXPECT_FALSE(topology::valid_encoding_tuple(
    "nvfbc", "nvenc-direct", "hevc-8-420-nvenc"
  ));
}

TEST(PlankTopology, AcceptsExactQualifiedLayouts) {
  EXPECT_EQ(topology::validate_layout_binding(
              "physical", "", "", "physical", "", "", 1),
            topology::layout_error::none);
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "4096x2160", "", "single", "4096x2160", "", 1),
            topology::layout_error::none);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "3840x2160", "1280x2160",
              "dual-horizontal", "3840x2160", "1280x2160", 2),
            topology::layout_error::none);
}

TEST(PlankTopology, EnforcesAdministratorDisplayPolicy) {
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("physical", "physical"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("single", "physical"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("dual-horizontal", "physical"));
  EXPECT_FALSE(topology::layout_allowed_by_startup_layout("physical", "single"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("single", "single"));
  EXPECT_TRUE(topology::layout_allowed_by_startup_layout("dual-horizontal", "single"));
  EXPECT_FALSE(topology::layout_allowed_by_startup_layout("dual-vertical", "physical"));
}

TEST(PlankTopology, RejectsMismatchBeforeLaunchState) {
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "1920x1080", "",
              "dual-horizontal", "1920x1080", "1024x2160", 2),
            topology::layout_error::mismatch);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "3840x2160", "1280x2160",
              "dual-horizontal", "3840x2160", "1024x2160", 2),
            topology::layout_error::mismatch);
}

TEST(PlankTopology, RejectsInvalidAndUnhealthyLayouts) {
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-vertical", "1920x1080", "",
              "dual-horizontal", "1920x1080", "1280x2160", 2),
            topology::layout_error::invalid_request);
  EXPECT_EQ(topology::validate_layout_binding(
              "physical", "1920x1080", "", "physical", "", "", 1),
            topology::layout_error::invalid_request);
  EXPECT_EQ(topology::validate_layout_binding(
              "dual-horizontal", "1920x1080", "1280x2160",
              "dual-horizontal", "1920x1080", "1280x2160", 1),
            topology::layout_error::unhealthy);
  EXPECT_EQ(topology::validate_layout_binding(
              "single", "1920x1080", "1280x2160",
              "single", "1920x1080", "", 1),
            topology::layout_error::invalid_request);
}

TEST(PlankTopology, RefusesPhysicalLeasesWithTooFewScanouts) {
  EXPECT_EQ(topology::layout_output_count("single"), 1U);
  EXPECT_EQ(topology::layout_output_count("dual-horizontal"), 2U);
  EXPECT_EQ(topology::layout_output_count("physical"), 0U);
  EXPECT_EQ(topology::layout_output_count("dual-vertical"), 0U);

  // A one-panel laptop host still advertises dual-horizontal (the deployed
  // 1.0.129 client requires the exact allowed-kinds list), so the binding
  // must answer 409 instead of starting a transition that cannot succeed.
  EXPECT_TRUE(topology::physical_lease_feasible("single", 1));
  EXPECT_FALSE(topology::physical_lease_feasible("dual-horizontal", 1));
  EXPECT_TRUE(topology::physical_lease_feasible("dual-horizontal", 2));
  EXPECT_TRUE(topology::physical_lease_feasible("physical", 1));
  EXPECT_FALSE(topology::physical_lease_feasible("physical", 0));
  EXPECT_FALSE(topology::physical_lease_feasible("single", 0));
  EXPECT_FALSE(topology::physical_lease_feasible("dual-vertical", 4));
}

namespace {
  nlohmann::json arrangement_topology_vector() {
    std::ifstream input {std::string {SUNSHINE_SOURCE_DIR} +
                         "/tests/fixtures/protocol/output-topology-v13-arrangement.json"};
    return nlohmann::json::parse(input);
  }

  std::vector<topology::document_output_t> vector_outputs(const nlohmann::json &document) {
    std::vector<topology::document_output_t> outputs;
    for (const auto &output : document.at("outputs")) {
      outputs.push_back({
        output.at("id"), output.at("name"), output.at("x"), output.at("y"), output.at("width"),
        output.at("height"), output.at("rotation"), output.at("refresh_millihz"), output.at("primary"),
      });
    }
    return outputs;
  }

  std::set<std::string> keys(const nlohmann::json &object) {
    std::set<std::string> result;
    for (const auto &[key, value] : object.items()) result.insert(key);
    return result;
  }
}  // namespace

TEST(PlankTopology, GatesTheArrangementFeaturePerHost) {
  EXPECT_EQ(topology::feature_display_arrangement, 0x8000000U);
  EXPECT_EQ(topology::feature_flags & topology::feature_display_arrangement, 0U);
  EXPECT_TRUE(topology::display_arrangement_advertised("physical", "physical", 1));
  EXPECT_TRUE(topology::display_arrangement_advertised("hybrid", "hybrid", 4));
  EXPECT_FALSE(topology::display_arrangement_advertised("virtual", "virtual", 2));
  EXPECT_FALSE(topology::display_arrangement_advertised("hybrid", "physical", 1));
  EXPECT_FALSE(topology::display_arrangement_advertised("physical", "", 1));
  EXPECT_FALSE(topology::display_arrangement_advertised("physical", "physical", 0));
}

TEST(PlankTopology, RefusesStreamsLargerThanTheEncoder) {
  EXPECT_TRUE(topology::stream_size_fits(4096, 2160, 4096, 4096));
  EXPECT_FALSE(topology::stream_size_fits(6864, 2160, 4096, 4096));
  EXPECT_TRUE(topology::stream_size_fits(7680, 4320, 8192, 8192));
  EXPECT_FALSE(topology::stream_size_fits(8194, 2160, 8192, 8192));
}

TEST(PlankTopology, PublishesTheArrangementVectorExactly) {
  const auto expected = arrangement_topology_vector();
  topology::document_layout_t layout {
    "physical", false, {}, "physical", {"physical", "single", "dual-horizontal"},
  };
  topology::arrangement_view_t view;
  view.startup_policy = "hybrid";
  view.request = "1:3024x1890+0+270:auto,3840x2160+3024+0:auto";
  view.state = "applied";
  view.outputs = {{"x11:DP-0", {"virtual", 0}}, {"x11:HDMI-0", {"physical", 1}}};
  view.lease = true;
  const auto capabilities = plank::arrangement::capabilities_from_json(expected.at("display_capabilities"));
  ASSERT_TRUE(capabilities);
  view.capabilities = *capabilities;
  const auto document = topology::topology_document(
    topology::protocol_version, expected.at("feature_flags"), vector_outputs(expected), layout, view,
    expected.at("generation")
  );
  EXPECT_EQ(document, expected);
}

TEST(PlankTopology, KeepsTheLegacyContractWithoutTheBit) {
  const auto vector = arrangement_topology_vector();
  topology::document_layout_t layout {
    "physical", false, {}, "physical", {"physical", "single", "dual-horizontal"},
  };
  const auto document = topology::topology_document(
    topology::protocol_version, topology::feature_flags, vector_outputs(vector), layout,
    std::nullopt, "x11:0000000000000000"
  );
  EXPECT_EQ(keys(document), (std::set<std::string> {
    "schema_version", "feature_flags", "layout", "outputs", "desktop", "generation",
  }));
  EXPECT_EQ(keys(document.at("layout")), (std::set<std::string> {
    "kind", "virtual", "virtual_modes", "output_count", "startup_kind", "allowed_kinds",
  }));
  for (const auto &output : document.at("outputs")) {
    EXPECT_EQ(keys(output), (std::set<std::string> {
      "id", "name", "x", "y", "width", "height", "rotation", "refresh_millihz", "primary",
      "virtual", "configured_mode", "source_rect",
    }));
  }
  EXPECT_EQ(document.at("desktop"), vector.at("desktop"));

  // During an arrangement lease the legacy fields stay valid for 1.0.129.
  EXPECT_EQ(vector.at("layout").at("kind"), "physical");
  EXPECT_EQ(vector.at("layout").at("virtual"), false);
  EXPECT_TRUE(vector.at("layout").at("virtual_modes").empty());
  EXPECT_EQ(vector.at("layout").at("allowed_kinds"),
            nlohmann::json({"physical", "single", "dual-horizontal"}));
  for (const auto &output : vector.at("outputs")) {
    EXPECT_EQ(output.at("virtual"), false);
    EXPECT_EQ(output.at("configured_mode"), "");
  }

  // A legacy request served by the engine keeps its exact legacy view.
  topology::document_layout_t legacy {
    "dual-horizontal", true, {"3024x1890", "3840x2160"}, "physical",
    {"physical", "single", "dual-horizontal"},
  };
  auto outputs = vector_outputs(vector);
  outputs[0].y = 0;
  const auto served = topology::topology_document(
    topology::protocol_version, topology::feature_flags, outputs, legacy, std::nullopt, "x11:1"
  );
  EXPECT_EQ(served.at("outputs")[0].at("configured_mode"), "3024x1890");
  EXPECT_EQ(served.at("outputs")[1].at("configured_mode"), "3840x2160");
  EXPECT_EQ(served.at("outputs")[1].at("virtual"), true);
}

TEST(PlankTopology, OutsideALeaseEveryOutputIsPhysical) {
  topology::document_layout_t layout {"physical", false, {}, "physical", {"physical", "single", "dual-horizontal"}};
  topology::arrangement_view_t view;
  view.startup_policy = "physical";
  const auto document = topology::topology_document(
    topology::protocol_version, topology::feature_flags | topology::feature_display_arrangement,
    {{"x11:DP-4", "DP-4", 0, 0, 1920, 1080, 0, 60008, true}}, layout, view, "x11:2"
  );
  EXPECT_EQ(document.at("layout").at("arrangement"),
            nlohmann::json({{"request", ""}, {"transition", {{"state", "idle"}, {"reason", ""}}}}));
  EXPECT_EQ(document.at("outputs")[0].at("backing"), "physical");
  EXPECT_EQ(document.at("outputs")[0].at("arrangement_index"), -1);
  EXPECT_TRUE(document.contains("display_capabilities"));
  // No lease, no capture_size; and never the macOS fixed-capture `capture` key.
  EXPECT_FALSE(document.contains("capture_size"));
  EXPECT_FALSE(document.contains("capture"));
  EXPECT_FALSE(document.at("outputs")[0].contains("capture_rect"));
}

TEST(PlankTopology, PublishesAPackedCaptureInCaptureCoordinates) {
  topology::document_layout_t layout {"physical", false, {}, "physical", {"physical", "single", "dual-horizontal"}};
  topology::arrangement_view_t view;
  view.startup_policy = "hybrid";
  view.lease = true;
  view.request = "1:3840x2160+0+0:auto,3840x2160+3840+0:auto,3840x2160+7680+0:auto";
  view.state = "applied";
  view.outputs = {
    {"x11:HDMI-0", {"physical", 0}}, {"x11:DP-0", {"virtual", 1}}, {"x11:DP-2", {"virtual", 2}},
  };
  view.capture_size = std::pair {7680, 4320};
  view.capture_rects = {
    {"x11:HDMI-0", {0, 0, 3840, 2160}}, {"x11:DP-0", {3840, 0, 3840, 2160}}, {"x11:DP-2", {0, 2160, 3840, 2160}},
  };
  const auto document = topology::topology_document(
    topology::protocol_version, topology::feature_flags | topology::feature_display_arrangement,
    {
      {"x11:HDMI-0", "HDMI-0", 0, 0, 3840, 2160, 0, 60000, true},
      {"x11:DP-0", "DP-0", 3840, 0, 3840, 2160, 0, 60000, false},
      {"x11:DP-2", "DP-2", 7680, 0, 3840, 2160, 0, 60000, false},
    },
    layout, view, "x11:3:packed-0123456789abcdef"
  );
  // The desktop keeps the requested positions; only the video is packed.
  EXPECT_EQ(document.at("desktop"), nlohmann::json({{"x", 0}, {"y", 0}, {"width", 11520}, {"height", 2160}}));
  EXPECT_EQ(document.at("capture_size"), nlohmann::json({{"width", 7680}, {"height", 4320}}));
  EXPECT_EQ(document.at("outputs")[2].at("x"), 7680);
  EXPECT_EQ(document.at("outputs")[2].at("capture_rect"),
            nlohmann::json({{"x", 0}, {"y", 2160}, {"width", 3840}, {"height", 2160}}));
  EXPECT_EQ(document.at("outputs")[1].at("capture_rect"),
            nlohmann::json({{"x", 3840}, {"y", 0}, {"width", 3840}, {"height", 2160}}));
  // source_rect keeps its schema-13 meaning, inside the desktop, for older parsers.
  EXPECT_EQ(document.at("outputs")[2].at("source_rect"),
            nlohmann::json({{"x", 7680}, {"y", 0}, {"width", 3840}, {"height", 2160}}));
  for (const auto &output : document.at("outputs")) {
    const auto &rect = output.at("source_rect");
    EXPECT_LE(rect.at("x").get<int>() + rect.at("width").get<int>(), 11520);
    EXPECT_LE(rect.at("y").get<int>() + rect.at("height").get<int>(), 2160);
  }
  EXPECT_FALSE(document.contains("capture"));
}
