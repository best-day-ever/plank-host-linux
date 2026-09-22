/**
 * @file tests/unit/test_display_qualify.cpp
 * @brief Command line, refusal rules and report of the supervisor's qualification modes.
 */
#include "src/session/display_qualify.h"

#include <gtest/gtest.h>

namespace display = plank::display;
using run_mode_t = display::supervisor_options_t::run_mode_t;

namespace {
  display::supervisor_options_result_t parse(std::vector<std::string_view> arguments) {
    return display::parse_supervisor_options(arguments);
  }

  display::qualification_preconditions_t allowed() {
    return {true, "hybrid", false, std::nullopt, 1000, false};
  }
}  // namespace

TEST(DisplayQualify, DefaultsToTheSupervisor) {
  const auto plain = parse({});
  ASSERT_TRUE(plain.options);
  EXPECT_EQ(plain.options->mode, run_mode_t::supervise);
  EXPECT_EQ(plain.options->worker, "/usr/bin/plank-host");
  const auto worker = parse({"--worker", "/opt/plank/plank-host"});
  ASSERT_TRUE(worker.options);
  EXPECT_EQ(worker.options->worker, "/opt/plank/plank-host");
  EXPECT_FALSE(parse({"--worker", "plank-host"}).options);
  EXPECT_FALSE(parse({"--worker"}).options);
  EXPECT_FALSE(parse({"--json"}).options);
  EXPECT_FALSE(parse({"--verbose"}).options);
}

TEST(DisplayQualify, ParsesTheQualificationMode) {
  const auto qualify = parse({"--qualify-arrangement", "1:3024x1890+0+270:auto,3840x2160+3024+0:auto"});
  ASSERT_TRUE(qualify.options) << qualify.error;
  EXPECT_EQ(qualify.options->mode, run_mode_t::qualify);
  EXPECT_EQ(qualify.options->request, "1:3024x1890+0+270:auto,3840x2160+3024+0:auto");
  EXPECT_EQ(qualify.options->hold_seconds, 10);
  EXPECT_FALSE(qualify.options->json);

  const auto held = parse({"--hold", "30", "--json", "--qualify-arrangement", "1:3840x2160+0+0:virtual"});
  ASSERT_TRUE(held.options) << held.error;
  EXPECT_EQ(held.options->hold_seconds, 30);
  EXPECT_TRUE(held.options->json);
  EXPECT_EQ(parse({"--qualify-arrangement", "1:3840x2160+0+0:auto", "--hold", "0"}).options->hold_seconds, 0);

  const auto inventory = parse({"--print-inventory", "--json"});
  ASSERT_TRUE(inventory.options);
  EXPECT_EQ(inventory.options->mode, run_mode_t::print_inventory);
  EXPECT_TRUE(inventory.options->json);
}

TEST(DisplayQualify, RefusesInvalidCommandLines) {
  // Only canonical requests; the host checks come later.
  const auto padded = parse({"--qualify-arrangement", "1:03840x2160+0+0:auto"});
  EXPECT_FALSE(padded.options);
  EXPECT_NE(padded.error.find("not_canonical"), std::string::npos);
  EXPECT_FALSE(parse({"--qualify-arrangement", "3840x2160"}).options);
  EXPECT_FALSE(parse({"--qualify-arrangement"}).options);
  for (const auto hold : {"-1", "3601", "010", "", "ten", "1e3"}) {
    EXPECT_FALSE(parse({"--qualify-arrangement", "1:3840x2160+0+0:auto", "--hold", hold}).options) << hold;
  }
  EXPECT_TRUE(parse({"--qualify-arrangement", "1:3840x2160+0+0:auto", "--hold", "3600"}).options);
  EXPECT_FALSE(parse({"--hold", "5"}).options);
  EXPECT_FALSE(parse({"--print-inventory", "--hold", "5"}).options);
  EXPECT_FALSE(parse({"--print-inventory", "--qualify-arrangement", "1:3840x2160+0+0:auto"}).options);
  EXPECT_FALSE(parse({"--worker", "/usr/bin/plank-host", "--print-inventory"}).options);
  EXPECT_FALSE(parse({"--json", "--json", "--print-inventory"}).options);
  EXPECT_FALSE(parse({"--qualify-arrangement", "1:3840x2160+0+0:auto",
                      "--qualify-arrangement", "1:1920x1080+0+0:auto"}).options);
  EXPECT_NE(display::supervisor_usage("plank-host-supervisor").find("--qualify-arrangement REQUEST"),
            std::string::npos);
}

TEST(DisplayQualify, RefusesWhenAStreamOrLeaseOwnsTheDisplay) {
  EXPECT_EQ(display::qualification_refusal(allowed()), "");
  auto preconditions = allowed();
  preconditions.startup_policy = "physical";
  EXPECT_EQ(display::qualification_refusal(preconditions), "");

  preconditions = allowed();
  preconditions.root = false;
  EXPECT_NE(display::qualification_refusal(preconditions).find("root"), std::string::npos);
  preconditions = allowed();
  preconditions.startup_policy = "virtual";
  EXPECT_NE(display::qualification_refusal(preconditions).find("physical or hybrid"), std::string::npos);
  preconditions.startup_policy = "invalid";
  EXPECT_FALSE(display::qualification_refusal(preconditions).empty());
  preconditions = allowed();
  preconditions.display_state_present = true;
  EXPECT_NE(display::qualification_refusal(preconditions).find("lease is active"), std::string::npos);
  preconditions = allowed();
  preconditions.qualification_live = true;
  EXPECT_NE(display::qualification_refusal(preconditions).find("another"), std::string::npos);

  // A running transition blocks; a failed or expired one does not.
  preconditions = allowed();
  preconditions.transition = plank::session::display_transition_t {
    "pending", "", "1:3840x2160+0+0:auto", 1000, 990,
  };
  EXPECT_NE(display::qualification_refusal(preconditions).find("transition"), std::string::npos);
  preconditions.now = 990 + 121;
  EXPECT_EQ(display::qualification_refusal(preconditions), "");
  preconditions.now = 1000;
  preconditions.transition->state = "failed";
  preconditions.transition->reason = "verify_failed";
  EXPECT_EQ(display::qualification_refusal(preconditions), "");
}

TEST(DisplayQualify, ReportsPlanApplyAndRestore) {
  display::arrangement_plan_t plan;
  plan.metamode = "DPY-0: 3840x2160 @3024x1890 +0+0 {ViewPortIn=3024x1890, ViewPortOut=3840x2160+0+0}, DPY-4: NULL";
  plan.primary = "DP-0";
  plan.width = 3024;
  plan.height = 1890;
  plan.outputs = {
    {"HDMI-0", "DPY-4", true, "off", "", -1, {}},
    {"DP-0", "DPY-0", false, "virtual", "3840x2160", 0, {0, 0, 3024, 1890}},
  };
  const auto visibility = display::visibility_arguments(plan, true);
  const auto plan_value = display::plan_json(plan, visibility);
  EXPECT_EQ(plan_value.at("metamode"), plan.metamode);
  EXPECT_EQ(plan_value.at("visibility").size(), visibility.size());
  EXPECT_EQ(plan_value.at("outputs")[1].at("backing"), "virtual");
  EXPECT_EQ(plan_value.at("outputs")[1].at("mode"), "3840x2160");

  display::randr_screen_t screen;
  screen.width = 3024;
  screen.height = 1890;
  screen.outputs.push_back({});
  screen.outputs.back().name = "DP-0";
  screen.outputs.back().connected = true;
  screen.outputs.back().enabled = true;
  screen.outputs.back().primary = true;
  screen.outputs.back().width = 3024;
  screen.outputs.back().height = 1890;
  screen.outputs.back().non_desktop = false;
  screen.outputs.push_back({});
  screen.outputs.back().name = "HDMI-0";
  screen.outputs.back().non_desktop = true;
  const auto screen_value = display::screen_json(screen);
  EXPECT_EQ(screen_value.at("outputs")[0].at("non_desktop"), 0);
  EXPECT_EQ(screen_value.at("outputs")[1].at("non_desktop"), 1);

  nlohmann::json report {
    {"mode", "qualify-arrangement"},
    {"request", "1:3024x1890+0+0:auto"},
    {"session", {{"id", "c1"}, {"class", "greeter"}, {"uid", 42}, {"display", ":0"}}},
    {"plan", plan_value},
    {"apply", {{"result", "ok"}, {"attempts", 1}, {"screen", screen_value}}},
    {"hold_seconds", 10},
    {"restore", {{"metamode_exact", true}, {"visibility_exact", true}, {"fallback", false}}},
    {"success", true},
  };
  const auto text = display::report_text(report);
  EXPECT_NE(text.find("metamode: " + plan.metamode), std::string::npos);
  EXPECT_NE(text.find("DP-0 (DPY-0): virtual 3840x2160 -> 3024x1890+0+0 entry 0"), std::string::npos);
  EXPECT_NE(text.find("HDMI-0 (DPY-4): off"), std::string::npos);
  EXPECT_NE(text.find("apply: ok after 1 attempt(s)"), std::string::npos);
  EXPECT_NE(text.find("DP-0: 3024x1890+0+0 primary non-desktop 0"), std::string::npos);
  EXPECT_NE(text.find("restore: metamode exact, visibility exact"), std::string::npos);
  EXPECT_NE(text.find("result: PASS"), std::string::npos);
}

TEST(DisplayQualify, ReportsTheInventory) {
  display::inventory_t inventory;
  inventory.fingerprint = std::string(64, 'a');
  inventory.gpu_bus_id = "PCI:1:0:0";
  inventory.driver_version = "580.159.04";
  inventory.startup_policy = "hybrid";
  inventory.physical.push_back({{"DFP-4", "DPY-4", "HDMI-0", "Connector-3"}, "MEC-O-3-H", "", "3840x2160",
                                {"3840x2160", "1920x1080"}});
  inventory.virtual_candidates.push_back({{"DFP-0", "DPY-0", "DP-0", "Connector-1"}, {}, {}, {}, {}});
  inventory.virtual_heads = 1;
  const auto value = display::inventory_json(inventory);
  EXPECT_EQ(value.at("physical")[0].at("display_name"), "MEC-O-3-H");
  EXPECT_FALSE(value.at("virtual_candidates")[0].contains("modes"));
  const auto text = display::report_text({{"inventory", value}});
  EXPECT_NE(text.find("physical HDMI-0 DFP-4/DPY-4 \"MEC-O-3-H\" preferred 3840x2160, modes 2"),
            std::string::npos);
  EXPECT_NE(text.find("virtual DP-0 DFP-0/DPY-0 Connector-1 (reserved head)"), std::string::npos);
}
