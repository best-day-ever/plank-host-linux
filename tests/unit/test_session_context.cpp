/**
 * @file tests/unit/test_session_context.cpp
 * @brief Security policy tests for PLANK logind session selection.
 */
#include <gtest/gtest.h>

#include "src/session/session_context.h"

#include <cstdlib>

#include <unistd.h>

namespace session = plank::session;

namespace {
  session::descriptor_t valid_session() {
    return {
      "c7",
      1000,
      "seat0",
      "x11",
      "user",
      "active",
      true,
      false,
    };
  }

  session::update_t valid_update() {
    return {
      7,
      valid_session(),
      {":0", "/run/user/1000/gdm/Xauthority", "/run/user/1000",
       "unix:path=/run/user/1000/bus", "unix:/run/user/1000/pulse/native",
       "/home/test/.config/pulse/cookie"},
    };
  }
}  // namespace

TEST(SessionContext, AcceptsActiveLocalSeat0UserAndGreeter) {
  auto descriptor = valid_session();
  EXPECT_TRUE(session::eligible_graphical_session(descriptor));

  descriptor.session_class = "greeter";
  EXPECT_TRUE(session::eligible_graphical_session(descriptor));
}

TEST(SessionContext, RejectsInactiveRemoteOrNonSeat0Sessions) {
  auto descriptor = valid_session();
  descriptor.active = false;
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.remote = true;
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.seat = "seat1";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.state = "closing";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));
}

TEST(SessionContext, RejectsUnsupportedSessionTypesAndClasses) {
  auto descriptor = valid_session();
  descriptor.type = "tty";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.type = "wayland";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));

  descriptor = valid_session();
  descriptor.session_class = "lock-screen";
  EXPECT_FALSE(session::eligible_graphical_session(descriptor));
}

TEST(SessionContext, RoundTripsBoundedDesktopUpdates) {
  const auto update = valid_update();
  const auto message = session::session_update_message(update);
  const auto parsed = session::parse_session_update(message);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->generation, update.generation);
  EXPECT_EQ(parsed->session.id, update.session.id);
  EXPECT_EQ(parsed->session.uid, update.session.uid);
  EXPECT_EQ(parsed->environment.display, update.environment.display);
  EXPECT_EQ(parsed->environment.pulse_cookie, update.environment.pulse_cookie);
}

TEST(SessionContext, RejectsMalformedOrIneligibleDesktopUpdates) {
  auto update = valid_update();
  auto message = session::session_update_message(update);
  ASSERT_FALSE(message.empty());
  message.pop_back();
  EXPECT_FALSE(session::parse_session_update(message));

  update.session.remote = true;
  EXPECT_TRUE(session::session_update_message(update).empty());

  update = valid_update();
  update.generation = 0;
  EXPECT_TRUE(session::session_update_message(update).empty());
}

TEST(SessionContext, RoundTripsBoundedDisplayRequests) {
  const session::display_request_t single {
    session::display_request_t::action_t::acquire,
    "single", "2560x1600", {}, 1000
  };
  const auto singleMessage = session::display_request_message(single);
  const auto parsedSingle = session::parse_display_request(singleMessage);
  ASSERT_TRUE(parsedSingle);
  EXPECT_EQ(parsedSingle->layout, single.layout);
  EXPECT_EQ(parsedSingle->mode_1, single.mode_1);
  EXPECT_TRUE(parsedSingle->mode_2.empty());
  EXPECT_EQ(parsedSingle->account_uid, single.account_uid);

  const session::display_request_t dual {
    session::display_request_t::action_t::acquire,
    "dual-horizontal", "4096x2160", "1024x2160", 1000
  };
  const auto parsedDual = session::parse_display_request(
    session::display_request_message(dual)
  );
  ASSERT_TRUE(parsedDual);
  EXPECT_EQ(parsedDual->mode_2, dual.mode_2);

  for (const auto action : {
         session::display_request_t::action_t::activate,
         session::display_request_t::action_t::release,
       }) {
    const session::display_request_t control {action, {}, {}, {}, 1000};
    const auto parsed = session::parse_display_request(
      session::display_request_message(control)
    );
    ASSERT_TRUE(parsed);
    EXPECT_EQ(parsed->action, action);
    EXPECT_EQ(parsed->account_uid, 1000U);
  }
}

TEST(SessionContext, RejectsMalformedDisplayRequests) {
  EXPECT_TRUE(session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "single", "1280x720", {}, 1000}
  ).empty());
  EXPECT_TRUE(session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "single", "2560x1600", "1024x2160", 1000}
  ).empty());
  EXPECT_TRUE(session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "dual-horizontal", "4096x2160", {}, 1000}
  ).empty());
  EXPECT_FALSE(session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "dual-horizontal", "4096x2160", "1280x2160", 1000}
  ).empty());
  EXPECT_TRUE(session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "single", "2560x1600", {}, 0}
  ).empty());
  auto truncated = session::display_request_message(
    {session::display_request_t::action_t::acquire,
     "single", "2560x1600", {}, 1000}
  );
  ASSERT_FALSE(truncated.empty());
  truncated.pop_back();
  EXPECT_FALSE(session::parse_display_request(truncated));
}

TEST(SessionContext, RoundTripsTemporaryRuntimeDisplayState) {
  const session::runtime_display_state_t state {
    "dual-horizontal", "3840x2160", "1280x2160", 1000
  };
  const auto message = session::runtime_display_state_message(state);
  const auto parsed = session::parse_runtime_display_state(message);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->layout, state.layout);
  EXPECT_EQ(parsed->mode_1, state.mode_1);
  EXPECT_EQ(parsed->mode_2, state.mode_2);
  EXPECT_EQ(parsed->lease_uid, state.lease_uid);

  auto truncated = message;
  truncated.pop_back();
  EXPECT_FALSE(session::parse_runtime_display_state(truncated));
  EXPECT_TRUE(session::runtime_display_state_message(
    {"single", "1280x1024", {}, 1000}
  ).empty());
}

TEST(SessionContext, ReadsSecondaryVisibilityFromOwnedOverlay) {
  constexpr std::string_view prefix =
    "# Generated by PLANK; do not edit.\n"
    "Section \"Device\"\n";
  EXPECT_EQ(session::secondary_output_visible_from_overlay(
              std::string {prefix} +
              "  Option \"MetaModes\" \"DFP-0: 2560x2160 +0+0, DFP-2: NULL\"\n"),
            false);
  EXPECT_EQ(session::secondary_output_visible_from_overlay(
              std::string {prefix} +
              "  Option \"MetaModes\" \"DFP-0: 4096x2160 +0+0, DFP-2: 1024x2160 +4096+0\"\n"),
            true);
  EXPECT_FALSE(session::secondary_output_visible_from_overlay(
                 "# foreign configuration\nOption \"MetaModes\" \"DFP-2: NULL\"\n")
                 .has_value());
}

namespace {
  session::runtime_display_state_2_t arrangement_state() {
    session::runtime_display_state_2_t state;
    state.lease_uid = 1000;
    state.session_id = "c7";
    state.display = ":1";
    state.origin = "arrangement";
    state.request = "1:3024x1890+0+270:auto,3840x2160+3024+0:auto";
    state.primary_before = "HDMI-0";
    state.outputs = {
      {"DP-0", "DPY-0", "virtual", "3024x1890", 0, 0, 270, 3024, 1890, 1},
      {"HDMI-0", "DPY-4", "physical", "3840x2160", 1, 3024, 0, 3840, 2160, 0},
      {"DP-2", "DPY-2", "off", "", -1, 0, 0, 0, 0, 1},
    };
    state.snapshot =
      "DPY-4: nvidia-auto-select @3840x2160 +0+0 {ViewPortIn=3840x2160, ViewPortOut=3840x2160+0+0}";
    return state;
  }

  std::string write_config(std::string_view contents) {
    char path[] = "/tmp/plank-session-context-XXXXXX";
    const int descriptor = mkstemp(path);
    EXPECT_GE(descriptor, 0);
    const auto written = write(descriptor, contents.data(), contents.size());
    EXPECT_EQ(written, static_cast<ssize_t>(contents.size()));
    close(descriptor);
    return path;
  }
}  // namespace

TEST(SessionContext, RoundTripsArrangementRequests) {
  session::display_request_t acquire;
  acquire.action = session::display_request_t::action_t::acquire;
  acquire.account_uid = 1000;
  acquire.arrangement = "1:3024x1890+0+270:auto,3840x2160+3024+0:auto";
  const auto message = session::display_request_message(acquire);
  ASSERT_FALSE(message.empty());
  EXPECT_TRUE(message.starts_with(std::string_view {"SC-DISPLAY-4\0acquire\0", 21}));
  const auto parsed = session::parse_display_request(message);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->action, session::display_request_t::action_t::acquire);
  EXPECT_EQ(parsed->arrangement, acquire.arrangement);
  EXPECT_EQ(parsed->account_uid, 1000U);
  EXPECT_TRUE(parsed->layout.empty());

  for (const auto action : {
         session::display_request_t::action_t::activate,
         session::display_request_t::action_t::release,
       }) {
    session::display_request_t control;
    control.action = action;
    control.account_uid = 1000;
    const auto record = session::display_arrangement_request_message(control);
    ASSERT_FALSE(record.empty());
    const auto parsed_control = session::parse_display_request(record);
    ASSERT_TRUE(parsed_control);
    EXPECT_EQ(parsed_control->action, action);
    EXPECT_TRUE(parsed_control->arrangement.empty());
  }
  // SC-DISPLAY-3 records are unchanged.
  EXPECT_TRUE(session::display_request_message(
    {session::display_request_t::action_t::release, {}, {}, {}, 1000}
  ).starts_with(std::string_view {"SC-DISPLAY-3\0", 13}));
}

TEST(SessionContext, RejectsMalformedArrangementRequests) {
  session::display_request_t request;
  request.account_uid = 1000;
  request.arrangement = "1:03840x2160+0+0:auto";
  EXPECT_TRUE(session::display_request_message(request).empty());
  request.arrangement = "1:3840x2160+0+0:auto";
  request.account_uid = 0;
  EXPECT_TRUE(session::display_request_message(request).empty());
  request.account_uid = 1000;
  request.layout = "single";
  EXPECT_TRUE(session::display_request_message(request).empty());
  request.layout.clear();
  EXPECT_TRUE(session::display_arrangement_request_message(
    {session::display_request_t::action_t::acquire, {}, {}, {}, 1000}
  ).empty());
  session::display_request_t release;
  release.action = session::display_request_t::action_t::release;
  release.account_uid = 1000;
  release.arrangement = "1:3840x2160+0+0:auto";
  EXPECT_TRUE(session::display_arrangement_request_message(release).empty());

  auto message = session::display_request_message(request);
  ASSERT_FALSE(message.empty());
  message.pop_back();
  EXPECT_FALSE(session::parse_display_request(message));
  auto extra = session::display_request_message(request);
  extra += "extra";
  extra.push_back('\0');
  EXPECT_FALSE(session::parse_display_request(extra));
}

TEST(SessionContext, RoundTripsArrangementLeaseState) {
  const auto state = arrangement_state();
  const auto message = session::runtime_display_state_2_message(state);
  ASSERT_FALSE(message.empty());
  EXPECT_TRUE(message.starts_with("SC-DISPLAY-STATE-2\nuid=1000\n"));
  EXPECT_NE(message.find("\nprimary=HDMI-0\n"), std::string::npos);
  EXPECT_NE(message.find("\noutput=DP-2 DPY-2 off - -1 0 0 0 0 1\n"), std::string::npos);
  const auto parsed = session::parse_runtime_display_state_2(message);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->request, state.request);
  EXPECT_EQ(parsed->primary_before, state.primary_before);
  ASSERT_EQ(parsed->outputs.size(), 3U);
  EXPECT_EQ(parsed->outputs[0].backing, "virtual");
  EXPECT_EQ(parsed->outputs[0].carrier, "3024x1890");
  EXPECT_EQ(parsed->outputs[0].y, 270);
  EXPECT_EQ(parsed->outputs[1].non_desktop_before, 0);
  EXPECT_EQ(parsed->outputs[2].backing, "off");
  EXPECT_EQ(parsed->snapshot, state.snapshot);

  auto no_primary = state;
  no_primary.primary_before = "";
  const auto no_primary_message = session::runtime_display_state_2_message(no_primary);
  ASSERT_TRUE(session::parse_runtime_display_state_2(no_primary_message));
  EXPECT_NE(no_primary_message.find("\nprimary=\n"), std::string::npos);
  auto older_record = state;
  older_record.primary_before.reset();
  const auto older_message = session::runtime_display_state_2_message(older_record);
  ASSERT_TRUE(session::parse_runtime_display_state_2(older_message));
  EXPECT_EQ(older_message.find("\nprimary="), std::string::npos);

  // The legacy STATE-1 marker is still parsed, and the two never cross.
  EXPECT_FALSE(session::parse_runtime_display_state(message));
  const auto legacy_message = session::runtime_display_state_message(
    {"single", "2560x1600", {}, 1000}
  );
  ASSERT_FALSE(legacy_message.empty());
  EXPECT_TRUE(session::parse_runtime_display_state(legacy_message));
  EXPECT_FALSE(session::parse_runtime_display_state_2(legacy_message));

  auto legacy = state;
  legacy.origin = "legacy";
  legacy.layout = "dual-horizontal";
  legacy.mode_1 = "3024x1890";
  legacy.mode_2 = "3840x2160";
  EXPECT_TRUE(session::parse_runtime_display_state_2(session::runtime_display_state_2_message(legacy)));
  legacy.mode_2 = "1280x720";
  EXPECT_TRUE(session::runtime_display_state_2_message(legacy).empty());
}

TEST(SessionContext, RejectsMalformedArrangementLeaseState) {
  auto state = arrangement_state();
  state.outputs[2].carrier = "1920x1080";
  EXPECT_TRUE(session::runtime_display_state_2_message(state).empty());
  state = arrangement_state();
  state.outputs[0].backing = "mirror";
  EXPECT_TRUE(session::runtime_display_state_2_message(state).empty());
  state = arrangement_state();
  state.request = "1:3024x1890+0+270:auto,3840x2160+3024+00:auto";
  EXPECT_TRUE(session::runtime_display_state_2_message(state).empty());
  state = arrangement_state();
  state.snapshot = "DPY-4: 3840x2160\n+0+0";
  EXPECT_TRUE(session::runtime_display_state_2_message(state).empty());
  state = arrangement_state();
  state.display = "remote:0";
  EXPECT_TRUE(session::runtime_display_state_2_message(state).empty());
  state = arrangement_state();
  state.primary_before = "DP-0;rm";
  EXPECT_TRUE(session::runtime_display_state_2_message(state).empty());
  state = arrangement_state();
  state.snapshot = std::string(17000, 'x');
  EXPECT_TRUE(session::runtime_display_state_2_message(state).empty());

  const auto message = session::runtime_display_state_2_message(arrangement_state());
  auto truncated = message;
  truncated.pop_back();
  EXPECT_FALSE(session::parse_runtime_display_state_2(truncated));
  auto reordered = message;
  reordered.replace(reordered.find("uid=1000"), 8, "uid=1001");
  EXPECT_TRUE(session::parse_runtime_display_state_2(reordered));
  reordered.replace(reordered.find("session=c7"), 10, "sessionx=c");
  EXPECT_FALSE(session::parse_runtime_display_state_2(reordered));
}

TEST(SessionContext, RoundTripsDisplayTransitions) {
  const session::display_transition_t failed {
    "failed", "too_many_displays", "1:3840x2160+0+0:auto", 1000, 1790000000
  };
  const auto message = session::display_transition_message(failed);
  ASSERT_FALSE(message.empty());
  const auto parsed = session::parse_display_transition(message);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->state, "failed");
  EXPECT_EQ(parsed->reason, "too_many_displays");
  EXPECT_EQ(parsed->time, 1790000000);
  EXPECT_TRUE(session::parse_display_transition(session::display_transition_message(
    {"pending", "", "1:3840x2160+0+0:auto", 1000, 1}
  )));
  EXPECT_TRUE(session::display_transition_message(
    {"pending", "busy", "1:3840x2160+0+0:auto", 1000, 1}
  ).empty());
  EXPECT_TRUE(session::display_transition_message(
    {"failed", "", "1:3840x2160+0+0:auto", 1000, 1}
  ).empty());
  EXPECT_TRUE(session::display_transition_message(
    {"applied", "", "1:3840x2160+0+0:auto", 1000, 1}
  ).empty());
  EXPECT_TRUE(session::display_transition_message(
    {"failed", "Bad Reason", "1:3840x2160+0+0:auto", 1000, 1}
  ).empty());
  EXPECT_FALSE(session::read_display_transition("/nonexistent/display-transition"));
}

TEST(SessionContext, ReadsTheHybridStartupPolicy) {
  const auto hybrid = write_config("[display]\nstartup_layout = hybrid\nadapter_name =\n");
  EXPECT_EQ(session::configured_startup_layout(hybrid), session::startup_layout_t::hybrid);
  unlink(hybrid.c_str());
  const auto physical = write_config("[general]\n[display]\n");
  EXPECT_EQ(session::configured_startup_layout(physical), session::startup_layout_t::physical);
  unlink(physical.c_str());
  const auto wrong = write_config("[display]\nstartup_layout = Hybrid\n");
  EXPECT_EQ(session::configured_startup_layout(wrong), session::startup_layout_t::invalid);
  unlink(wrong.c_str());
  const auto duplicate = write_config("[display]\nstartup_layout = hybrid\nstartup_layout = hybrid\n");
  EXPECT_EQ(session::configured_startup_layout(duplicate), session::startup_layout_t::invalid);
  unlink(duplicate.c_str());
}

TEST(SessionContext, TransitionsExpireAndMatchTheirRequest) {
  constexpr std::string_view request = "1:3840x2160+0+0:auto";
  const session::display_transition_t pending {"pending", "", std::string {request}, 1000, 100};
  const session::display_transition_t failed {"failed", "verify_failed", std::string {request}, 1000, 100};
  using status = session::transition_status_t;
  EXPECT_EQ(session::transition_status(std::nullopt, request, 1000, 100), status::none);
  EXPECT_EQ(session::transition_status(pending, request, 1000, 150), status::pending);
  EXPECT_EQ(session::transition_status(pending, request, 1000, 221), status::none);
  EXPECT_EQ(session::transition_status(failed, request, 1000, 129), status::failed);
  EXPECT_EQ(session::transition_status(failed, request, 1000, 131), status::none);
  EXPECT_EQ(session::transition_status(failed, "1:1920x1080+0+0:auto", 1000, 101), status::none);
  EXPECT_EQ(session::transition_status(failed, request, 1001, 101), status::none);
  EXPECT_FALSE(session::transition_current(failed, 0));
  EXPECT_TRUE(session::transition_current(failed, 97));
}
