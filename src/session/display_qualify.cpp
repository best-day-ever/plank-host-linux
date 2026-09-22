/**
 * @file src/session/display_qualify.cpp
 * @brief Command line and report of the supervisor's display qualification modes.
 */
#include "display_qualify.h"

#include "../plank_arrangement.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <set>
#include <sstream>

namespace plank::display {
  namespace {
    std::optional<int> parse_hold(std::string_view value) {
      int parsed {};
      const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
      if (value.empty() || result.ec != std::errc {} || result.ptr != value.data() + value.size() ||
          parsed < 0 || parsed > maximum_hold_seconds ||
          (value.size() > 1 && value.front() == '0')) {
        return std::nullopt;
      }
      return parsed;
    }

    std::string rect_text(const nlohmann::json &rect) {
      return std::to_string(rect.value("width", 0)) + "x" + std::to_string(rect.value("height", 0)) +
             "+" + std::to_string(rect.value("x", 0)) + "+" + std::to_string(rect.value("y", 0));
    }
  }  // namespace

  supervisor_options_result_t parse_supervisor_options(const std::vector<std::string_view> &arguments) {
    supervisor_options_t options;
    std::set<std::string_view> seen;
    const auto fail = [](std::string message) {
      return supervisor_options_result_t {std::nullopt, std::move(message)};
    };
    for (std::size_t index = 0; index < arguments.size(); ++index) {
      const auto argument = arguments[index];
      if (!seen.insert(argument).second) return fail(std::string {argument} + " is given twice");
      const bool has_value = index + 1 < arguments.size();
      if (argument == "--worker") {
        if (!has_value) return fail("--worker needs an absolute path");
        options.worker = std::string {arguments[++index]};
        if (options.worker.empty() || options.worker.front() != '/') {
          return fail("--worker needs an absolute path");
        }
      } else if (argument == "--qualify-arrangement") {
        if (!has_value) return fail("--qualify-arrangement needs a canonical display arrangement");
        options.request = std::string {arguments[++index]};
        options.mode = supervisor_options_t::run_mode_t::qualify;
        const auto parsed = plank::arrangement::parse(options.request);
        if (!parsed.request) {
          return fail("--qualify-arrangement is not a canonical display arrangement (" +
                      std::string {plank::arrangement::error_code(parsed.error)} + ")");
        }
      } else if (argument == "--hold") {
        if (!has_value) return fail("--hold needs a number of seconds");
        const auto hold = parse_hold(arguments[++index]);
        if (!hold) return fail("--hold must be 0 to " + std::to_string(maximum_hold_seconds) + " seconds");
        options.hold_seconds = *hold;
      } else if (argument == "--capture") {
        if (!has_value) return fail("--capture needs an NVENC encoding mode");
        options.capture_mode = std::string {arguments[++index]};
        static constexpr std::array<std::string_view, 5> modes {
          "h264-8-444-nvenc", "hevc-8-444-nvenc", "hevc-10-444-nvenc", "h264-8-420-nvenc", "hevc-10-420-nvenc",
        };
        if (std::find(modes.begin(), modes.end(), options.capture_mode) == modes.end()) {
          return fail("--capture needs an NVENC encoding mode, for example hevc-10-444-nvenc");
        }
      } else if (argument == "--capture-frames") {
        if (!has_value) return fail("--capture-frames needs a number of frames");
        const auto value = arguments[++index];
        int frames {};
        const auto result = std::from_chars(value.data(), value.data() + value.size(), frames);
        if (value.empty() || result.ec != std::errc {} || result.ptr != value.data() + value.size() ||
            frames < 1 || frames > 3600 || value.front() == '0') {
          return fail("--capture-frames must be 1 to 3600");
        }
        options.capture_frames = frames;
      } else if (argument == "--capture-output") {
        if (!has_value) return fail("--capture-output needs an absolute directory");
        options.capture_output = std::string {arguments[++index]};
        if (options.capture_output.empty() || options.capture_output.front() != '/' ||
            options.capture_output.find_first_of(" \t\n") != std::string::npos) {
          return fail("--capture-output needs an absolute directory without spaces");
        }
      } else if (argument == "--print-inventory") {
        options.mode = supervisor_options_t::run_mode_t::print_inventory;
      } else if (argument == "--json") {
        options.json = true;
      } else {
        return fail("unknown argument: " + std::string {argument});
      }
    }
    const bool qualify = seen.contains("--qualify-arrangement");
    const bool inventory = seen.contains("--print-inventory");
    if (qualify && inventory) return fail("--qualify-arrangement and --print-inventory are separate modes");
    if (seen.contains("--worker") && (qualify || inventory)) {
      return fail("--worker applies only to the supervisor");
    }
    if (seen.contains("--hold") && !qualify) return fail("--hold applies only to --qualify-arrangement");
    if ((seen.contains("--capture") || seen.contains("--capture-frames") || seen.contains("--capture-output")) &&
        !qualify) {
      return fail("--capture applies only to --qualify-arrangement");
    }
    if ((seen.contains("--capture-frames") || seen.contains("--capture-output")) && !seen.contains("--capture")) {
      return fail("--capture-frames and --capture-output need --capture");
    }
    if (options.json && !qualify && !inventory) {
      return fail("--json applies only to --qualify-arrangement and --print-inventory");
    }
    return {std::move(options), {}};
  }

  std::string supervisor_usage(std::string_view program) {
    const std::string name {program};
    return "usage: " + name + " [--worker ABSOLUTE_PATH]\n"
           "       " + name + " --qualify-arrangement REQUEST [--hold SECONDS] [--json]\n"
           "           [--capture MODE [--capture-frames N] [--capture-output DIRECTORY]]\n"
           "       " + name + " --print-inventory [--json]\n";
  }

  std::string qualification_refusal(const qualification_preconditions_t &preconditions) {
    if (!preconditions.root) return "display qualification must run as root";
    if (preconditions.startup_policy != "physical" && preconditions.startup_policy != "hybrid") {
      return "display.startup_layout is " + preconditions.startup_policy +
             "; display arrangements need physical or hybrid";
    }
    if (preconditions.qualification_live) return "another display qualification is running";
    if (preconditions.display_state_present) {
      return "a PLANK display lease is active (/run/plank/host/display-state exists); "
             "disconnect the client first";
    }
    if (preconditions.transition && preconditions.transition->state == "pending" &&
        plank::session::transition_current(*preconditions.transition, preconditions.now)) {
      return "a PLANK display transition is running";
    }
    return {};
  }

  nlohmann::json inventory_json(const inventory_t &inventory) {
    const auto output_json = [](const inventory_output_t &output, bool physical) {
      nlohmann::json item {
        {"dfp", output.device.dfp},
        {"dpy", output.device.dpy},
        {"output", output.device.randr},
        {"connector", output.device.connector},
      };
      if (physical) {
        item["display_name"] = output.display_name;
        item["edid_sha256"] = output.edid_sha256;
        item["preferred"] = output.preferred;
        item["modes"] = output.modes;
      }
      return item;
    };
    nlohmann::json physical = nlohmann::json::array();
    for (const auto &output : inventory.physical) physical.push_back(output_json(output, true));
    nlohmann::json candidates = nlohmann::json::array();
    for (const auto &output : inventory.virtual_candidates) candidates.push_back(output_json(output, false));
    return {
      {"version", inventory.version},
      {"fingerprint", inventory.fingerprint},
      {"gpu_bus_id", inventory.gpu_bus_id},
      {"driver_version", inventory.driver_version},
      {"startup_policy", inventory.startup_policy},
      {"screen_virtual", {{"width", inventory.screen_virtual_width}, {"height", inventory.screen_virtual_height}}},
      {"physical", physical},
      {"virtual_candidates", candidates},
      {"virtual_heads", inventory.virtual_heads},
    };
  }

  nlohmann::json plan_json(const arrangement_plan_t &plan, const std::vector<std::string> &visibility) {
    nlohmann::json outputs = nlohmann::json::array();
    for (const auto &output : plan.outputs) {
      outputs.push_back({
        {"output", output.randr},
        {"dpy", output.dpy},
        {"physical", output.physical},
        {"backing", output.backing},
        {"mode", output.mode},
        {"index", output.index},
        {"rect", {{"x", output.rect.x}, {"y", output.rect.y},
                  {"width", output.rect.width}, {"height", output.rect.height}}},
      });
    }
    return {
      {"metamode", plan.metamode},
      {"visibility", visibility},
      {"primary", plan.primary},
      {"desktop", {{"width", plan.width}, {"height", plan.height}}},
      {"outputs", outputs},
    };
  }

  nlohmann::json screen_json(const randr_screen_t &screen) {
    nlohmann::json outputs = nlohmann::json::array();
    for (const auto &output : screen.outputs) {
      outputs.push_back({
        {"output", output.name},
        {"connected", output.connected},
        {"enabled", output.enabled},
        {"primary", output.primary},
        {"rect", {{"x", output.x}, {"y", output.y}, {"width", output.width}, {"height", output.height}}},
        {"non_desktop", output.non_desktop ? nlohmann::json(*output.non_desktop ? 1 : 0) : nlohmann::json()},
      });
    }
    return {{"width", screen.width}, {"height", screen.height}, {"outputs", outputs}};
  }

  std::string report_text(const nlohmann::json &report) {
    std::ostringstream text;
    if (report.contains("session")) {
      const auto &session = report.at("session");
      text << "session: " << session.value("id", "") << " (" << session.value("class", "")
           << ", uid " << session.value("uid", 0) << ", display " << session.value("display", "") << ")\n";
    }
    if (report.contains("inventory")) {
      const auto &inventory = report.at("inventory");
      text << "inventory: " << inventory.value("startup_policy", "") << ", GPU "
           << inventory.value("gpu_bus_id", "") << ", driver " << inventory.value("driver_version", "")
           << ", fingerprint " << inventory.value("fingerprint", "") << "\n";
      for (const auto &output : inventory.at("physical")) {
        text << "  physical " << output.value("output", "") << " " << output.value("dfp", "") << "/"
             << output.value("dpy", "") << " \"" << output.value("display_name", "") << "\" preferred "
             << output.value("preferred", "") << ", modes " << output.at("modes").size() << "\n";
      }
      const auto heads = inventory.value("virtual_heads", 0);
      int index = 0;
      for (const auto &output : inventory.at("virtual_candidates")) {
        text << "  virtual " << output.value("output", "") << " " << output.value("dfp", "") << "/"
             << output.value("dpy", "") << " " << output.value("connector", "")
             << (index++ < heads ? " (reserved head)" : " (candidate)") << "\n";
      }
    }
    if (report.contains("display_capabilities")) {
      text << "display_capabilities: " << report.at("display_capabilities").dump() << "\n";
    }
    if (report.contains("request")) text << "request: " << report.at("request").get<std::string>() << "\n";
    if (report.contains("error")) text << "error: " << report.at("error").get<std::string>() << "\n";
    if (report.contains("plan")) {
      const auto &plan = report.at("plan");
      text << "plan: desktop " << plan.at("desktop").value("width", 0) << "x"
           << plan.at("desktop").value("height", 0) << ", primary " << plan.value("primary", "") << "\n"
           << "  metamode: " << plan.value("metamode", "") << "\n  visibility:";
      for (const auto &argument : plan.at("visibility")) text << " " << argument.get<std::string>();
      text << "\n";
      for (const auto &output : plan.at("outputs")) {
        text << "  " << output.value("output", "") << " (" << output.value("dpy", "") << "): "
             << output.value("backing", "");
        if (output.value("backing", "") != "off") {
          text << " " << output.value("mode", "") << " -> " << rect_text(output.at("rect"))
               << " entry " << output.value("index", -1);
        }
        text << "\n";
      }
    }
    if (report.contains("apply")) {
      const auto &apply = report.at("apply");
      text << "apply: " << apply.value("result", "") << " after " << apply.value("attempts", 0)
           << " attempt(s)\n";
      if (apply.contains("screen")) {
        const auto &screen = apply.at("screen");
        text << "  screen " << screen.value("width", 0) << "x" << screen.value("height", 0) << "\n";
        for (const auto &output : screen.at("outputs")) {
          if (!output.value("enabled", false) && !output.value("connected", false)) continue;
          text << "  " << output.value("output", "") << ": "
               << (output.value("enabled", false) ? rect_text(output.at("rect")) : std::string {"off"})
               << (output.value("primary", false) ? " primary" : "")
               << " non-desktop " << (output.at("non_desktop").is_null() ? std::string {"?"} :
                                      std::to_string(output.at("non_desktop").get<int>()))
               << "\n";
        }
      }
    }
    if (report.contains("capture")) {
      const auto &capture = report.at("capture");
      text << "capture probe: exit " << capture.value("exit_code", -1);
      if (capture.contains("plan")) {
        const auto &plan = capture.at("plan");
        text << ", " << (plan.value("packed", false) ? "packed " : "unpacked ")
             << plan.at("capture").value("width", 0) << "x" << plan.at("capture").value("height", 0);
      }
      if (capture.contains("frames_encoded")) {
        text << ", " << capture.value("frames_encoded", 0) << " frames, "
             << capture.value("fps", 0.0) << " fps";
      }
      if (capture.contains("error")) text << ", error: " << capture.value("error", "");
      text << "\n";
      if (capture.contains("stream")) text << "  stream: " << capture.value("stream", "") << "\n";
      if (capture.contains("image")) text << "  image: " << capture.value("image", "") << "\n";
    }
    if (report.contains("hold_seconds")) text << "held: " << report.at("hold_seconds").get<int>() << " s\n";
    if (report.contains("restore")) {
      const auto &restore = report.at("restore");
      text << "restore: metamode " << (restore.value("metamode_exact", false) ? "exact" : "NOT exact")
           << ", visibility " << (restore.value("visibility_exact", false) ? "exact" : "NOT exact")
           << (restore.value("fallback", false) ? ", fallback applied" : "") << "\n";
    }
    if (report.contains("success")) {
      text << "result: " << (report.at("success").get<bool>() ? "PASS" : "FAIL") << "\n";
    }
    return text.str();
  }
}  // namespace plank::display
