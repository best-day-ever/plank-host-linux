/**
 * @file src/platform/linux/x11_clipboard.h
 * @brief X11 UTF-8 clipboard watch and publish helpers for PLANK sessions.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct _XEvent;
typedef struct _XEvent XEvent;

namespace platf::x11 {
  /**
   * @brief Session-scoped X11 CLIPBOARD/PRIMARY bridge.
   */
  class clipboard_t {
  public:
    static std::optional<clipboard_t> make();

    clipboard_t(const clipboard_t &) = delete;
    clipboard_t &operator=(const clipboard_t &) = delete;
    clipboard_t(clipboard_t &&) = default;
    clipboard_t &operator=(clipboard_t &&) = default;

    bool poll_change(std::string &text);
    bool set_text(const std::vector<std::uint8_t> &text);

  private:
    clipboard_t() = default;
    bool read_selection(std::string &text);
    void dispatch_event(const XEvent &event);
    void handle_selection_request(const XEvent &event);

    void *display_ {nullptr};
    unsigned long window_ {0};
    int xfixes_event_base_ {-1};
    std::uint64_t generation_ {0};
    std::string owned_text_;
    std::string last_sent_text_;
  };
}  // namespace platf::x11
