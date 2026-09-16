/**
 * @file src/platform/linux/x11_clipboard.h
 * @brief X11 UTF-8 clipboard watch and publish helpers for PLANK sessions.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace platf::x11 {
  class text_change_tracker_t {
  public:
    bool accept(const std::string &text) {
      if (text == last_text_) {
        return false;
      }
      last_text_ = text;
      return true;
    }

    void mark(const std::string &text) {
      last_text_ = text;
    }

    void reset() {
      last_text_.clear();
    }

  private:
    std::string last_text_;
  };

  /**
   * @brief Session-scoped X11 CLIPBOARD/PRIMARY bridge.
   */
  class clipboard_t {
  public:
    static std::optional<clipboard_t> make();

    clipboard_t(const clipboard_t &) = delete;
    clipboard_t &operator=(const clipboard_t &) = delete;
    clipboard_t(clipboard_t &&other) noexcept;
    clipboard_t &operator=(clipboard_t &&other) noexcept;
    ~clipboard_t();

    bool poll_change(std::string &text);
    bool set_text(const std::vector<std::uint8_t> &text);

  private:
    clipboard_t() = default;
    void reset() noexcept;
    bool read_selection(std::string &text);

    void *display_ {nullptr};
    unsigned long window_ {0};
    int xfixes_event_base_ {-1};
    std::uint64_t generation_ {0};
    std::string owned_text_;
    text_change_tracker_t last_forwarded_text_;
  };
}  // namespace platf::x11
