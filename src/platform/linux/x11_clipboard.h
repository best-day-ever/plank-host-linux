/**
 * @file src/platform/linux/x11_clipboard.h
 * @brief X11 UTF-8 clipboard watch and publish helpers for PLANK sessions.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <memory>
#include <string>
#include <vector>

namespace platf::x11 {
  /**
   * @brief One stable X11 CLIPBOARD value returned by the isolated worker.
   */
  struct clipboard_content_t {
    enum class kind_e {
      text,
      files,
    } kind = kind_e::text;  ///< Native flavor selected from the current owner.

    std::string text;  ///< UTF-8 text when kind is text.
    std::vector<std::string> file_uris;  ///< Local file URLs when kind is files.
  };

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
    /**
     * @brief Poll the active CLIPBOARD owner without interpreting file URLs as text.
     * @param content Receives either bounded UTF-8 text or local file URLs.
     * @return True when a new stable clipboard value was completed.
     */
    bool poll_change(clipboard_content_t &content);
    bool set_text(const std::vector<std::uint8_t> &text);
    /**
     * @brief Own CLIPBOARD with GNOME and freedesktop copy-file representations.
     * @param local_file_uris Absolute local file URLs; network URLs are rejected.
     * @return True when ownership and bounded payload construction succeed.
     */
    bool set_files(const std::vector<std::string> &local_file_uris);

    /**
     * @brief Wait for X11 traffic, or at most 250 ms for inbox/shutdown polling.
     * @return False if the dedicated X11 connection has failed.
     */
    bool wait_for_activity();

  private:
    struct state_t;
    explicit clipboard_t(std::unique_ptr<state_t> state);
    std::unique_ptr<state_t> state_;
  };
}  // namespace platf::x11
