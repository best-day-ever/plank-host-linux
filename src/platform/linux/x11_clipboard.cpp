/**
 * @file src/platform/linux/x11_clipboard.cpp
 * @brief Session-scoped X11 clipboard bridge with bounded asynchronous reads.
 */
#if defined(__linux__) && defined(SUNSHINE_BUILD_X11)

#include "x11_clipboard.h"

#include <xcb/xcb.h>
#include <poll.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <utility>

#include "src/logging.h"

namespace platf::x11 {
  using namespace std::literals;

  namespace {
    constexpr std::size_t max_text_size = 512 * 1024;
    constexpr std::size_t max_file_list_size = 4 * 1024 * 1024;
    constexpr std::size_t max_file_items = 1024;
    constexpr auto conversion_timeout = std::chrono::seconds(5);
    constexpr auto selection_poll_interval = std::chrono::milliseconds(250);

    template<class T>
    using reply_ptr = std::unique_ptr<T, decltype(&std::free)>;

    template<class T>
    reply_ptr<T> reply(T *value) {
      return reply_ptr<T>(value, &std::free);
    }

    bool valid_percent_encoding(std::string_view value) {
      constexpr std::string_view hex = "0123456789abcdefABCDEF";
      for (std::size_t index = 0; index < value.size(); ++index) {
        if (value[index] == '%') {
          if (index + 2 >= value.size() ||
              hex.find(value[index + 1]) == std::string_view::npos ||
              hex.find(value[index + 2]) == std::string_view::npos) {
            return false;
          }
          index += 2;
        }
      }
      return true;
    }

    bool starts_with(std::string_view value, std::string_view prefix) {
      return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
    }

    bool local_file_uri(std::string_view value) {
      if (value.empty() || value.find('\0') != std::string_view::npos ||
          value.find('\r') != std::string_view::npos ||
          value.find('\n') != std::string_view::npos ||
          value.find("%00") != std::string_view::npos ||
          !valid_percent_encoding(value)) {
        return false;
      }
      if (starts_with(value, "file:///"sv) && value.size() > 8) {
        return true;
      }
      if (starts_with(value, "file://localhost/"sv)) {
        return value.size() > std::string_view("file://localhost/").size();
      }
      if (starts_with(value, "file://"sv)) return false;
      return starts_with(value, "file:/"sv) && value.size() > 6;
    }

    std::optional<std::vector<std::string>> parse_file_list(
      std::string_view payload,
      bool gnome
    ) {
      std::vector<std::string> result;
      std::size_t offset = 0;
      bool first = true;
      while (offset <= payload.size()) {
        const auto newline = payload.find('\n', offset);
        const auto end = newline == std::string_view::npos ? payload.size() : newline;
        auto line = payload.substr(offset, end - offset);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        offset = newline == std::string_view::npos ? payload.size() + 1 : newline + 1;
        if (line.empty() || (!gnome && line.front() == '#')) continue;
        if (gnome && first) {
          first = false;
          if (line != "copy"sv && line != "cut"sv) return std::nullopt;
          continue;
        }
        first = false;
        if (!local_file_uri(line) || result.size() == max_file_items) {
          return std::nullopt;
        }
        result.emplace_back(line);
      }
      if ((gnome && first) || result.empty()) return std::nullopt;
      return result;
    }
  }

  // This connection is used only by the serialized clipboard worker. In
  // particular, a disappearing requestor produces an XCB error, never an Xlib
  // default-handler exit or a temporary process-wide error-handler change.
  struct clipboard_t::state_t {
    xcb_connection_t *connection = nullptr;
    xcb_window_t root = XCB_NONE;
    xcb_window_t window = XCB_NONE;
    xcb_atom_t clipboard = XCB_NONE, utf8 = XCB_NONE, property = XCB_NONE;
    xcb_atom_t targets = XCB_NONE, plain = XCB_NONE, plain_utf8 = XCB_NONE, incr = XCB_NONE;
    xcb_atom_t uri_list = XCB_NONE, gnome_files = XCB_NONE;
    std::string owned_text;
    std::string owned_uri_list;
    std::string owned_gnome_files;
    std::vector<std::string> last_forwarded_files;
    xcb_window_t last_forwarded_file_owner = XCB_NONE;
    text_change_tracker_t last_forwarded;
    reply_ptr<xcb_generic_event_t> next_event {nullptr, &std::free};
    std::chrono::steady_clock::time_point next_conversion;

    struct conversion_t {
      xcb_window_t window = XCB_NONE;
      xcb_window_t owner = XCB_NONE;
      bool incremental = false;
      xcb_atom_t target = XCB_NONE;
      std::size_t maximum_size = max_text_size;
      std::string bytes;
      std::chrono::steady_clock::time_point deadline;
    } pending;

    ~state_t() {
      if (connection != nullptr) {
        // Disconnect destroys our windows and releases only selections still
        // owned by them. It cannot clear a newer owner's selection.
        xcb_disconnect(connection);
      }
    }

    bool checked(xcb_void_cookie_t cookie) {
      return !reply(xcb_request_check(connection, cookie));
    }

    xcb_atom_t atom(const char *name) {
      auto result = reply(xcb_intern_atom_reply(connection,
        xcb_intern_atom(connection, false, std::strlen(name), name), nullptr));
      return result ? result->atom : static_cast<xcb_atom_t>(XCB_NONE);
    }

    xcb_window_t owner(xcb_atom_t selection) {
      auto result = reply(xcb_get_selection_owner_reply(connection,
        xcb_get_selection_owner(connection, selection), nullptr));
      return result ? result->owner : static_cast<xcb_window_t>(XCB_NONE);
    }

    xcb_window_t make_window() {
      auto id = xcb_generate_id(connection);
      const std::uint32_t events = XCB_EVENT_MASK_PROPERTY_CHANGE;
      if (!checked(xcb_create_window_checked(connection, XCB_COPY_FROM_PARENT,
            id, root, 0, 0, 1, 1, 0, XCB_WINDOW_CLASS_INPUT_OUTPUT,
            XCB_COPY_FROM_PARENT, XCB_CW_EVENT_MASK, &events))) {
        return XCB_NONE;
      }
      return id;
    }

    void cancel_conversion() {
      if (pending.window != XCB_NONE) {
        xcb_destroy_window(connection, pending.window);
      }
      pending = {};
    }

    void start_conversion(xcb_window_t current_owner) {
      next_conversion = std::chrono::steady_clock::now() + selection_poll_interval;
      pending.window = make_window();
      if (pending.window == XCB_NONE) {
        return;
      }
      pending.owner = current_owner;
      pending.deadline = std::chrono::steady_clock::now() + conversion_timeout;
      // A distinct requestor window correlates late replies without allocating
      // a permanent server atom for every clipboard poll.
      pending.target = targets;
      pending.maximum_size = max_file_list_size;
      xcb_convert_selection(connection, pending.window, clipboard, targets,
        property, XCB_CURRENT_TIME);
    }

    void continue_conversion(xcb_atom_t target) {
      pending.target = target;
      pending.maximum_size = target == utf8 ? max_text_size : max_file_list_size;
      pending.bytes.clear();
      pending.incremental = false;
      pending.deadline = std::chrono::steady_clock::now() + conversion_timeout;
      xcb_convert_selection(connection, pending.window, clipboard, target,
        property, XCB_CURRENT_TIME);
    }

    void serve(const xcb_selection_request_event_t &request) {
      auto destination = request.property != XCB_NONE ? request.property : request.target;
      bool supported = request.owner == window &&
        (request.selection == clipboard ||
         (request.selection == XCB_ATOM_PRIMARY && !owned_text.empty())) &&
        owner(request.selection) == window;
      if (supported && request.target == targets) {
        const xcb_atom_t text_types[] = {targets, utf8, plain, plain_utf8, XCB_ATOM_STRING};
        const xcb_atom_t file_types[] = {targets, gnome_files, uri_list};
        const auto *types = owned_uri_list.empty() ? text_types : file_types;
        const auto count = owned_uri_list.empty() ? 5U : 3U;
        supported = checked(xcb_change_property_checked(connection, XCB_PROP_MODE_REPLACE,
          request.requestor, destination, XCB_ATOM_ATOM, 32, count, types));
      } else if (supported && owned_uri_list.empty() &&
                 (request.target == utf8 || request.target == plain ||
                                request.target == plain_utf8 || request.target == XCB_ATOM_STRING)) {
        supported = checked(xcb_change_property_checked(connection, XCB_PROP_MODE_REPLACE,
          request.requestor, destination,
          request.target == XCB_ATOM_STRING ? static_cast<xcb_atom_t>(XCB_ATOM_STRING) : utf8,
          8, owned_text.size(), owned_text.data()));
      } else if (supported && !owned_uri_list.empty() &&
                 (request.target == uri_list || request.target == gnome_files)) {
        const auto &payload = request.target == uri_list ? owned_uri_list : owned_gnome_files;
        supported = checked(xcb_change_property_checked(connection, XCB_PROP_MODE_REPLACE,
          request.requestor, destination, request.target, 8,
          payload.size(), payload.data()));
      } else {
        supported = false;
      }
      xcb_selection_notify_event_t notify {};
      notify.response_type = XCB_SELECTION_NOTIFY;
      notify.requestor = request.requestor;
      notify.selection = request.selection;
      notify.target = request.target;
      notify.property = supported ? destination : static_cast<xcb_atom_t>(XCB_NONE);
      notify.time = request.time;
      // Both property and notification requests may race window destruction.
      // Checked errors are consumed on this connection only.
      checked(xcb_send_event_checked(connection, false, request.requestor, 0,
        reinterpret_cast<const char *>(&notify)));
    }

    std::optional<clipboard_content_t> read_property(bool initial) {
      auto value = reply(xcb_get_property_reply(connection,
        xcb_get_property(connection, true, pending.window, property,
          XCB_GET_PROPERTY_TYPE_ANY, 0, (pending.maximum_size + 3) / 4), nullptr));
      if (!value || value->bytes_after != 0) {
        cancel_conversion();
        return std::nullopt;
      }
      const auto size = static_cast<std::size_t>(xcb_get_property_value_length(value.get()));
      if (pending.target == targets) {
        if (value->type != XCB_ATOM_ATOM || value->format != 32 ||
            size % sizeof(xcb_atom_t) != 0) {
          cancel_conversion();
          return std::nullopt;
        }
        const auto *atoms = static_cast<const xcb_atom_t *>(xcb_get_property_value(value.get()));
        const auto count = size / sizeof(xcb_atom_t);
        const auto contains = [&](xcb_atom_t target) {
          return std::find(atoms, atoms + count, target) != atoms + count;
        };
        if (contains(gnome_files)) {
          continue_conversion(gnome_files);
        } else if (contains(uri_list)) {
          continue_conversion(uri_list);
        } else if (contains(utf8)) {
          continue_conversion(utf8);
        } else {
          cancel_conversion();
        }
        return std::nullopt;
      }
      if (initial && value->type == incr) {
        std::uint32_t advertised = 0;
        if (value->format == 32 && size == sizeof(advertised)) {
          std::memcpy(&advertised, xcb_get_property_value(value.get()), sizeof(advertised));
          if (advertised <= pending.maximum_size) {
            // get_property(delete=true) acknowledges INCR. The owner sends
            // each subsequent chunk only after the previous property deletion.
            pending.incremental = true;
            return std::nullopt;
          }
        }
        cancel_conversion();
        return std::nullopt;
      }
      if ((value->type != pending.target && value->type != utf8) || value->format != 8 ||
          pending.bytes.size() > pending.maximum_size ||
          size > pending.maximum_size - pending.bytes.size()) {
        cancel_conversion();
        return std::nullopt;
      }
      if (size != 0) {
        pending.bytes.append(static_cast<const char *>(xcb_get_property_value(value.get())), size);
      }
      if (initial || size == 0) {
        auto completed = std::move(pending.bytes);
        const auto completed_target = pending.target;
        cancel_conversion();
        clipboard_content_t content;
        if (completed_target == utf8) {
          content.kind = clipboard_content_t::kind_e::text;
          content.text = std::move(completed);
          return content;
        }
        auto files = parse_file_list(completed, completed_target == gnome_files);
        if (!files) return std::nullopt;
        content.kind = clipboard_content_t::kind_e::files;
        content.file_uris = std::move(*files);
        return content;
      }
      return std::nullopt;
    }

    std::optional<clipboard_content_t> dispatch(const xcb_generic_event_t &event) {
      switch (event.response_type & 0x7f) {
        case XCB_SELECTION_REQUEST:
          serve(reinterpret_cast<const xcb_selection_request_event_t &>(event));
          break;
        case XCB_SELECTION_CLEAR:
          // PRIMARY and CLIPBOARD have independent ownership, but identical
          // text while we own both. Losing just one must not erase the other.
          if (owner(clipboard) != window && owner(XCB_ATOM_PRIMARY) != window) {
            owned_text.clear();
            owned_uri_list.clear();
            owned_gnome_files.clear();
          }
          break;
        case XCB_SELECTION_NOTIFY: {
          const auto &notify = reinterpret_cast<const xcb_selection_notify_event_t &>(event);
          if (pending.window != XCB_NONE && notify.requestor == pending.window &&
              notify.selection == clipboard && notify.target == pending.target && !pending.incremental) {
            if (notify.property == property) {
              return read_property(true);
            }
            if (notify.property == XCB_NONE) {
              cancel_conversion();
            }
          }
          break;
        }
        case XCB_PROPERTY_NOTIFY: {
          const auto &notify = reinterpret_cast<const xcb_property_notify_event_t &>(event);
          if (pending.incremental && notify.window == pending.window &&
              notify.atom == property && notify.state == XCB_PROPERTY_NEW_VALUE) {
            return read_property(false);
          }
          break;
        }
        default:
          // Includes errors from unchecked requests. They never escape into
          // capture threads or terminate the process.
          break;
      }
      return std::nullopt;
    }
  };

  clipboard_t::clipboard_t(std::unique_ptr<state_t> state) : state_(std::move(state)) {}
  clipboard_t::clipboard_t(clipboard_t &&other) noexcept = default;
  clipboard_t &clipboard_t::operator=(clipboard_t &&other) noexcept = default;
  clipboard_t::~clipboard_t() = default;

  std::optional<clipboard_t> clipboard_t::make() {
    auto state = std::make_unique<state_t>();
    int screen_number = 0;
    state->connection = xcb_connect(nullptr, &screen_number);
    if (xcb_connection_has_error(state->connection)) {
      BOOST_LOG(error) << "Unable to open X11 display for PLANK clipboard sync";
      return std::nullopt;
    }
    auto screens = xcb_setup_roots_iterator(xcb_get_setup(state->connection));
    for (int index = 0; index < screen_number && screens.rem; ++index) {
      xcb_screen_next(&screens);
    }
    if (!screens.rem) {
      return std::nullopt;
    }
    state->root = screens.data->root;
    state->window = state->make_window();
    state->clipboard = state->atom("CLIPBOARD");
    state->utf8 = state->atom("UTF8_STRING");
    state->property = state->atom("PLANK_CLIPBOARD");
    state->targets = state->atom("TARGETS");
    state->plain = state->atom("text/plain");
    state->plain_utf8 = state->atom("text/plain;charset=utf-8");
    state->incr = state->atom("INCR");
    state->uri_list = state->atom("text/uri-list");
    state->gnome_files = state->atom("x-special/gnome-copied-files");
    if (!state->window || !state->clipboard || !state->utf8 || !state->property ||
        !state->targets || !state->plain || !state->plain_utf8 || !state->incr ||
        !state->uri_list || !state->gnome_files) {
      return std::nullopt;
    }
    return clipboard_t(std::move(state));
  }

  bool clipboard_t::poll_change(std::string &text) {
    clipboard_content_t content;
    if (!poll_change(content) || content.kind != clipboard_content_t::kind_e::text) {
      return false;
    }
    text = std::move(content.text);
    return true;
  }

  bool clipboard_t::poll_change(clipboard_content_t &content) {
    auto &state = *state_;
    auto current_owner = state.owner(state.clipboard);
    if (state.pending.window != XCB_NONE &&
        (state.pending.owner != current_owner ||
         std::chrono::steady_clock::now() >= state.pending.deadline)) {
      state.cancel_conversion();
    }
    std::optional<clipboard_content_t> completed;
    // Bound work per poll even when another X11 client floods our event queue.
    for (int count = 0; count < 256; ++count) {
      auto event = state.next_event ? std::move(state.next_event) :
                                     reply(xcb_poll_for_event(state.connection));
      if (!event) {
        break;
      }
      auto result = state.dispatch(*event);
      if (result) {
        completed = std::move(result);
      }
    }
    current_owner = state.owner(state.clipboard);
    if (state.pending.window == XCB_NONE && current_owner != XCB_NONE && current_owner != state.window &&
        std::chrono::steady_clock::now() >= state.next_conversion) {
      state.start_conversion(current_owner);
    }
    xcb_flush(state.connection);
    if (!completed) {
      return false;
    }
    if (completed->kind == clipboard_content_t::kind_e::text) {
      if (completed->text.empty() || !state.last_forwarded.accept(completed->text)) {
        return false;
      }
    } else if (completed->file_uris.empty()) {
      return false;
    } else if (completed->file_uris == state.last_forwarded_files &&
               current_owner == state.last_forwarded_file_owner) {
      return false;
    } else {
      state.last_forwarded_files = completed->file_uris;
      state.last_forwarded_file_owner = current_owner;
    }
    content = std::move(*completed);
    return true;
  }

  bool clipboard_t::set_text(const std::vector<std::uint8_t> &text) {
    if (text.empty() || text.size() > max_text_size) {
      return false;
    }
    auto &state = *state_;
    state.cancel_conversion();
    state.owned_uri_list.clear();
    state.owned_gnome_files.clear();
    state.last_forwarded_files.clear();
    state.last_forwarded_file_owner = XCB_NONE;
    xcb_set_selection_owner(state.connection, state.window, state.clipboard, XCB_CURRENT_TIME);
    if (state.owner(state.clipboard) != state.window) {
      BOOST_LOG(warning) << "Unable to become X11 CLIPBOARD owner for PLANK sync";
      return false;
    }
    state.owned_text.assign(reinterpret_cast<const char *>(text.data()), text.size());
    state.last_forwarded.mark(state.owned_text);
    xcb_set_selection_owner(state.connection, state.window, XCB_ATOM_PRIMARY, XCB_CURRENT_TIME);
    xcb_flush(state.connection);
    return true;
  }

  bool clipboard_t::set_files(const std::vector<std::string> &local_file_uris) {
    if (local_file_uris.empty() || local_file_uris.size() > max_file_items) {
      return false;
    }
    std::string uri_payload;
    std::string gnome_payload = "copy\n";
    for (const auto &uri : local_file_uris) {
      if (!local_file_uri(uri) ||
          uri_payload.size() > max_file_list_size - uri.size() - 2 ||
          gnome_payload.size() > max_file_list_size - uri.size() - 1) {
        return false;
      }
      uri_payload.append(uri).append("\r\n");
      gnome_payload.append(uri).push_back('\n');
    }

    auto &state = *state_;
    state.cancel_conversion();
    xcb_set_selection_owner(state.connection, state.window, state.clipboard, XCB_CURRENT_TIME);
    if (state.owner(state.clipboard) != state.window) {
      BOOST_LOG(warning) << "Unable to become X11 CLIPBOARD owner for PLANK file sync";
      return false;
    }
    state.owned_text.clear();
    state.owned_uri_list = std::move(uri_payload);
    state.owned_gnome_files = std::move(gnome_payload);
    state.last_forwarded_files = local_file_uris;
    state.last_forwarded_file_owner = state.window;
    xcb_set_selection_owner(state.connection, XCB_NONE, XCB_ATOM_PRIMARY, XCB_CURRENT_TIME);
    xcb_flush(state.connection);
    return true;
  }

  bool clipboard_t::wait_for_activity() {
    auto &state = *state_;
    if (xcb_connection_has_error(state.connection)) {
      return false;
    }
    // Reply reads can already have buffered events inside XCB, leaving the
    // socket unreadable. Preserve one for poll_change() before sleeping.
    if (!state.next_event) {
      state.next_event = reply(xcb_poll_for_event(state.connection));
    }
    if (state.next_event) {
      return true;
    }
    // INCR is a deletion-acknowledged exchange. A fixed sleep for every chunk
    // would spend the five-second transfer deadline on our own polling delay.
    // New conversions still start at most four times per second, even if a
    // clipboard owner immediately answers or refuses every request.
    auto timeout = selection_poll_interval;
    const auto until_conversion = state.next_conversion - std::chrono::steady_clock::now();
    if (state.pending.window == XCB_NONE && until_conversion > decltype(until_conversion)::zero()) {
      timeout = std::min(timeout, std::chrono::ceil<std::chrono::milliseconds>(until_conversion));
    }
    pollfd socket {xcb_get_file_descriptor(state.connection), POLLIN, 0};
    const auto result = ::poll(&socket, 1, static_cast<int>(timeout.count()));
    return (result >= 0 || errno == EINTR) &&
           !(socket.revents & (POLLERR | POLLHUP | POLLNVAL)) &&
           !xcb_connection_has_error(state.connection);
  }
}  // namespace platf::x11
#endif
