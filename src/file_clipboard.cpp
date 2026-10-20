/**
 * @file src/file_clipboard.cpp
 * @brief Pull-driven Client-to-Host file clipboard staging.
 */
#if defined(__linux__) && defined(SUNSHINE_BUILD_X11) && defined(PLANK_TRANSPORT)

#include "file_clipboard.h"

#include <plank_clipboard_file_wire.h>
#include <plank_transport.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "src/logging.h"

namespace stream::file_clipboard {
  namespace {
    using namespace std::chrono_literals;
    using namespace std::literals;
    namespace fs = std::filesystem;

    struct entry_t {
      std::uint64_t id = 0;
      std::uint64_t parent = 0;
      std::uint8_t kind = 0;
      std::uint16_t mode = 0;
      std::uint64_t size = 0;
      std::int64_t mtime_ns = 0;
      unsigned depth = 0;
      std::string name;
      fs::path relative;
      fs::path source;
      std::uint64_t device = 0;
      std::uint64_t inode = 0;
      std::int64_t ctime_ns = 0;
    };

    struct offer_t {
      std::array<std::uint8_t, 16> id {};
      std::uint64_t epoch = 0;
      std::uint64_t receive_sequence = 1;
      std::uint64_t send_sequence = 1;
      PlankClipboardFileOfferBegin begin {};
      std::vector<entry_t> entries;
      std::map<std::uint64_t, std::size_t> by_id;
    };

    std::int64_t timespec_ns(const timespec &value) {
      constexpr std::int64_t billion = 1000000000;
      if (value.tv_sec > std::numeric_limits<std::int64_t>::max() / billion ||
          value.tv_sec < std::numeric_limits<std::int64_t>::min() / billion) {
        return value.tv_sec < 0 ? std::numeric_limits<std::int64_t>::min() :
                                 std::numeric_limits<std::int64_t>::max();
      }
      return static_cast<std::int64_t>(value.tv_sec) * billion + value.tv_nsec;
    }

    const timespec &stat_mtime(const struct stat &value) {
#if defined(__APPLE__)
      return value.st_mtimespec;
#else
      return value.st_mtim;
#endif
    }

    const timespec &stat_ctime(const struct stat &value) {
#if defined(__APPLE__)
      return value.st_ctimespec;
#else
      return value.st_ctim;
#endif
    }

    bool source_stable(const struct stat &value, const entry_t &entry) {
      return static_cast<std::uint64_t>(value.st_dev) == entry.device &&
             static_cast<std::uint64_t>(value.st_ino) == entry.inode &&
             static_cast<std::uint64_t>(value.st_size) == entry.size &&
             timespec_ns(stat_mtime(value)) == entry.mtime_ns &&
             timespec_ns(stat_ctime(value)) == entry.ctime_ns;
    }

    int hex_value(char value) {
      if (value >= '0' && value <= '9') return value - '0';
      if (value >= 'a' && value <= 'f') return value - 'a' + 10;
      if (value >= 'A' && value <= 'F') return value - 'A' + 10;
      return -1;
    }

    std::optional<fs::path> path_from_uri(std::string_view uri) {
      std::string_view encoded;
      if (uri.starts_with("file://localhost/")) {
        encoded = uri.substr(std::string_view("file://localhost").size());
      } else if (uri.starts_with("file:///") ||
                 (uri.starts_with("file:/") && !uri.starts_with("file://"))) {
        encoded = uri.substr(std::string_view("file:").size());
      } else {
        return std::nullopt;
      }
      std::string decoded;
      decoded.reserve(encoded.size());
      for (std::size_t index = 0; index < encoded.size(); ++index) {
        if (encoded[index] != '%') {
          decoded.push_back(encoded[index]);
          continue;
        }
        if (index + 2 >= encoded.size()) return std::nullopt;
        const auto high = hex_value(encoded[index + 1]);
        const auto low = hex_value(encoded[index + 2]);
        if (high < 0 || low < 0 || (high == 0 && low == 0)) return std::nullopt;
        decoded.push_back(static_cast<char>((high << 4) | low));
        index += 2;
      }
      fs::path result(decoded);
      if (!result.is_absolute() || result.empty()) return std::nullopt;
      return result;
    }

    bool append_source_tree(const fs::path &path, std::uint64_t parent,
                            unsigned depth, std::vector<entry_t> &entries,
                            std::uint64_t &total_bytes) {
      if (depth > PLANK_CLIPBOARD_FILE_MAX_DEPTH ||
          entries.size() >= PLANK_CLIPBOARD_FILE_MAX_ENTRIES) return false;
      struct stat value {};
      if (::lstat(path.c_str(), &value) != 0 || S_ISLNK(value.st_mode)) return false;
      const bool regular = S_ISREG(value.st_mode);
      const bool directory = S_ISDIR(value.st_mode);
      if ((!regular && !directory) || (regular && value.st_nlink > 1)) return false;
      const auto name = path.filename().string();
      if (!plank_clipboard_file_name_valid(
            reinterpret_cast<const std::uint8_t *>(name.data()), name.size())) return false;

      entry_t entry;
      entry.id = entries.size() + 1;
      entry.parent = parent;
      entry.kind = regular ? PLANK_CLIPBOARD_FILE_REGULAR :
                             PLANK_CLIPBOARD_FILE_DIRECTORY;
      entry.mode = static_cast<std::uint16_t>(value.st_mode & 0700);
      entry.size = regular ? static_cast<std::uint64_t>(value.st_size) : 0;
      entry.mtime_ns = timespec_ns(stat_mtime(value));
      entry.ctime_ns = timespec_ns(stat_ctime(value));
      entry.device = static_cast<std::uint64_t>(value.st_dev);
      entry.inode = static_cast<std::uint64_t>(value.st_ino);
      entry.depth = depth;
      entry.name = name;
      entry.source = path;
      if (entry.size > std::numeric_limits<std::uint64_t>::max() - total_bytes) return false;
      total_bytes += entry.size;
      const auto id = entry.id;
      entries.push_back(std::move(entry));

      if (directory) {
        std::error_code error;
        std::vector<fs::path> children;
        for (fs::directory_iterator iterator(path, error), end;
             !error && iterator != end; iterator.increment(error)) {
          children.push_back(iterator->path());
        }
        if (error) return false;
        std::sort(children.begin(), children.end());
        for (const auto &child : children) {
          if (!append_source_tree(child, id, depth + 1, entries, total_bytes)) return false;
        }
      }
      return true;
    }

    fs::path staging_root() {
      const char *xdg = std::getenv("XDG_CACHE_HOME");
      if (xdg != nullptr && *xdg != '\0') {
        return fs::path(xdg) / "plank" / "file-clipboard";
      }
      const char *home = std::getenv("HOME");
      return home != nullptr && *home != '\0' ?
        fs::path(home) / ".cache" / "plank" / "file-clipboard" : fs::path {};
    }

    std::string offer_hex(const std::array<std::uint8_t, 16> &id) {
      constexpr char digits[] = "0123456789abcdef";
      std::string result(32, '0');
      for (std::size_t index = 0; index < id.size(); ++index) {
        result[index * 2] = digits[id[index] >> 4];
        result[index * 2 + 1] = digits[id[index] & 0xf];
      }
      return result;
    }

    std::string collision_key(std::string value) {
      std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch - 'A' + 'a') :
                                      static_cast<char>(ch);
      });
      return value;
    }

    std::string file_uri(const fs::path &path) {
      constexpr char digits[] = "0123456789ABCDEF";
      const auto bytes = path.string();
      std::string result = "file://";
      for (const unsigned char ch : bytes) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '/' || ch == '-' ||
            ch == '_' || ch == '.' || ch == '~') {
          result.push_back(static_cast<char>(ch));
        } else {
          result.push_back('%');
          result.push_back(digits[ch >> 4]);
          result.push_back(digits[ch & 0xf]);
        }
      }
      return result;
    }

    bool ensure_private_root(const fs::path &root) {
      if (root.empty()) return false;
      std::error_code error;
      fs::create_directories(root, error);
      if (error || ::chmod(root.c_str(), 0700) != 0) return false;
      struct stat value {};
      return ::lstat(root.c_str(), &value) == 0 && S_ISDIR(value.st_mode) &&
             !S_ISLNK(value.st_mode) && value.st_uid == ::geteuid();
    }

    class digest_t {
    public:
      digest_t() : context(EVP_MD_CTX_new(), &EVP_MD_CTX_free) {
        valid = context && EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1;
      }
      bool update(const void *bytes, std::size_t size) {
        return valid && EVP_DigestUpdate(context.get(), bytes, size) == 1;
      }
      std::optional<std::array<std::uint8_t, 32>> finish() {
        std::array<std::uint8_t, 32> result {};
        unsigned length = 0;
        if (!valid || EVP_DigestFinal_ex(context.get(), result.data(), &length) != 1 ||
            length != result.size()) return std::nullopt;
        valid = false;
        return result;
      }
    private:
      std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context;
      bool valid = false;
    };

    /** @brief Keep deferred control records and connection state across failed offers. */
    struct inbox_t {
      std::optional<std::vector<std::uint8_t>> control;  ///< Next phase or next offer record.
      bool disconnected = false;  ///< Native transport is no longer usable.
    };

    class wire_t;
    bool parse_manifest(wire_t &wire, std::vector<std::uint8_t> &storage);

    /** @brief A bounded, session-scoped PCF2 offer exchange. */
    class wire_t {
    public:
      /**
       * @brief Bind an offer exchange to the worker's persistent inbox.
       * @param endpoint Authenticated native transport.
       * @param stop_token Session cancellation.
       * @param inbox Deferred records shared across offer recovery.
       * @param idle_timeout Maximum time without successful offer traffic.
       */
      wire_t(PlankTransportNativeEndpoint *endpoint, std::stop_token stop_token,
             inbox_t &inbox, std::chrono::milliseconds idle_timeout = 60s)
          : endpoint(endpoint), stop_token(stop_token), inbox(inbox),
            idle_timeout(idle_timeout) {}

      /** @brief Find a new offer, discarding residual records from failed transfers. */
      std::optional<PlankClipboardFileRecord> first(
        std::vector<std::uint8_t> &storage,
        std::uint32_t timeout_ms = 100
      ) {
        // No new DATA is legal before a READ_REQUEST. Clear residual old chunks
        // so an abandoned transfer cannot fill the independent data queue.
        std::vector<std::uint8_t> stale;
        read(stale, 0, true);
        failed = false;
        auto record = read(storage, timeout_ms, false);
        if (!record || record->type != PLANK_CLIPBOARD_FILE_OFFER_BEGIN ||
            record->sequence != 1) return std::nullopt;
        adopt(*record);
        return record;
      }

      /** @brief Initialize an outgoing Host offer with a fresh identity. */
      void start_source(const std::array<std::uint8_t, 16> &id, std::uint64_t epoch) {
        offer = {};
        offer.id = id;
        offer.epoch = epoch;
        source = true;
        progress();
      }

      /** @brief Read the next control record, resolving crossed offers in Host's favor. */
      std::optional<PlankClipboardFileRecord> control(
        std::vector<std::uint8_t> &storage,
        std::uint32_t timeout_ms = 100
      ) {
        while (active()) {
          auto record = read(storage, timeout_ms, false);
          if (!record) continue;
          if (matches(*record)) return accept(*record);
          if (new_offer(*record)) {
            if (drain_competing(*record, storage)) continue;
            if (failed) return std::nullopt;
            defer(storage);
            failed = true;
          }
          // Old offer responses can remain on the reliable queue after abort.
          // They do not advance this offer's sequence or inactivity deadline.
        }
        return std::nullopt;
      }

      /** @brief Wait for DATA while observing terminal controls on the other lane. */
      std::optional<PlankClipboardFileRecord> data(
        std::vector<std::uint8_t> &storage,
        std::uint32_t timeout_ms = 100
      ) {
        while (active()) {
          if (auto record = read(storage, timeout_ms, true)) {
            if (matches(*record)) return accept(*record);
          }
          if (failed) break;
          if (inbox.control) continue;
          std::vector<std::uint8_t> control_storage;
          if (auto record = read(control_storage, 0, false)) {
            if (matches(*record)) {
              if (record->type == PLANK_CLIPBOARD_FILE_CANCEL ||
                  record->type == PLANK_CLIPBOARD_FILE_ERROR) {
                PlankClipboardFileTerminal terminal {};
                if (!plank_clipboard_file_terminal_decode(
                      record->payload, record->payload_size, &terminal) ||
                    terminal.materialization_id != materialization ||
                    record->sequence < offer.receive_sequence) {
                  failed = true;
                  break;
                }
                // A terminal ends the whole offer even if DATA with a lower
                // sequence remains in flight on the independently queued lane.
                offer.receive_sequence = record->sequence + 1;
                progress();
                storage = std::move(control_storage);
                plank_clipboard_file_decode(storage.data(), storage.size(),
                  PLANK_CLIPBOARD_FILE_CONTROL_PAYLOAD_LIMIT, &*record);
                return record;
              }
              // ENTRY_COMPLETE can overtake DATA across independent queues.
              // Validate its sequence only when the control phase consumes it.
              defer(control_storage);
            } else if (new_offer(*record)) {
              defer(control_storage);
              failed = true;
            }
          }
        }
        return std::nullopt;
      }

      /** @brief Send a sequenced control record with a bounded backpressure wait. */
      bool send_control(std::uint16_t type, std::uint32_t flags,
                        const std::uint8_t *payload, std::size_t size) {
        return send(type, flags, payload, size, false);
      }

      /** @brief Send a sequenced data record with a bounded backpressure wait. */
      bool send_data(const std::uint8_t *payload, std::size_t size) {
        return send(PLANK_CLIPBOARD_FILE_DATA, 0, payload, size, true);
      }

      offer_t offer;  ///< Active offer identity, sequence, and manifest.
      std::uint64_t materialization = 0;  ///< Expected sink materialization for terminals.
      bool failed = false;  ///< This offer must be abandoned, not the whole worker.

    private:
      /** @brief Reset inactivity only after useful offer traffic. */
      void progress() { last_activity = std::chrono::steady_clock::now(); }

      /** @brief Check cancellation, connection state, and the inactivity deadline. */
      bool active() {
        if (inbox.disconnected ||
            std::chrono::steady_clock::now() - last_activity >= idle_timeout) failed = true;
        return !failed && !inbox.disconnected && !stop_token.stop_requested();
      }

      /** @brief Test the active offer identity independently of its sequence. */
      bool matches(const PlankClipboardFileRecord &record) const {
        return std::memcmp(record.offer_id, offer.id.data(), offer.id.size()) == 0 &&
               record.session_epoch == offer.epoch;
      }

      /** @brief Recognize a potential resynchronization boundary. */
      static bool new_offer(const PlankClipboardFileRecord &record) {
        return record.type == PLANK_CLIPBOARD_FILE_OFFER_BEGIN && record.sequence == 1;
      }

      /** @brief Initialize a sink without disturbing a concurrent source identity. */
      void adopt(const PlankClipboardFileRecord &record) {
        std::memcpy(offer.id.data(), record.offer_id, offer.id.size());
        offer.epoch = record.session_epoch;
        offer.receive_sequence = 2;
        progress();
      }

      /**
       * @brief Validate and drain one losing Client manifest without advancing Host sequence.
       * @param record Candidate foreign OFFER_BEGIN with storage-backed payload.
       * @param storage Receive buffer reusable while consuming its bounded manifest.
       * @return True after a valid crossed manifest was completely drained.
       */
      bool drain_competing(const PlankClipboardFileRecord &record,
                           std::vector<std::uint8_t> &storage) {
        if (!source || collision_drained || matches(record) || !new_offer(record)) return false;
        PlankClipboardFileOfferBegin begin {};
        if (!plank_clipboard_file_offer_begin_decode(
              record.payload, record.payload_size, &begin) ||
            begin.direction != PLANK_CLIPBOARD_FILE_CLIENT_TO_HOST) return false;
        // A Windows source yields to the Host offer and retries its paste
        // after receiving it. Consume its already queued manifest without
        // acknowledging or cancelling the losing offer.
        wire_t competing(endpoint, stop_token, inbox, idle_timeout);
        competing.adopt(record);
        collision_drained = true;
        if (!parse_manifest(competing, storage)) {
          failed = true;
          return false;
        }
        progress();
        return true;
      }

      /** @brief Preserve a record for the next phase or offer. */
      void defer(std::vector<std::uint8_t> &storage) {
        inbox.control = std::move(storage);
      }

      /** @brief Validate one selected lane's sequence after demultiplexing. */
      std::optional<PlankClipboardFileRecord> accept(const PlankClipboardFileRecord &record) {
        if (record.sequence != offer.receive_sequence) {
          failed = true;
          return std::nullopt;
        }
        ++offer.receive_sequence;
        progress();
        return record;
      }

      /** @brief Receive one native record without advancing any offer sequence. */
      std::optional<PlankClipboardFileRecord> read(
        std::vector<std::uint8_t> &storage, std::uint32_t timeout_ms, bool content
      ) {
        if (stop_token.stop_requested() || inbox.disconnected) return std::nullopt;
        const auto payload_limit = content ?
          PLANK_CLIPBOARD_FILE_DATA_PREFIX_BYTES + PLANK_CLIPBOARD_FILE_DATA_BYTES :
          PLANK_CLIPBOARD_FILE_CONTROL_PAYLOAD_LIMIT;
        if (!content && inbox.control) {
          storage = std::move(*inbox.control);
          inbox.control.reset();
        } else {
          storage.resize(PLANK_CLIPBOARD_FILE_HEADER_BYTES + payload_limit);
          std::size_t size = 0;
          const auto result = content ?
            plank_transport_native_file_data_receive(
              endpoint, storage.data(), storage.size(), &size, timeout_ms
            ) :
            plank_transport_native_file_control_receive(
              endpoint, storage.data(), storage.size(), &size, timeout_ms
            );
          if (result == PLANK_TRANSPORT_TIMEOUT) return std::nullopt;
          if (result != PLANK_TRANSPORT_OK) {
            inbox.disconnected = true;
            failed = true;
            return std::nullopt;
          }
          storage.resize(size);
        }
        PlankClipboardFileRecord record {};
        if (!plank_clipboard_file_decode(storage.data(), storage.size(),
              static_cast<std::uint32_t>(payload_limit), &record)) {
          failed = true;
          return std::nullopt;
        }
        return record;
      }

      /** @brief Encode and send a record, bounded by the same wire inactivity limit. */
      bool send(std::uint16_t type, std::uint32_t flags,
                const std::uint8_t *payload, std::size_t size, bool content) {
        const auto limit = content ?
          PLANK_CLIPBOARD_FILE_DATA_PREFIX_BYTES + PLANK_CLIPBOARD_FILE_DATA_BYTES :
          PLANK_CLIPBOARD_FILE_CONTROL_PAYLOAD_LIMIT;
        if (size > limit) return false;
        std::vector<std::uint8_t> record(PLANK_CLIPBOARD_FILE_HEADER_BYTES + size);
        if (!plank_clipboard_file_header(record.data(), record.size(), type, flags,
              static_cast<std::uint32_t>(size), offer.id.data(), offer.epoch,
              offer.send_sequence++)) return false;
        if (size != 0) {
          std::memcpy(record.data() + PLANK_CLIPBOARD_FILE_HEADER_BYTES, payload, size);
        }
        // Error reporting after a failed offer also needs a finite send budget.
        while (!stop_token.stop_requested() && !inbox.disconnected &&
               std::chrono::steady_clock::now() - last_activity < idle_timeout) {
          const auto result = content ?
            plank_transport_native_file_data_send(endpoint, record.data(), record.size()) :
            plank_transport_native_file_control_send(endpoint, record.data(), record.size());
          if (result == PLANK_TRANSPORT_OK) {
            progress();
            return true;
          }
          if (result != PLANK_TRANSPORT_TIMEOUT) {
            inbox.disconnected = true;
            return false;
          }
          if (source && !collision_drained && !inbox.control) {
            // Both sources can fill their flow-control windows before either
            // finishes its manifest. Host wins by draining the Client source
            // while its own send is backpressured, then resumes this record.
            std::vector<std::uint8_t> storage;
            if (auto incoming = read(storage, 0, false)) {
              if (!drain_competing(*incoming, storage)) {
                if (failed) return false;
                if (matches(*incoming) || new_offer(*incoming)) {
                  // A future response is validated only in the receiving phase.
                  defer(storage);
                }
              }
            }
            if (failed) return false;
          }
          std::this_thread::sleep_for(2ms);
        }
        failed = true;
        return false;
      }

      PlankTransportNativeEndpoint *endpoint;  ///< Authenticated transport.
      std::stop_token stop_token;  ///< Session cancellation.
      inbox_t &inbox;  ///< Worker-owned recovery state.
      std::chrono::milliseconds idle_timeout;  ///< Maximum inactive wire interval.
      std::chrono::steady_clock::time_point last_activity = std::chrono::steady_clock::now();  ///< Last useful traffic.
      bool source = false;  ///< Host sources win crossed offers.
      bool collision_drained = false;  ///< At most one competing manifest per source offer.
    };

    bool parse_manifest(wire_t &wire, std::vector<std::uint8_t> &storage) {
      if (!plank_clipboard_file_offer_begin_decode(
            storage.data() + PLANK_CLIPBOARD_FILE_HEADER_BYTES,
            storage.size() - PLANK_CLIPBOARD_FILE_HEADER_BYTES,
            &wire.offer.begin) ||
          wire.offer.begin.direction != PLANK_CLIPBOARD_FILE_CLIENT_TO_HOST ||
          wire.offer.begin.total_bytes > (1ULL << 40)) return false;

      std::set<std::string> paths;
      std::uint64_t total_bytes = 0;
      std::uint32_t top_level = 0;
      std::size_t manifest_bytes = PLANK_CLIPBOARD_FILE_OFFER_BEGIN_BYTES;
      for (std::uint32_t index = 0; index < wire.offer.begin.entry_count; ++index) {
        auto record = wire.control(storage);
        if (!record || record->type != PLANK_CLIPBOARD_FILE_OFFER_ENTRY) return false;
        manifest_bytes += record->payload_size;
        if (manifest_bytes > PLANK_CLIPBOARD_FILE_MAX_MANIFEST_BYTES) return false;
        PlankClipboardFileOfferEntry decoded {};
        if (!plank_clipboard_file_offer_entry_decode(
              record->payload, record->payload_size, &decoded) ||
            wire.offer.by_id.contains(decoded.entry_id)) return false;

        entry_t entry;
        entry.id = decoded.entry_id;
        entry.parent = decoded.parent_id;
        entry.kind = decoded.kind;
        entry.mode = decoded.mode;
        entry.size = decoded.size;
        entry.mtime_ns = decoded.mtime_ns;
        entry.name.assign(reinterpret_cast<const char *>(decoded.name), decoded.name_size);
        if (entry.parent == 0) {
          entry.depth = 1;
          entry.relative = fs::path(entry.name);
          ++top_level;
        } else {
          const auto parent = wire.offer.by_id.find(entry.parent);
          if (parent == wire.offer.by_id.end() ||
              wire.offer.entries[parent->second].kind != PLANK_CLIPBOARD_FILE_DIRECTORY) {
            return false;
          }
          entry.depth = wire.offer.entries[parent->second].depth + 1;
          entry.relative = wire.offer.entries[parent->second].relative / fs::path(entry.name);
        }
        if (entry.depth > PLANK_CLIPBOARD_FILE_MAX_DEPTH ||
            entry.size > std::numeric_limits<std::uint64_t>::max() - total_bytes ||
            !paths.insert(collision_key(entry.relative.string())).second) return false;
        total_bytes += entry.size;
        wire.offer.by_id.emplace(entry.id, wire.offer.entries.size());
        wire.offer.entries.push_back(std::move(entry));
      }
      auto end = wire.control(storage);
      return end && end->type == PLANK_CLIPBOARD_FILE_OFFER_END &&
             end->payload_size == 0 && top_level == wire.offer.begin.top_level_count &&
             total_bytes == wire.offer.begin.total_bytes;
    }

    bool set_mtime(int fd, std::int64_t nanoseconds) {
      constexpr std::int64_t billion = 1000000000;
      timespec times[2] {};
      times[0].tv_nsec = UTIME_OMIT;
      times[1].tv_sec = static_cast<time_t>(nanoseconds / billion);
      times[1].tv_nsec = static_cast<long>(nanoseconds % billion);
      if (times[1].tv_nsec < 0) {
        --times[1].tv_sec;
        times[1].tv_nsec += billion;
      }
      return ::futimens(fd, times) == 0;
    }

    bool set_path_mtime(const fs::path &path, std::int64_t nanoseconds) {
      constexpr std::int64_t billion = 1000000000;
      timespec times[2] {};
      times[0].tv_nsec = UTIME_OMIT;
      times[1].tv_sec = static_cast<time_t>(nanoseconds / billion);
      times[1].tv_nsec = static_cast<long>(nanoseconds % billion);
      if (times[1].tv_nsec < 0) {
        --times[1].tv_sec;
        times[1].tv_nsec += billion;
      }
      return ::utimensat(AT_FDCWD, path.c_str(), times, AT_SYMLINK_NOFOLLOW) == 0;
    }

    bool free_space_available(const fs::path &root, std::uint64_t bytes) {
      struct statvfs value {};
      if (::statvfs(root.c_str(), &value) != 0) return false;
      const auto available = static_cast<__uint128_t>(value.f_bavail) *
                             static_cast<__uint128_t>(value.f_frsize);
      return available >= static_cast<__uint128_t>(bytes);
    }

    bool send_offer(std::stop_token stop_token,
                    PlankTransportNativeEndpoint *endpoint,
                    inbox_t &inbox,
                    const std::vector<std::string> &uris,
                    std::uint64_t generation) {
      if (uris.empty() || uris.size() > PLANK_CLIPBOARD_FILE_MAX_TOP_LEVEL) return false;
      std::vector<entry_t> entries;
      std::uint64_t total_bytes = 0;
      for (const auto &uri : uris) {
        const auto path = path_from_uri(uri);
        if (!path || !append_source_tree(*path, 0, 1, entries, total_bytes)) {
          return false;
        }
      }
      if (entries.empty() || total_bytes > (1ULL << 40)) return false;

      std::array<std::uint8_t, 16> id {};
      std::uint64_t epoch = 0;
      if (RAND_bytes(id.data(), id.size()) != 1 ||
          RAND_bytes(reinterpret_cast<unsigned char *>(&epoch), sizeof(epoch)) != 1 ||
          !epoch) return false;
      wire_t wire(endpoint, stop_token, inbox);
      wire.start_source(id, epoch);
      wire.offer.entries = entries;
      for (std::size_t index = 0; index < entries.size(); ++index) {
        wire.offer.by_id.emplace(entries[index].id, index);
      }
      wire.offer.begin = {
        PLANK_CLIPBOARD_FILE_HOST_TO_CLIENT,
        generation,
        static_cast<std::uint32_t>(uris.size()),
        static_cast<std::uint32_t>(entries.size()),
        total_bytes,
      };
      std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_OFFER_BEGIN_BYTES> begin {};
      if (!plank_clipboard_file_offer_begin_encode(begin.data(), &wire.offer.begin) ||
          !wire.send_control(PLANK_CLIPBOARD_FILE_OFFER_BEGIN, 0,
                             begin.data(), begin.size())) return false;
      // Every local source failure must wake the peer's DATA/control wait.
      // The terminal is scoped after BEGIN so no phantom offer is created.
      bool transferred = false;
      std::uint64_t materialization = 0;
      struct source_terminal_t {
        wire_t &wire;  ///< Offer being served.
        bool &transferred;  ///< Suppress cancellation after successful readiness.
        std::uint64_t &materialization;  ///< Zero before the peer materializes.
        /** @brief Cancel any partially served source offer on early return. */
        ~source_terminal_t() {
          if (transferred) return;
          PlankClipboardFileTerminal terminal {
            materialization, PLANK_CLIPBOARD_FILE_REASON_SOURCE_UNAVAILABLE, 0
          };
          std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_TERMINAL_BYTES> payload {};
          if (plank_clipboard_file_terminal_encode(payload.data(), &terminal)) {
            wire.send_control(PLANK_CLIPBOARD_FILE_CANCEL, 0, payload.data(), payload.size());
          }
        }
      } terminal {wire, transferred, materialization};
      for (const auto &entry : entries) {
        std::array<std::uint8_t,
          PLANK_CLIPBOARD_FILE_OFFER_ENTRY_PREFIX_BYTES +
          PLANK_CLIPBOARD_FILE_MAX_NAME_BYTES> payload {};
        PlankClipboardFileOfferEntry encoded {
          entry.id, entry.parent, entry.kind, entry.mode, entry.size, entry.mtime_ns,
          reinterpret_cast<const std::uint8_t *>(entry.name.data()),
          static_cast<std::uint16_t>(entry.name.size()),
        };
        std::size_t payload_size = 0;
        if (!plank_clipboard_file_offer_entry_encode(
              payload.data(), payload.size(), &encoded, &payload_size) ||
            !wire.send_control(PLANK_CLIPBOARD_FILE_OFFER_ENTRY, 0,
                               payload.data(), payload_size)) return false;
      }
      if (!wire.send_control(PLANK_CLIPBOARD_FILE_OFFER_END, 0, nullptr, 0)) return false;

      std::vector<std::uint8_t> storage;
      bool acknowledged = false;
      while (!stop_token.stop_requested() && !materialization) {
        const auto record = wire.control(storage);
        if (!record) {
          if (wire.failed) return false;
          continue;
        }
        if (record->type == PLANK_CLIPBOARD_FILE_OFFER_ACK) {
          PlankClipboardFileOfferAck ack {};
          if (acknowledged || !plank_clipboard_file_offer_ack_decode(
                record->payload, record->payload_size, &ack)) return false;
          acknowledged = true;
        } else if (record->type == PLANK_CLIPBOARD_FILE_MATERIALIZE) {
          if (!acknowledged || record->flags != PLANK_CLIPBOARD_FILE_FLAG_ALL_ITEMS ||
              !plank_clipboard_file_materialization_decode(
                record->payload, record->payload_size, &materialization)) return false;
        } else if (record->type == PLANK_CLIPBOARD_FILE_CANCEL ||
                   record->type == PLANK_CLIPBOARD_FILE_ERROR) {
          return false;
        } else {
          return false;
        }
      }

      for (const auto &entry : entries) {
        if (entry.kind != PLANK_CLIPBOARD_FILE_REGULAR) continue;
        digest_t digest;
        std::uint64_t offset = 0;
        int fd = -1;
        if (entry.size != 0) {
          fd = ::open(entry.source.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
          struct stat current {};
          if (fd < 0 || ::fstat(fd, &current) != 0 || !source_stable(current, entry)) {
            if (fd >= 0) ::close(fd);
            return false;
          }
        }
        while (offset < entry.size) {
          const auto record = wire.control(storage);
          if (!record) {
            if (wire.failed || stop_token.stop_requested()) {
              ::close(fd);
              return false;
            }
            continue;
          }
          PlankClipboardFileRange range {};
          if (record->type != PLANK_CLIPBOARD_FILE_READ_REQUEST ||
              !plank_clipboard_file_decode_range(
                record->payload, record->payload_size, 0, &range) ||
              range.materialization_id != materialization || range.entry_id != entry.id ||
              range.offset != offset || range.size > entry.size - offset) {
            ::close(fd);
            return false;
          }
          std::vector<std::uint8_t> payload(
            PLANK_CLIPBOARD_FILE_DATA_PREFIX_BYTES + range.size
          );
          if (!plank_clipboard_file_range_header(
                payload.data(), materialization, entry.id, offset, range.size)) {
            ::close(fd);
            return false;
          }
          const auto count = ::pread(
            fd, payload.data() + PLANK_CLIPBOARD_FILE_DATA_PREFIX_BYTES,
            range.size, static_cast<off_t>(offset)
          );
          if (count != static_cast<ssize_t>(range.size) ||
              !digest.update(payload.data() + PLANK_CLIPBOARD_FILE_DATA_PREFIX_BYTES,
                             range.size) ||
              !wire.send_data(payload.data(), payload.size())) {
            ::close(fd);
            return false;
          }
          offset += range.size;
        }
        if (fd >= 0) {
          struct stat current {};
          const bool stable = ::fstat(fd, &current) == 0 && source_stable(current, entry);
          ::close(fd);
          if (!stable) return false;
        }
        const auto hash = digest.finish();
        if (!hash) return false;
        PlankClipboardFileEntryComplete complete {
          materialization, entry.id, entry.size, {0}
        };
        std::memcpy(complete.sha256, hash->data(), hash->size());
        std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_ENTRY_COMPLETE_BYTES> payload {};
        if (!plank_clipboard_file_entry_complete_encode(payload.data(), &complete) ||
            !wire.send_control(PLANK_CLIPBOARD_FILE_ENTRY_COMPLETE, 0,
                               payload.data(), payload.size())) return false;
      }

      while (!stop_token.stop_requested()) {
        const auto record = wire.control(storage);
        if (!record) {
          if (wire.failed) return false;
          continue;
        }
        std::uint64_t ready = 0;
        if (record->type == PLANK_CLIPBOARD_FILE_TRANSFER_READY &&
            plank_clipboard_file_materialization_decode(
              record->payload, record->payload_size, &ready) && ready == materialization) {
          transferred = true;
          BOOST_LOG(info) << "PLANK Host file clipboard materialized: "sv
                          << entries.size() << " entries, "sv << total_bytes << " bytes"sv;
          return true;
        }
        return false;
      }
      return false;
    }

    bool receive_offer(std::stop_token stop_token,
                       wire_t &wire,
                       std::vector<std::uint8_t> &control_storage,
                       const publish_files_t &publish_files) {
      const auto fail = [&](std::uint16_t reason, std::uint64_t materialization = 0) {
        PlankClipboardFileTerminal terminal {materialization, reason, 0};
        std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_TERMINAL_BYTES> payload {};
        if (plank_clipboard_file_terminal_encode(payload.data(), &terminal)) {
          wire.send_control(PLANK_CLIPBOARD_FILE_ERROR, 0, payload.data(), payload.size());
        }
        return false;
      };
      if (!parse_manifest(wire, control_storage)) {
        return fail(PLANK_CLIPBOARD_FILE_REASON_INVALID_MANIFEST);
      }

      const auto root = staging_root();
      if (!ensure_private_root(root) ||
          !free_space_available(root, wire.offer.begin.total_bytes)) {
        return fail(PLANK_CLIPBOARD_FILE_REASON_NO_SPACE);
      }
      const auto stem = offer_hex(wire.offer.id);
      const auto partial = root / (stem + ".partial");
      const auto tree = partial / "tree";
      const auto blobs = partial / "blobs";
      const auto completed = root / stem;
      std::error_code error;
      fs::remove_all(partial, error);
      error.clear();
      if (!fs::create_directories(tree, error) || error ||
          !fs::create_directories(blobs, error) || error ||
          ::chmod(partial.c_str(), 0700) != 0 ||
          ::chmod(tree.c_str(), 0700) != 0 || ::chmod(blobs.c_str(), 0700) != 0) {
        fs::remove_all(partial, error);
        return fail(PLANK_CLIPBOARD_FILE_REASON_DESTINATION_UNAVAILABLE);
      }
      for (const auto &entry : wire.offer.entries) {
        if (entry.kind == PLANK_CLIPBOARD_FILE_DIRECTORY) {
          if (!fs::create_directory(tree / entry.relative, error) || error) {
            fs::remove_all(partial, error);
            return fail(PLANK_CLIPBOARD_FILE_REASON_DESTINATION_UNAVAILABLE);
          }
        }
      }

      std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_OFFER_ACK_BYTES> ack {};
      if (!plank_clipboard_file_offer_ack_encode(
            ack.data(), PLANK_CLIPBOARD_FILE_DATA_BYTES,
            PLANK_CLIPBOARD_FILE_MAX_OUTSTANDING_BYTES) ||
          !wire.send_control(PLANK_CLIPBOARD_FILE_OFFER_ACK, 0, ack.data(), ack.size())) {
        fs::remove_all(partial, error);
        return false;
      }
      std::uint64_t materialization = 0;
      if (RAND_bytes(reinterpret_cast<unsigned char *>(&materialization),
                     sizeof(materialization)) != 1 || !materialization) {
        fs::remove_all(partial, error);
        return fail(PLANK_CLIPBOARD_FILE_REASON_INTERNAL_ERROR);
      }
      std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_MATERIALIZE_BYTES> materialize {};
      if (!plank_clipboard_file_materialization_encode(
            materialize.data(), materialization) ||
          !wire.send_control(PLANK_CLIPBOARD_FILE_MATERIALIZE,
            PLANK_CLIPBOARD_FILE_FLAG_ALL_ITEMS,
            materialize.data(), materialize.size())) {
        fs::remove_all(partial, error);
        return false;
      }

      wire.materialization = materialization;
      std::vector<std::uint8_t> data_storage;
      for (const auto &entry : wire.offer.entries) {
        if (entry.kind != PLANK_CLIPBOARD_FILE_REGULAR) continue;
        const auto blob = blobs / std::to_string(entry.id);
        const int fd = ::open(blob.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0) {
          fs::remove_all(partial, error);
          return fail(PLANK_CLIPBOARD_FILE_REASON_DESTINATION_UNAVAILABLE, materialization);
        }
        digest_t digest;
        bool valid = true;
        std::uint64_t offset = 0;
        while (valid && offset < entry.size) {
          const auto request_size = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(PLANK_CLIPBOARD_FILE_DATA_BYTES, entry.size - offset)
          );
          std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_DATA_PREFIX_BYTES> request {};
          valid = plank_clipboard_file_range_header(
                    request.data(), materialization, entry.id, offset, request_size) &&
                  wire.send_control(PLANK_CLIPBOARD_FILE_READ_REQUEST, 0,
                                    request.data(), request.size());
          std::optional<PlankClipboardFileRecord> record;
          while (valid && !record && !stop_token.stop_requested()) {
            record = wire.data(data_storage);
            if (!record && wire.failed) valid = false;
          }
          PlankClipboardFileRange range {};
          if (!valid || !record || record->type != PLANK_CLIPBOARD_FILE_DATA ||
              !plank_clipboard_file_decode_range(
                record->payload, record->payload_size, 1, &range) ||
              range.materialization_id != materialization || range.entry_id != entry.id ||
              range.offset != offset || range.size != request_size) {
            valid = false;
            break;
          }
          const auto *bytes = range.bytes;
          std::size_t remaining = range.size;
          while (remaining != 0) {
            const auto written = ::write(fd, bytes, remaining);
            if (written <= 0) {
              valid = false;
              break;
            }
            bytes += written;
            remaining -= static_cast<std::size_t>(written);
          }
          valid = valid && digest.update(range.bytes, range.size);
          offset += range.size;
        }

        std::optional<PlankClipboardFileRecord> complete_record;
        while (valid && !complete_record && !stop_token.stop_requested()) {
          complete_record = wire.control(control_storage);
          if (!complete_record && wire.failed) valid = false;
        }
        PlankClipboardFileEntryComplete complete {};
        const auto expected_digest = digest.finish();
        valid = valid && complete_record && expected_digest &&
                complete_record->type == PLANK_CLIPBOARD_FILE_ENTRY_COMPLETE &&
                plank_clipboard_file_entry_complete_decode(
                  complete_record->payload, complete_record->payload_size, &complete) &&
                complete.materialization_id == materialization &&
                complete.entry_id == entry.id && complete.size == entry.size &&
                std::memcmp(complete.sha256, expected_digest->data(),
                            expected_digest->size()) == 0 &&
                ::fsync(fd) == 0 && ::fchmod(fd, entry.mode & 0700) == 0 &&
                set_mtime(fd, entry.mtime_ns);
        ::close(fd);
        if (valid) fs::rename(blob, tree / entry.relative, error);
        if (!valid || error) {
          fs::remove_all(partial, error);
          return fail(valid ? PLANK_CLIPBOARD_FILE_REASON_DESTINATION_UNAVAILABLE :
                              PLANK_CLIPBOARD_FILE_REASON_INTEGRITY_FAILED,
                      materialization);
        }
      }

      for (auto iterator = wire.offer.entries.rbegin();
           iterator != wire.offer.entries.rend(); ++iterator) {
        if (iterator->kind != PLANK_CLIPBOARD_FILE_DIRECTORY) continue;
        const auto path = tree / iterator->relative;
        if (::chmod(path.c_str(), iterator->mode & 0700) != 0 ||
            !set_path_mtime(path, iterator->mtime_ns)) {
          fs::remove_all(partial, error);
          return fail(PLANK_CLIPBOARD_FILE_REASON_DESTINATION_UNAVAILABLE, materialization);
        }
      }
      fs::remove(blobs, error);
      if (!error && !fs::exists(completed)) fs::rename(tree, completed, error);
      if (error || fs::exists(tree)) {
        fs::remove_all(partial, error);
        return fail(PLANK_CLIPBOARD_FILE_REASON_DESTINATION_UNAVAILABLE, materialization);
      }
      fs::remove(partial, error);

      std::vector<std::string> uris;
      for (const auto &entry : wire.offer.entries) {
        if (entry.parent == 0) uris.push_back(file_uri(completed / entry.relative));
      }
      if (!publish_files || !publish_files(uris)) {
        return fail(PLANK_CLIPBOARD_FILE_REASON_DESTINATION_UNAVAILABLE, materialization);
      }
      if (!wire.send_control(PLANK_CLIPBOARD_FILE_TRANSFER_READY, 0,
            materialize.data(), materialize.size())) return false;
      BOOST_LOG(info) << "PLANK file clipboard ready: "sv
                      << wire.offer.entries.size() << " entries, "sv
                      << wire.offer.begin.total_bytes << " bytes"sv;
      return true;
    }
  }  // namespace

  bool client_to_host_allowed(std::string_view mode) {
    return mode == "client-to-host" || mode == "bidirectional";
  }

  bool host_to_client_allowed(std::string_view mode) {
    return mode == "host-to-client" || mode == "bidirectional";
  }

  void worker(
    std::stop_token stop_token,
    PlankTransportNativeEndpoint *endpoint,
    publish_files_t publish_files,
    take_files_t take_files,
    std::string_view mode
  ) {
    if (endpoint == nullptr ||
        (!client_to_host_allowed(mode) && !host_to_client_allowed(mode))) return;
    std::uint64_t generation = 0;
    inbox_t inbox;
    while (!stop_token.stop_requested() && !inbox.disconnected) {
      if (host_to_client_allowed(mode) && take_files) {
        if (auto files = take_files()) {
          if (!send_offer(stop_token, endpoint, inbox, *files, ++generation) &&
              !stop_token.stop_requested()) {
            BOOST_LOG(warning) << "PLANK Host file clipboard offer failed"sv;
          }
          continue;
        }
      }
      if (!client_to_host_allowed(mode)) {
        std::this_thread::sleep_for(25ms);
        continue;
      }
      wire_t wire(endpoint, stop_token, inbox);
      std::vector<std::uint8_t> storage;
      if (!wire.first(storage, 25)) {
        if (wire.failed) {
          BOOST_LOG(warning) << "PLANK file clipboard skipped invalid residual record"sv;
        }
        continue;
      }
      if (!receive_offer(stop_token, wire, storage, publish_files) &&
          !stop_token.stop_requested()) {
        BOOST_LOG(warning) << "PLANK file clipboard transfer failed; awaiting next offer"sv;
      }
    }
  }
}  // namespace stream::file_clipboard

#endif
