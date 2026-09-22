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

#include "logging.h"

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

    class wire_t {
    public:
      wire_t(PlankTransportNativeEndpoint *endpoint, std::stop_token stop_token)
          : endpoint(endpoint), stop_token(stop_token) {}

      std::optional<PlankClipboardFileRecord> first(std::vector<std::uint8_t> &storage) {
        auto record = receive_control_unchecked(storage);
        if (!record || record->type != PLANK_CLIPBOARD_FILE_OFFER_BEGIN ||
            record->sequence != 1) return std::nullopt;
        std::memcpy(offer.id.data(), record->offer_id, offer.id.size());
        offer.epoch = record->session_epoch;
        offer.receive_sequence = 2;
        return record;
      }

      std::optional<PlankClipboardFileRecord> control(
        std::vector<std::uint8_t> &storage,
        std::uint32_t timeout_ms = 100
      ) {
        return receive(storage, timeout_ms, false);
      }

      std::optional<PlankClipboardFileRecord> data(
        std::vector<std::uint8_t> &storage,
        std::uint32_t timeout_ms = 100
      ) {
        return receive(storage, timeout_ms, true);
      }

      bool send_control(std::uint16_t type, std::uint32_t flags,
                        const std::uint8_t *payload, std::size_t size) {
        if (size > PLANK_CLIPBOARD_FILE_CONTROL_PAYLOAD_LIMIT) return false;
        std::vector<std::uint8_t> record(PLANK_CLIPBOARD_FILE_HEADER_BYTES + size);
        if (!plank_clipboard_file_header(record.data(), record.size(), type, flags,
              static_cast<std::uint32_t>(size), offer.id.data(), offer.epoch,
              offer.send_sequence++)) return false;
        if (size != 0) {
          std::memcpy(record.data() + PLANK_CLIPBOARD_FILE_HEADER_BYTES, payload, size);
        }
        while (!stop_token.stop_requested()) {
          const auto result = plank_transport_native_file_control_send(
            endpoint, record.data(), record.size()
          );
          if (result == PLANK_TRANSPORT_OK) return true;
          if (result != PLANK_TRANSPORT_TIMEOUT) return false;
          std::this_thread::sleep_for(2ms);
        }
        return false;
      }

      offer_t offer;
      bool failed = false;

    private:
      std::optional<PlankClipboardFileRecord> receive_control_unchecked(
        std::vector<std::uint8_t> &storage
      ) {
        storage.resize(PLANK_CLIPBOARD_FILE_HEADER_BYTES +
                       PLANK_CLIPBOARD_FILE_CONTROL_PAYLOAD_LIMIT);
        std::size_t size = 0;
        while (!stop_token.stop_requested()) {
          const auto result = plank_transport_native_file_control_receive(
            endpoint, storage.data(), storage.size(), &size, 100
          );
          if (result == PLANK_TRANSPORT_TIMEOUT) continue;
          if (result != PLANK_TRANSPORT_OK) {
            failed = true;
            return std::nullopt;
          }
          storage.resize(size);
          PlankClipboardFileRecord record {};
          if (!plank_clipboard_file_decode(storage.data(), storage.size(),
                PLANK_CLIPBOARD_FILE_CONTROL_PAYLOAD_LIMIT, &record)) {
            failed = true;
            return std::nullopt;
          }
          return record;
        }
        return std::nullopt;
      }

      std::optional<PlankClipboardFileRecord> receive(
        std::vector<std::uint8_t> &storage,
        std::uint32_t timeout_ms,
        bool content
      ) {
        const auto payload_limit = content ?
          PLANK_CLIPBOARD_FILE_DATA_PREFIX_BYTES + PLANK_CLIPBOARD_FILE_DATA_BYTES :
          PLANK_CLIPBOARD_FILE_CONTROL_PAYLOAD_LIMIT;
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
          failed = true;
          return std::nullopt;
        }
        storage.resize(size);
        PlankClipboardFileRecord record {};
        if (!plank_clipboard_file_decode(storage.data(), storage.size(),
              static_cast<std::uint32_t>(payload_limit), &record) ||
            std::memcmp(record.offer_id, offer.id.data(), offer.id.size()) != 0 ||
            record.session_epoch != offer.epoch ||
            record.sequence != offer.receive_sequence++) {
          failed = true;
          return std::nullopt;
        }
        return record;
      }

      PlankTransportNativeEndpoint *endpoint;
      std::stop_token stop_token;
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
      for (std::uint32_t index = 0; index < wire.offer.begin.entry_count; ++index) {
        auto record = wire.control(storage);
        if (!record || record->type != PLANK_CLIPBOARD_FILE_OFFER_ENTRY) return false;
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

    bool receive_offer(std::stop_token stop_token,
                       PlankTransportNativeEndpoint *endpoint,
                       const publish_files_t &publish_files) {
      wire_t wire(endpoint, stop_token);
      std::vector<std::uint8_t> control_storage;
      auto first = wire.first(control_storage);
      if (!first) return false;
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

  void client_to_host_worker(
    std::stop_token stop_token,
    PlankTransportNativeEndpoint *endpoint,
    publish_files_t publish_files,
    std::string_view mode
  ) {
    if (!client_to_host_allowed(mode) || endpoint == nullptr || !publish_files) return;
    while (!stop_token.stop_requested()) {
      if (!receive_offer(stop_token, endpoint, publish_files)) {
        if (!stop_token.stop_requested()) {
          BOOST_LOG(warning) << "PLANK file clipboard receiver stopped after transfer failure"sv;
        }
        return;
      }
    }
  }
}  // namespace stream::file_clipboard

#endif
