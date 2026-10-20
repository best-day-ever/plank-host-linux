/**
 * @file tests/clipboard/file-recovery.cxx
 * @brief Exercise the real PCF2 worker using deterministic native-lane queues.
 */
#if defined(__APPLE__)
#define __linux__ 1
#endif
#define SUNSHINE_BUILD_X11 1
#define PLANK_TRANSPORT 1
#include "src/file_clipboard.cpp"

#include <deque>
#include <iostream>
#include <stdexcept>

using namespace std::chrono_literals;
using namespace stream::file_clipboard;
#define REQUIRE(condition) do { if (!(condition)) throw std::runtime_error( \
  std::string(__func__) + ":" + std::to_string(__LINE__) + ": " #condition); } while (0)

/** @brief Deterministic transport substitute; production encoding and worker stay intact. */
struct PlankTransportNativeEndpoint {
  std::deque<std::vector<std::uint8_t>> controls, data;
  std::function<void(const PlankClipboardFileRecord &)> sent;
  unsigned data_timeouts = 0;
  unsigned control_timeouts = 0;
  bool block_sends = false;
  std::vector<std::uint16_t> sent_types;
};

/** @brief Pop one native packet, simulating the transport's timeout contract. */
static int32_t pop(std::deque<std::vector<std::uint8_t>> &queue,
                   uint8_t *out, size_t capacity, size_t *size, uint32_t timeout) {
  if (queue.empty()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(std::min(timeout, 1u)));
    return PLANK_TRANSPORT_TIMEOUT;
  }
  REQUIRE(queue.front().size() <= capacity);
  *size = queue.front().size();
  std::memcpy(out, queue.front().data(), *size);
  queue.pop_front();
  return PLANK_TRANSPORT_OK;
}
extern "C" int32_t plank_transport_native_file_control_receive(
  PlankTransportNativeEndpoint *endpoint, uint8_t *out, size_t capacity,
  size_t *size, uint32_t timeout) {
  if (timeout && endpoint->control_timeouts) {
    --endpoint->control_timeouts;
    return PLANK_TRANSPORT_TIMEOUT;
  }
  return pop(endpoint->controls, out, capacity, size, timeout);
}
extern "C" int32_t plank_transport_native_file_data_receive(
  PlankTransportNativeEndpoint *endpoint, uint8_t *out, size_t capacity,
  size_t *size, uint32_t timeout) {
  if (endpoint->data_timeouts) {
    --endpoint->data_timeouts;
    return PLANK_TRANSPORT_TIMEOUT;
  }
  return pop(endpoint->data, out, capacity, size, timeout);
}
extern "C" int32_t plank_transport_native_file_control_send(
  PlankTransportNativeEndpoint *endpoint, const uint8_t *bytes, size_t size) {
  if (endpoint->block_sends) return PLANK_TRANSPORT_TIMEOUT;
  PlankClipboardFileRecord record {};
  REQUIRE(plank_clipboard_file_decode(bytes, size,
    PLANK_CLIPBOARD_FILE_CONTROL_PAYLOAD_LIMIT, &record));
  endpoint->sent_types.push_back(record.type);
  if (endpoint->sent) endpoint->sent(record);
  return PLANK_TRANSPORT_OK;
}
extern "C" int32_t plank_transport_native_file_data_send(
  PlankTransportNativeEndpoint *endpoint, const uint8_t *bytes, size_t size) {
  PlankClipboardFileRecord record {};
  REQUIRE(plank_clipboard_file_decode(bytes, size,
    PLANK_CLIPBOARD_FILE_DATA_PREFIX_BYTES + PLANK_CLIPBOARD_FILE_DATA_BYTES, &record));
  endpoint->sent_types.push_back(record.type);
  if (endpoint->sent) endpoint->sent(record);
  return PLANK_TRANSPORT_OK;
}

/** @brief Encode a peer record with an independent offer identity and sequence. */
static std::vector<std::uint8_t> packet(std::uint8_t identity, std::uint16_t type,
  std::uint64_t sequence, const void *payload = nullptr, std::size_t size = 0,
  std::uint32_t flags = 0) {
  std::array<std::uint8_t, 16> id {};
  id[0] = identity;
  std::vector<std::uint8_t> result(PLANK_CLIPBOARD_FILE_HEADER_BYTES + size);
  REQUIRE(plank_clipboard_file_header(result.data(), result.size(), type, flags,
    size, id.data(), identity, sequence));
  if (size) std::memcpy(result.data() + PLANK_CLIPBOARD_FILE_HEADER_BYTES, payload, size);
  return result;
}

/** @brief Queue a bounded one-file source manifest, optionally corrupting its sequence. */
static void manifest(PlankTransportNativeEndpoint &endpoint, std::uint8_t id,
  std::uint64_t size = 0, bool bad_sequence = false) {
  PlankClipboardFileOfferBegin begin {PLANK_CLIPBOARD_FILE_CLIENT_TO_HOST, 1, 1, 1, size};
  std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_OFFER_BEGIN_BYTES> payload {};
  REQUIRE(plank_clipboard_file_offer_begin_encode(payload.data(), &begin));
  endpoint.controls.push_back(packet(id, PLANK_CLIPBOARD_FILE_OFFER_BEGIN, 1,
    payload.data(), payload.size()));
  PlankClipboardFileOfferEntry entry {1, 0, PLANK_CLIPBOARD_FILE_REGULAR, 0600,
    size, 0, reinterpret_cast<const std::uint8_t *>("sample.txt"), 10};
  std::array<std::uint8_t, 300> encoded {};
  std::size_t encoded_size = 0;
  REQUIRE(plank_clipboard_file_offer_entry_encode(encoded.data(), encoded.size(),
    &entry, &encoded_size));
  endpoint.controls.push_back(packet(id, PLANK_CLIPBOARD_FILE_OFFER_ENTRY,
    bad_sequence ? 3 : 2, encoded.data(), encoded_size));
  endpoint.controls.push_back(packet(id, PLANK_CLIPBOARD_FILE_OFFER_END, 3));
}

/** @brief Queue a valid terminal referencing the active sink materialization. */
static void cancel(PlankTransportNativeEndpoint &endpoint, std::uint8_t id,
  std::uint64_t materialization, std::uint64_t sequence = 4) {
  PlankClipboardFileTerminal terminal {materialization,
    PLANK_CLIPBOARD_FILE_REASON_SOURCE_UNAVAILABLE, 0};
  std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_TERMINAL_BYTES> payload {};
  REQUIRE(plank_clipboard_file_terminal_encode(payload.data(), &terminal));
  endpoint.controls.push_back(packet(id, PLANK_CLIPBOARD_FILE_CANCEL, sequence,
    payload.data(), payload.size()));
}

/** @brief Complete a zero-byte regular file using its real SHA-256 digest. */
static void complete(PlankTransportNativeEndpoint &endpoint, std::uint8_t id,
  std::uint64_t materialization) {
  digest_t digest;
  const auto hash = digest.finish();
  REQUIRE(hash);
  PlankClipboardFileEntryComplete complete {materialization, 1, 0, {0}};
  std::memcpy(complete.sha256, hash->data(), hash->size());
  std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_ENTRY_COMPLETE_BYTES> payload {};
  REQUIRE(plank_clipboard_file_entry_complete_encode(payload.data(), &complete));
  endpoint.controls.push_back(packet(id, PLANK_CLIPBOARD_FILE_ENTRY_COMPLETE, 4,
    payload.data(), payload.size()));
}

/** @brief Verify Host source wins crossed manifests without disturbing its own sequence. */
static void crossed_offers() {
  PlankTransportNativeEndpoint endpoint;
  inbox_t inbox;
  std::stop_source stop;
  wire_t host(&endpoint, stop.get_token(), inbox, 30ms);
  std::array<std::uint8_t, 16> host_id {9};
  host.start_source(host_id, 9);
  manifest(endpoint, 1);
  std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_OFFER_ACK_BYTES> ack {};
  REQUIRE(plank_clipboard_file_offer_ack_encode(ack.data(),
    PLANK_CLIPBOARD_FILE_DATA_BYTES, PLANK_CLIPBOARD_FILE_MAX_OUTSTANDING_BYTES));
  endpoint.controls.push_back(packet(9, PLANK_CLIPBOARD_FILE_OFFER_ACK, 1,
    ack.data(), ack.size()));
  std::array<std::uint8_t, 8> materialize {};
  REQUIRE(plank_clipboard_file_materialization_encode(materialize.data(), 7));
  endpoint.controls.push_back(packet(9, PLANK_CLIPBOARD_FILE_MATERIALIZE, 2,
    materialize.data(), materialize.size(), PLANK_CLIPBOARD_FILE_FLAG_ALL_ITEMS));
  std::vector<std::uint8_t> storage;
  auto response = host.control(storage);
  REQUIRE(response && response->type == PLANK_CLIPBOARD_FILE_OFFER_ACK);
  REQUIRE(host.offer.receive_sequence == 2);
  response = host.control(storage);
  REQUIRE(response && response->type == PLANK_CLIPBOARD_FILE_MATERIALIZE);
  REQUIRE(host.offer.receive_sequence == 3 && !host.failed);
  REQUIRE(endpoint.sent_types.empty());
  REQUIRE(endpoint.controls.empty());
}

/** @brief Build peer replies that preserve the actual randomized Host offer identity. */
static std::vector<std::uint8_t> reply(const PlankClipboardFileRecord &source,
  std::uint16_t type, std::uint64_t sequence, const void *payload,
  std::size_t size, std::uint32_t flags = 0) {
  std::vector<std::uint8_t> result(PLANK_CLIPBOARD_FILE_HEADER_BYTES + size);
  REQUIRE(plank_clipboard_file_header(result.data(), result.size(), type, flags,
    size, source.offer_id, source.session_epoch, sequence));
  if (size) std::memcpy(result.data() + PLANK_CLIPBOARD_FILE_HEADER_BYTES, payload, size);
  return result;
}

/** @brief Exercise the complete Host source exchange under a crossed Client manifest. */
static void source_collision_and_failure() {
  const auto source = std::filesystem::path(std::getenv("XDG_CACHE_HOME")) / "source.txt";
  const int fd = ::open(source.c_str(), O_CREAT | O_WRONLY, 0600);
  REQUIRE(fd >= 0);
  REQUIRE(::write(fd, "abc", 3) == 3);
  ::close(fd);
  for (const bool fail_source : {false, true}) {
    PlankTransportNativeEndpoint endpoint;
    inbox_t inbox;
    unsigned received_data = 0;
    endpoint.sent = [&](const PlankClipboardFileRecord &record) {
      if (record.type == PLANK_CLIPBOARD_FILE_OFFER_END) {
        manifest(endpoint, 1);
        std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_OFFER_ACK_BYTES> ack {};
        REQUIRE(plank_clipboard_file_offer_ack_encode(ack.data(),
          PLANK_CLIPBOARD_FILE_DATA_BYTES, PLANK_CLIPBOARD_FILE_MAX_OUTSTANDING_BYTES));
        endpoint.controls.push_back(reply(record, PLANK_CLIPBOARD_FILE_OFFER_ACK, 1,
          ack.data(), ack.size()));
        std::array<std::uint8_t, 8> materialization {};
        REQUIRE(plank_clipboard_file_materialization_encode(materialization.data(), 7));
        endpoint.controls.push_back(reply(record, PLANK_CLIPBOARD_FILE_MATERIALIZE, 2,
          materialization.data(), materialization.size(), PLANK_CLIPBOARD_FILE_FLAG_ALL_ITEMS));
        std::array<std::uint8_t, PLANK_CLIPBOARD_FILE_DATA_PREFIX_BYTES> range {};
        REQUIRE(plank_clipboard_file_range_header(range.data(), 7, 1, 0, 3));
        endpoint.controls.push_back(reply(record, PLANK_CLIPBOARD_FILE_READ_REQUEST, 3,
          range.data(), range.size()));
        if (fail_source) std::filesystem::remove(source);
      } else if (record.type == PLANK_CLIPBOARD_FILE_DATA) {
        PlankClipboardFileRange range {};
        REQUIRE(plank_clipboard_file_decode_range(record.payload, record.payload_size, 1, &range));
        REQUIRE(range.size == 3 && std::memcmp(range.bytes, "abc", 3) == 0);
        ++received_data;
      } else if (record.type == PLANK_CLIPBOARD_FILE_ENTRY_COMPLETE) {
        std::array<std::uint8_t, 8> materialization {};
        REQUIRE(plank_clipboard_file_materialization_encode(materialization.data(), 7));
        endpoint.controls.push_back(reply(record, PLANK_CLIPBOARD_FILE_TRANSFER_READY, 4,
          materialization.data(), materialization.size()));
      } else if (record.type == PLANK_CLIPBOARD_FILE_CANCEL) {
        PlankClipboardFileTerminal terminal {};
        REQUIRE(plank_clipboard_file_terminal_decode(record.payload, record.payload_size, &terminal));
        REQUIRE(terminal.materialization_id == 7);
      }
    };
    REQUIRE(send_offer({}, &endpoint, inbox, {file_uri(source)}, 1) == !fail_source);
    REQUIRE(received_data == (fail_source ? 0u : 1u));
    REQUIRE(std::count(endpoint.sent_types.begin(), endpoint.sent_types.end(),
      PLANK_CLIPBOARD_FILE_CANCEL) == (fail_source ? 1 : 0));
  }
}

/** @brief Do not validate ENTRY_COMPLETE ahead of DATA across independent lanes. */
static void cross_lane_completion() {
  PlankTransportNativeEndpoint endpoint;
  inbox_t inbox;
  wire_t sink(&endpoint, {}, inbox, 30ms);
  manifest(endpoint, 1, 1);
  std::vector<std::uint8_t> storage;
  REQUIRE(sink.first(storage));
  REQUIRE(parse_manifest(sink, storage));
  sink.materialization = 7;
  endpoint.controls.push_back(packet(1, PLANK_CLIPBOARD_FILE_ENTRY_COMPLETE, 5));
  std::vector<std::uint8_t> payload(PLANK_CLIPBOARD_FILE_DATA_PREFIX_BYTES + 1);
  REQUIRE(plank_clipboard_file_range_header(payload.data(), 7, 1, 0, 1));
  payload.back() = 'a';
  endpoint.data.push_back(packet(1, PLANK_CLIPBOARD_FILE_DATA, 4,
    payload.data(), payload.size()));
  endpoint.data_timeouts = 1;
  auto data = sink.data(storage);
  REQUIRE(data && data->type == PLANK_CLIPBOARD_FILE_DATA && !sink.failed);
  auto end = sink.control(storage);
  REQUIRE(end && end->sequence == 5 && !sink.failed);
}

/** @brief Source cancellation wakes a sink even if the DATA lane never produces a chunk. */
static void cancel_during_data() {
  PlankTransportNativeEndpoint endpoint;
  inbox_t inbox;
  wire_t sink(&endpoint, {}, inbox, 30ms);
  manifest(endpoint, 1, 1);
  std::vector<std::uint8_t> storage;
  REQUIRE(sink.first(storage));
  REQUIRE(parse_manifest(sink, storage));
  sink.materialization = 7;
  cancel(endpoint, 1, 7, 5); // A failed send may have reserved DATA sequence 4.
  const auto begin = std::chrono::steady_clock::now();
  auto record = sink.data(storage);
  REQUIRE(record && record->type == PLANK_CLIPBOARD_FILE_CANCEL);
  REQUIRE(std::chrono::steady_clock::now() - begin < 20ms);
  REQUIRE(endpoint.controls.empty());
}

/** @brief Manifest reads tolerate native receive timeout slices instead of aborting. */
static void delayed_manifest() {
  PlankTransportNativeEndpoint endpoint;
  inbox_t inbox;
  wire_t sink(&endpoint, {}, inbox, 30ms);
  manifest(endpoint, 1);
  std::vector<std::uint8_t> storage;
  REQUIRE(sink.first(storage));
  endpoint.control_timeouts = 3;
  REQUIRE(parse_manifest(sink, storage));
  REQUIRE(!sink.failed && endpoint.controls.empty());
}

/** @brief Reject a terminal for another materialization rather than treating it as valid cancellation. */
static void invalid_terminal() {
  PlankTransportNativeEndpoint endpoint;
  inbox_t inbox;
  wire_t sink(&endpoint, {}, inbox, 30ms);
  manifest(endpoint, 1, 1);
  std::vector<std::uint8_t> storage;
  REQUIRE(sink.first(storage));
  REQUIRE(parse_manifest(sink, storage));
  sink.materialization = 7;
  cancel(endpoint, 1, 8);
  REQUIRE(!sink.data(storage) && sink.failed);
}

/** @brief Both receive and send stalls expire and allow a fresh offer afterwards. */
static void inactivity_recovery() {
  PlankTransportNativeEndpoint endpoint;
  inbox_t inbox;
  wire_t sink(&endpoint, {}, inbox, 5ms);
  manifest(endpoint, 1, 1);
  std::vector<std::uint8_t> storage;
  REQUIRE(sink.first(storage));
  REQUIRE(parse_manifest(sink, storage));
  const auto begin = std::chrono::steady_clock::now();
  REQUIRE(!sink.data(storage) && sink.failed);
  REQUIRE(std::chrono::steady_clock::now() - begin < 50ms);
  manifest(endpoint, 2);
  wire_t next(&endpoint, {}, inbox, 10ms);
  REQUIRE(next.first(storage));
  REQUIRE(parse_manifest(next, storage));
  endpoint.block_sends = true;
  REQUIRE(!next.send_control(PLANK_CLIPBOARD_FILE_OFFER_END, 0, nullptr, 0));
  REQUIRE(next.failed);
}

/** @brief Bad manifest leftovers and source failure do not permanently stop the real worker. */
static void worker_recovery() {
  PlankTransportNativeEndpoint endpoint;
  std::stop_source stop;
  manifest(endpoint, 1, 0, true);
  manifest(endpoint, 2, 1);
  endpoint.sent = [&](const PlankClipboardFileRecord &record) {
    if (record.type == PLANK_CLIPBOARD_FILE_MATERIALIZE) {
      std::uint64_t materialization = 0;
      REQUIRE(plank_clipboard_file_materialization_decode(record.payload,
        record.payload_size, &materialization));
      if (record.offer_id[0] == 2) {
        cancel(endpoint, 2, materialization);
        // A malformed trailing DATA record must not poison the following offer.
        endpoint.data.push_back({0, 1, 2});
        manifest(endpoint, 3);
      } else {
        REQUIRE(record.offer_id[0] == 3);
        complete(endpoint, 3, materialization);
      }
    }
  };
  unsigned published = 0;
  worker(stop.get_token(), &endpoint, [&](const std::vector<std::string> &uris) {
    REQUIRE(uris.size() == 1 && uris[0].ends_with("/sample.txt"));
    ++published;
    stop.request_stop();
    return true;
  }, {}, "bidirectional");
  REQUIRE(published == 1);
  REQUIRE(std::count(endpoint.sent_types.begin(), endpoint.sent_types.end(),
    PLANK_CLIPBOARD_FILE_ERROR) == 2);
}

/** @brief A next OFFER_BEGIN read during an incomplete manifest must survive recovery. */
static void next_offer_boundary() {
  PlankTransportNativeEndpoint endpoint;
  inbox_t inbox;
  manifest(endpoint, 1);
  endpoint.controls.pop_back(); // Missing END: next BEGIN belongs to the new offer.
  manifest(endpoint, 2);
  std::vector<std::uint8_t> storage;
  wire_t first(&endpoint, {}, inbox, 10ms);
  REQUIRE(first.first(storage));
  REQUIRE(!parse_manifest(first, storage));
  wire_t second(&endpoint, {}, inbox, 10ms);
  REQUIRE(second.first(storage));
  REQUIRE(second.offer.id[0] == 2);
  REQUIRE(parse_manifest(second, storage));
}

/** @brief Run each regression with an isolated staging root and remove owned output. */
int main() {
  ::alarm(10); // A regression must fail in bounded time even if the worker strands.
  char temporary[] = "/tmp/plank-file-recovery.XXXXXX";
  const char *root = ::mkdtemp(temporary);
  REQUIRE(root);
  ::setenv("XDG_CACHE_HOME", root, 1);
  try {
    for (const auto &[name, test] : std::vector<std::pair<const char *, void (*)()>> {
      {"crossed offers", crossed_offers},
      {"complete source collision and local failure", source_collision_and_failure},
      {"cross-lane completion", cross_lane_completion},
      {"source cancel during DATA", cancel_during_data},
      {"manifest timeout slices", delayed_manifest},
      {"terminal materialization validation", invalid_terminal},
      {"inactivity and follow-on recovery", inactivity_recovery},
      {"real worker recovery", worker_recovery},
      {"next-offer manifest boundary", next_offer_boundary},
    }) {
      test();
      std::cout << "PASS " << name << '\n';
    }
  } catch (const std::exception &error) {
    std::filesystem::remove_all(root);
    std::cerr << "FAIL " << error.what() << '\n';
    return 1;
  }
  std::filesystem::remove_all(root);
}
