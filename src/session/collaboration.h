/**
 * @file src/session/collaboration.h
 * @brief Owner-approved, desktop-bound collaboration authorization.
 */
#pragma once
#include <chrono>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <sys/types.h>

namespace plank::collaboration {
  /** @brief A permission is effective only while its desktop and consent UI remain valid. */
  enum class permission_t { pending, denied, view, control, revoked, expired };
  /** @brief Current supervisor-attested unlocked desktop identity. */
  struct desktop_t {
    uid_t owner {};
    std::uint64_t generation {};
    bool operator==(const desktop_t &) const = default;
  };
  /** @brief Mutable authorization retained by each approved guest stream. */
  struct lease_t {
    std::mutex mutex;  ///< Serializes permission changes against input injection.
    std::atomic<permission_t> permission {permission_t::pending};  ///< Effective permission.
    bool input_suspended {true};  ///< Owner security UI or pending consent blocks guest input.
    bool claimed {};  ///< Grants are one use, bound to the authenticated guest.
    std::function<void()> revoke_transport;  ///< Stop pending or active media immediately on revocation.
    std::function<void()> release_input;  ///< Immediately release only this guest's held input.
  };
  /** @brief One bounded consent request and its desktop-bound grant. */
  struct request_t {
    std::string id;  ///< Opaque public request identifier.
    std::string grant;  ///< Opaque, one-use stream authorization.
    uid_t guest {};  ///< Authenticated guest UID, never supplied by the client.
    std::string guest_name;  ///< OS-resolved label shown to the owner.
    desktop_t desktop;  ///< Desktop identity approved by its owner.
    std::chrono::steady_clock::time_point deadline;  ///< Pending/grant expiry.
    std::shared_ptr<lease_t> lease {std::make_shared<lease_t>()};  ///< Live permission.
  };
  /** @brief Bounded consent registry; callers serialize access with its mutex. */
  class registry_t {
  public:
    /** @brief Add a request, or return an existing live request for the same guest. */
    std::shared_ptr<request_t> add(uid_t guest, std::string name, desktop_t desktop,
                                  std::string id, std::string grant,
                                  std::chrono::steady_clock::time_point now);
    /** @brief Look up a request visible to its guest or desktop owner only. */
    std::shared_ptr<request_t> find(const std::string &id, uid_t account);
    /** @brief Change permission only for the exact current desktop owner. */
    bool decide(const std::string &id, uid_t owner, desktop_t desktop, permission_t permission);
    /** @brief Consume an unexpired grant once for its own authenticated account. */
    std::shared_ptr<request_t> claim(const std::string &grant, uid_t guest, desktop_t desktop,
                                    std::chrono::steady_clock::time_point now);
    /** @brief Revoke stale desktops, timeouts, and every grant if its local consent UI disappears. */
    void refresh(const desktop_t *desktop, bool ui_connected,
                 std::chrono::steady_clock::time_point now);
    /** @brief Suspend guest interaction while pending consent or the owner management panel is open. */
    void suspend(bool panel_open);
    /** @brief Revoke every active and pending participant. */
    void revoke_all();
    /** @brief End a participant when its native stream disconnects. */
    void ended(const std::shared_ptr<lease_t> &lease);
    /** @brief Snapshot requests (callers hold the registry mutex). */
    const std::vector<std::shared_ptr<request_t>> &requests() const { return requests_; }
    bool ui_connected {};  ///< A live credential-checked local owner helper is mandatory.
    std::mutex mutex;  ///< Registry and UI state serialization.
  private:
    std::vector<std::shared_ptr<request_t>> requests_;  ///< At most four live guests and sixteen recent records.
  };
  /** @brief Return the stable wire spelling for a permission. */
  const char *permission_name(permission_t permission);
  /** @brief Process registry shared by HTTPS, the consent UI, and native streams. */
  registry_t &registry();
  /** @brief Run the peer-credential-authenticated local consent channel until destruction. */
  class ui_t {
  public:
    ui_t();
    ~ui_t();
    ui_t(const ui_t &) = delete;
    ui_t &operator=(const ui_t &) = delete;
  private:
    struct impl_t;
    std::unique_ptr<impl_t> impl_;
  };
}
