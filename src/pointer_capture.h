/**
 * @file src/pointer_capture.h
 * @brief Ordered pointer-capture epochs and framebuffer-to-desktop movement.
 */
#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <optional>
#include <utility>

#include <plank_transport_pointer.h>

namespace input {
  /** @brief Immutable coordinate transform for one captured pointer epoch. */
  struct pointer_capture_geometry_t {
    int offset_x {};  ///< Root desktop X origin.
    int offset_y {};  ///< Root desktop Y origin.
    int width {};  ///< Input canvas width.
    int height {};  ///< Input canvas height.
    int logical_width {};  ///< Logical input canvas width.
    int logical_height {};  ///< Logical input canvas height.
    int env_width {};  ///< Full physical desktop width.
    int env_height {};  ///< Full physical desktop height.
    int env_logical_width {};  ///< Full logical desktop width.
    int env_logical_height {};  ///< Full logical desktop height.
    float client_offset_x {};  ///< Capture letterbox X offset.
    float client_offset_y {};  ///< Capture letterbox Y offset.
    float scalar_inv {};  ///< Frame-to-display scale.
    float scalar_tpcoords {};  ///< Physical-to-logical input scale.

    /** @brief Compare every value that affects the input coordinate transform. */
    bool operator==(const pointer_capture_geometry_t &) const = default;

    /** @brief Require a finite, nondegenerate desktop transform. */
    bool valid() const {
      return width > 0 && height > 0 && std::isfinite(client_offset_x) &&
        std::isfinite(client_offset_y) && std::isfinite(scalar_inv) && scalar_inv > 0 &&
        std::isfinite(scalar_tpcoords) && scalar_tpcoords > 0;
    }
  };

  /**
   * @brief State of a single connection's ordered, unaccelerated mouse gesture.
   *
   * Packet sequence, transform and fractional carry belong to one epoch. No
   * sampled cursor position is used to infer application warps or acknowledge
   * completion. Callers hold the production input owner lock around this state.
   */
  class pointer_capture_t {
  public:
    /** @brief Whether ordinary absolute input must remain suspended. */
    bool active() const { return active_; }

    /**
     * @brief Start a new epoch after the backend probe, preserving the current desktop pointer.
     * @param packet Validated BEGIN packet.
     * @param geometry Current desktop coordinate transform.
     * @return True if this is a fresh epoch with its first sequence number.
     */
    bool can_begin(const PlankPointerPacket &packet, const pointer_capture_geometry_t &geometry) const {
      return !active_ && packet.operation == PLANK_POINTER_BEGIN && packet.sequence == 1 &&
        packet.epoch > last_epoch_ && geometry.valid();
    }

    /** @brief Commit a BEGIN after its backend capability probe succeeded. */
    bool begin(const PlankPointerPacket &packet, const pointer_capture_geometry_t &geometry) {
      if (!can_begin(packet, geometry)) return false;
      active_ = true;
      last_epoch_ = packet.epoch;
      sequence_ = packet.sequence;
      width_ = packet.width;
      height_ = packet.height;
      geometry_ = geometry;
      carry_x_ = carry_y_ = 0;
      return true;
    }

    /**
     * @brief Validate the next MOVE or completion without changing state.
     * @param packet Validated wire packet.
     * @param geometry Current coordinate transform.
     * @return True for the exact next sequence and transform; CANCEL may retire an obsolete transform.
     */
    bool accepts(const PlankPointerPacket &packet, const pointer_capture_geometry_t &geometry) const {
      return active_ && packet.epoch == last_epoch_ && sequence_ != UINT64_MAX &&
        packet.sequence == sequence_ + 1 && packet.width == width_ && packet.height == height_ &&
        (geometry == geometry_ || packet.operation == PLANK_POINTER_CANCEL) &&
        packet.operation >= PLANK_POINTER_MOVE && packet.operation <= PLANK_POINTER_CANCEL;
    }

    /**
     * @brief Accept cleanup for the last epoch even after its END or local reset.
     * @param packet Validated CANCEL packet.
     * @return True for the exact next sequence without reactivating movement.
     */
    bool can_cancel(const PlankPointerPacket &packet) const {
      return packet.operation == PLANK_POINTER_CANCEL && last_epoch_ != 0 &&
        packet.epoch == last_epoch_ && sequence_ != UINT64_MAX && packet.sequence == sequence_ + 1 &&
        packet.width == width_ && packet.height == height_;
    }

    /**
     * @brief Scale one validated MOVE while retaining subpixel displacement.
     * @param packet Validated next MOVE packet.
     * @param geometry Current coordinate transform.
     * @return Exact integer desktop-pixel displacement, or no value on invalid input.
     */
    std::optional<std::pair<int, int>> movement(const PlankPointerPacket &packet, const pointer_capture_geometry_t &geometry) {
      if (packet.operation != PLANK_POINTER_MOVE || !accepts(packet, geometry)) return std::nullopt;
      const double x = carry_x_ + double(packet.x) * geometry.width / width_ * geometry.scalar_inv / geometry.scalar_tpcoords;
      const double y = carry_y_ + double(packet.y) * geometry.height / height_ * geometry.scalar_inv / geometry.scalar_tpcoords;
      if (!std::isfinite(x) || !std::isfinite(y) || std::abs(x) > 32767 || std::abs(y) > 32767) return std::nullopt;
      const auto dx = int(std::round(x)), dy = int(std::round(y));
      carry_x_ = x - dx;
      carry_y_ = y - dy;
      sequence_ = packet.sequence;
      return std::pair {dx, dy};
    }

    /** @brief Finish an ordered epoch after the platform end position is read. */
    void finish() { active_ = false; carry_x_ = carry_y_ = 0; }

    /** @brief Retire a validated completion while retaining its sequence for later cleanup. */
    void complete(const PlankPointerPacket &packet) {
      sequence_ = packet.sequence;
      finish();
    }

    /**
     * @brief Express a root desktop pointer in the epoch's encoded-frame pixels.
     * @param root_x Authoritative desktop pointer X position.
     * @param root_y Authoritative desktop pointer Y position.
     * @return Clamped frame-pixel pointer, preserving capture letterboxing/scaling.
     */
    std::pair<float, float> frame_position(double root_x, double root_y) const {
      const auto &g = geometry_;
      const double x = ((root_x - g.offset_x) * g.scalar_tpcoords / g.scalar_inv + g.client_offset_x) * width_ / g.width;
      const double y = ((root_y - g.offset_y) * g.scalar_tpcoords / g.scalar_inv + g.client_offset_y) * height_ / g.height;
      return {float(std::clamp(x, 0.0, double(width_ - 1))), float(std::clamp(y, 0.0, double(height_ - 1)))};
    }

  private:
    bool active_ = false;  ///< True until END, CANCEL or connection cleanup.
    std::uint64_t last_epoch_ {}, sequence_ {};  ///< Last accepted epoch and sequence.
    std::uint16_t width_ {}, height_ {};  ///< Encoded-frame dimensions of this epoch.
    pointer_capture_geometry_t geometry_;  ///< Frozen coordinate transform.
    double carry_x_ {}, carry_y_ {};  ///< Fractional movement retained across packets.
  };
}  // namespace input
