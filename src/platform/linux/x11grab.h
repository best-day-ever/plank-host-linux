/**
 * @file src/platform/linux/x11grab.h
 * @brief Declarations for x11 capture.
 */
#pragma once

// standard includes
#include <cstddef>
#include <cstdint>
#include <optional>

// local includes
#include "src/platform/common.h"
#include "src/utility.h"

// X11 Display
extern "C" struct _XDisplay;

namespace egl {
  class cursor_t;
}

namespace platf::x11 {
  /**
   * @brief Host-authoritative root-pointer position.
   */
  struct cursor_position_t {
    int x;  ///< Root-window X coordinate of the pointer hotspot.
    int y;  ///< Root-window Y coordinate of the pointer hotspot.
    int desktop_width;  ///< Current root-window width.
    int desktop_height;  ///< Current root-window height.
  };

  /**
   * @brief Unpack one depth-30 X11 RGB row into FFmpeg identity-GBR planes.
   *
   * The qualified visual stores red in bits 0-9, green in bits 10-19, and
   * blue in bits 20-29. FFmpeg's identity matrix consumes planes as G, B, R.
   *
   * @param source Packed X11 pixels.
   * @param green FFmpeg plane 0 destination.
   * @param blue FFmpeg plane 1 destination.
   * @param red FFmpeg plane 2 destination.
   * @param pixel_count Number of pixels in the row.
   */
  void unpack_xrgb10_to_gbr10_row(const std::uint32_t *source,
                                  std::uint16_t *green,
                                  std::uint16_t *blue,
                                  std::uint16_t *red,
                                  std::size_t pixel_count);

  struct cursor_ctx_raw_t;
  /**
   * @brief Release cursor context resources.
   *
   * @param ctx Native context object used by the operation or callback.
   */
  void freeCursorCtx(cursor_ctx_raw_t *ctx);
  /**
   * @brief Release display resources.
   *
   * @param xdisplay X11 display connection.
   */
  void freeDisplay(_XDisplay *xdisplay);

  /**
   * @brief XFixes cursor image pointer released with `XFree`.
   */
  using cursor_ctx_t = util::safe_ptr<cursor_ctx_raw_t, freeCursorCtx>;
  /**
   * @brief X11 display pointer released with `XCloseDisplay`.
   */
  using xdisplay_t = util::safe_ptr<_XDisplay, freeDisplay>;

  /**
   * @brief X11 cursor image and positioning state used during capture.
   */
  class cursor_t {
  public:
    /**
     * @brief Allocate the underlying object and wrap it in the owning handle.
     *
     * @return Created backend object, or null when creation fails.
     */
    static std::optional<cursor_t> make();

    /**
     * @brief Run the capture loop for this backend.
     *
     * @param img Image or frame object to read from or populate.
     */
    bool capture(egl::cursor_t &img);

    /**
     * @brief Subscribe this connection to XFixes cursor-shape changes.
     *
     * This also captures the root geometry used by position queries.
     *
     * @return True when local cursor monitoring is available.
     */
    bool subscribe_shape_events();

    /**
     * @brief Query the current root-pointer position through XQueryPointer.
     *
     * @param position Position populated on success.
     * @return True when the query succeeds.
     */
    bool query_position(cursor_position_t &position);

    /**
     * @brief Drain queued X11 events and report a cursor-shape change.
     *
     * @return 1 when one or more shape changes were coalesced, 0 when none
     *         were pending, or -1 before shape monitoring is initialized.
     */
    int consume_shape_change();

    /**
     * Capture and blend the cursor into the image
     *
     * img <-- destination image
     * offsetX, offsetY <--- Top left corner of the virtual screen
     * @param img Image or frame object to read from or populate.
     * @param offsetX Offset x.
     * @param offsetY Offset y.
     */
    void blend(img_t &img, int offsetX, int offsetY);

    cursor_ctx_t ctx;  ///< X11 cursor context used to track and blend cursor images.

  private:
    int xfixes_event_base_ {-1};  ///< Base event number for XFixes notifications.
    int desktop_width_ {0};  ///< Root-window width captured at subscription time.
    int desktop_height_ {0};  ///< Root-window height captured at subscription time.
  };

  /**
   * @brief Open and initialize the display connection used for capture.
   *
   * @return Constructed display object.
   */
  xdisplay_t make_display();
}  // namespace platf::x11
