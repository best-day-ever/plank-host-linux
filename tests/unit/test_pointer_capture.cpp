/**
 * @file tests/unit/test_pointer_capture.cpp
 * @brief Pointer transaction ordering, geometry and fractional-pixel behavior.
 */
#ifdef PLANK_TRANSPORT
#include "src/pointer_capture.h"
#include <array>
#include <limits>
#include <gtest/gtest.h>

namespace {
  /** @brief A scaled, offset and letterboxed desktop used by the tests. */
  input::pointer_capture_geometry_t geometry() {
    return {100, 200, 1920, 1080, 1920, 1080, 3840, 2160, 3840, 2160,
            96, 54, 1.5f, 1.0f};
  }

  /** @brief Construct a valid first packet with an explicit frame anchor. */
  PlankPointerPacket begin_packet(std::uint64_t epoch = 1) {
    return {PLANK_POINTER_BEGIN, epoch, 1, 1280, 720, 100, 150};
  }

  /** @brief Construct a subsequent packet in the same geometry. */
  PlankPointerPacket packet(std::uint8_t operation, std::uint64_t sequence, float x = 0, float y = 0) {
    return {operation, 1, sequence, 1280, 720, x, y};
  }
}

TEST(PointerCapture, FreshEpochRequiresFirstSequenceAndAnInactiveOwner) {
  input::pointer_capture_t state;
  auto begin = begin_packet();
  begin.sequence = 2;
  EXPECT_FALSE(state.begin(begin, geometry()));
  begin.sequence = 1;
  ASSERT_TRUE(state.begin(begin, geometry()));
  EXPECT_TRUE(state.active());
  EXPECT_FALSE(state.begin(begin_packet(2), geometry()));
  state.finish();
  EXPECT_FALSE(state.active());
  EXPECT_FALSE(state.begin(begin_packet(), geometry()));
  EXPECT_TRUE(state.begin(begin_packet(2), geometry()));
}

TEST(PointerCapture, RequiresExactSequenceAndEpochBeforeEveryMovement) {
  input::pointer_capture_t state;
  ASSERT_TRUE(state.begin(begin_packet(), geometry()));
  EXPECT_FALSE(state.movement(packet(PLANK_POINTER_MOVE, 3, 5, 0), geometry()));
  auto stale = packet(PLANK_POINTER_MOVE, 2, 5, 0);
  stale.epoch = 2;
  EXPECT_FALSE(state.movement(stale, geometry()));
  ASSERT_TRUE(state.movement(packet(PLANK_POINTER_MOVE, 2, 5, 0), geometry()));
  EXPECT_FALSE(state.movement(packet(PLANK_POINTER_MOVE, 2, 5, 0), geometry()));
  EXPECT_TRUE(state.accepts(packet(PLANK_POINTER_END, 3), geometry()));
  EXPECT_FALSE(state.accepts(packet(PLANK_POINTER_END_ACK, 3), geometry()));
}

TEST(PointerCapture, RetainsFractionalPixelsWithoutDirectionDependentDrift) {
  input::pointer_capture_t state;
  ASSERT_TRUE(state.begin(begin_packet(), geometry()));
  int total_x = 0, total_y = 0;
  for (std::uint64_t sequence = 2; sequence < 102; ++sequence) {
    const auto delta = state.movement(packet(PLANK_POINTER_MOVE, sequence, .2f, -.2f), geometry());
    ASSERT_TRUE(delta);
    total_x += delta->first; total_y += delta->second;
  }
  EXPECT_EQ(total_x, 45);
  EXPECT_EQ(total_y, -45);
  for (std::uint64_t sequence = 102; sequence < 202; ++sequence) {
    const auto delta = state.movement(packet(PLANK_POINTER_MOVE, sequence, -.2f, .2f), geometry());
    ASSERT_TRUE(delta);
    total_x += delta->first; total_y += delta->second;
  }
  EXPECT_EQ(total_x, 0);
  EXPECT_EQ(total_y, 0);
}

TEST(PointerCapture, RejectsLayoutOrFrameChangesInsteadOfApplyingOldScaling) {
  input::pointer_capture_t state;
  ASSERT_TRUE(state.begin(begin_packet(), geometry()));
  auto changed = geometry();
  changed.offset_x += 1;
  EXPECT_FALSE(state.movement(packet(PLANK_POINTER_MOVE, 2, 4, 1), changed));
  changed = geometry(); changed.env_logical_width += 1;
  EXPECT_FALSE(state.accepts(packet(PLANK_POINTER_END, 2), changed));
  EXPECT_TRUE(state.accepts(packet(PLANK_POINTER_CANCEL, 2), changed));
  auto resized = packet(PLANK_POINTER_MOVE, 2, 4, 1);
  resized.width -= 1;
  EXPECT_FALSE(state.movement(resized, geometry()));
  EXPECT_TRUE(state.movement(packet(PLANK_POINTER_MOVE, 2, 4, 1), geometry()));
}

TEST(PointerCapture, CompletionPositionInvertsTheAnchorTransformAndClampsOutsideRoots) {
  input::pointer_capture_t state;
  ASSERT_TRUE(state.begin(begin_packet(), geometry()));
  const auto frame = state.frame_position(181, 456.5);
  EXPECT_FLOAT_EQ(frame.first, 100);
  EXPECT_FLOAT_EQ(frame.second, 150);
  const auto outside = state.frame_position(-1000, 10000);
  EXPECT_FLOAT_EQ(outside.first, 0);
  EXPECT_FLOAT_EQ(outside.second, 719);
}

TEST(PointerCapture, BackendRangeOverflowDoesNotConsumeTheNextSequence) {
  input::pointer_capture_t state;
  ASSERT_TRUE(state.begin(begin_packet(), geometry()));
  EXPECT_FALSE(state.movement(packet(PLANK_POINTER_MOVE, 2, 20000, 0), geometry()));
  EXPECT_TRUE(state.movement(packet(PLANK_POINTER_MOVE, 2, 1, 0), geometry()));
  state.finish();
  EXPECT_FALSE(state.accepts(packet(PLANK_POINTER_MOVE, 3, 1, 0), geometry()));
}

TEST(PointerCapture, CancellationAfterEndOrResetIsOrderedAndNeverResurrectsMovement) {
  input::pointer_capture_t state;
  ASSERT_TRUE(state.begin(begin_packet(), geometry()));
  const auto end = packet(PLANK_POINTER_END, 2);
  ASSERT_TRUE(state.accepts(end, geometry()));
  state.complete(end);
  const auto cancel = packet(PLANK_POINTER_CANCEL, 3);
  EXPECT_TRUE(state.can_cancel(cancel));
  EXPECT_FALSE(state.accepts(packet(PLANK_POINTER_MOVE, 3, 1, 1), geometry()));
  state.complete(cancel);
  EXPECT_FALSE(state.can_cancel(cancel));
  EXPECT_TRUE(state.can_cancel(packet(PLANK_POINTER_CANCEL, 4)));
  auto newer = begin_packet(2);
  ASSERT_TRUE(state.begin(newer, geometry()));
  state.finish();
  auto reset_cancel = packet(PLANK_POINTER_CANCEL, 2);
  reset_cancel.epoch = 2;
  EXPECT_TRUE(state.can_cancel(reset_cancel));
  EXPECT_FALSE(state.active());
}

TEST(PointerCapture, RejectsDegenerateOrNonfiniteGeometryBeforeBeginning) {
  for (const auto value : {0.0f, -1.0f, std::numeric_limits<float>::infinity(),
                           std::numeric_limits<float>::quiet_NaN()}) {
    input::pointer_capture_t state;
    auto invalid = geometry(); invalid.scalar_inv = value;
    EXPECT_FALSE(state.can_begin(begin_packet(), invalid));
    EXPECT_FALSE(state.active());
  }
}

TEST(PointerCapture, WireValidationRejectsInvalidCoordinatesAndReservedBytes) {
  auto begin = begin_packet();
  std::array<std::uint8_t, PLANK_POINTER_PACKET_SIZE> wire {};
  PlankPointerPacket decoded {};
  plank_pointer_encode(wire.data(), &begin);
  ASSERT_EQ(plank_pointer_decode(wire.data(), wire.size(), &decoded), 0);
  EXPECT_EQ(decoded.epoch, begin.epoch);
  wire[3] = 1;
  EXPECT_NE(plank_pointer_decode(wire.data(), wire.size(), &decoded), 0);
  wire[3] = 0;
  begin.x = std::numeric_limits<float>::quiet_NaN();
  plank_pointer_encode(wire.data(), &begin);
  EXPECT_NE(plank_pointer_decode(wire.data(), wire.size(), &decoded), 0);
  begin.x = begin.width;
  plank_pointer_encode(wire.data(), &begin);
  EXPECT_NE(plank_pointer_decode(wire.data(), wire.size(), &decoded), 0);
}
#endif
