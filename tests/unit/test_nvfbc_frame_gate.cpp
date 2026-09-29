/**
 * @file tests/unit/test_nvfbc_frame_gate.cpp
 * @brief Cover duplicate suppression and capture-session recreation.
 */
#include <gtest/gtest.h>
#include <src/platform/linux/nvfbc_frame_gate.h>

TEST(NvfbcFrameGate, PublishesInitialImageAndChangesButSkipsDuplicates) {
  nvfbc::frame_gate_t gate;
  EXPECT_TRUE(gate.publish(false));
  EXPECT_FALSE(gate.publish(false));
  EXPECT_FALSE(gate.publish(false));
  EXPECT_TRUE(gate.publish(true));
  EXPECT_FALSE(gate.publish(false));
  gate.reset();
  EXPECT_TRUE(gate.publish(false));
  EXPECT_FALSE(gate.publish(false));
}
