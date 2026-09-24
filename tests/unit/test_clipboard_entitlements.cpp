#include <gtest/gtest.h>

#include "src/clipboard_entitlements.h"

TEST(ClipboardEntitlements, FileGrantCanBeRemovedWithoutRemovingText) {
  using namespace plank::topology;
  const auto requested = feature_clipboard_sync | feature_file_clipboard | feature_selected_output;
  const auto effective = plank::clipboard_entitlements::effective_features(requested, true, false);
  EXPECT_NE(effective & feature_clipboard_sync, 0u);
  EXPECT_EQ(effective & feature_file_clipboard, 0u);
  EXPECT_NE(effective & feature_selected_output, 0u);
}

TEST(ClipboardEntitlements, TextDenialAlsoClosesDependentFileChannels) {
  using namespace plank::topology;
  const auto requested = feature_clipboard_sync | feature_file_clipboard;
  EXPECT_EQ(plank::clipboard_entitlements::effective_features(requested, false, true), 0u);
  EXPECT_EQ(plank::clipboard_entitlements::effective_features(requested, true, true), requested);
}
