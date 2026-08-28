/**
 * @file tests/unit/test_process.cpp
 * @brief Tests for the fixed StationConnect Desktop identity.
 */

// test imports
#include "../tests_common.h"

// local imports
#include <src/process.h>

TEST(Process, ExposesOneStableDesktopIdentity) {
  EXPECT_EQ(proc::desktop_app_id, 881448767);
  EXPECT_EQ(proc::desktop_app_name, "Desktop");
  EXPECT_GT(proc::desktop_app_id, 0);
}

TEST(Process, AcceptsOnlyTheDesktopApplicationId) {
  EXPECT_TRUE(proc::is_desktop_app(proc::desktop_app_id));
  EXPECT_FALSE(proc::is_desktop_app(0));
  EXPECT_FALSE(proc::is_desktop_app(-1));
  EXPECT_FALSE(proc::is_desktop_app(proc::desktop_app_id + 1));
}

TEST(Process, UsesThePackagedDesktopArtwork) {
  EXPECT_EQ(
    std::string_view {proc::desktop_image_path}.substr(
      std::string_view {proc::desktop_image_path}.find_last_of('/') + 1
    ),
    "desktop.png"
  );
}
