/**
 * @file tests/unit/test_entry_handler.cpp
 * @brief Test src/entry_handler.*.
 */
#include "../tests_common.h"
#include "../tests_log_checker.h"

#include <src/entry_handler.h>

#include <string_view>

TEST(EntryHandlerTests, LogPublisherDataTest) {
  // call log_publisher_data
  log_publisher_data();

  // check if specific log messages exist
  ASSERT_TRUE(log_checker::line_starts_with("test_sunshine.log", "Info: Package Publisher: "));
  ASSERT_TRUE(log_checker::line_starts_with("test_sunshine.log", "Info: Publisher Website: "));
  // The support line is logged only when the build names an issue URL; PLANK
  // product builds leave it empty.
  ASSERT_EQ(log_checker::line_starts_with("test_sunshine.log", "Info: Support: "),
            std::string_view {SUNSHINE_PUBLISHER_ISSUE_URL}.size() != 0);
}
