#!/usr/bin/env bash
# Run in a disposable Linux container with no Host service or /run/plank directory.
# Reuse the checkout's GoogleTest and pinned nlohmann_json headers; no downloads.
set -euo pipefail
host_root=$(cd "$(dirname "$0")/../.." && pwd)
: "${PLANK_GTEST_SOURCE:?GoogleTest source directory required}"
: "${PLANK_JSON_INCLUDE:?Directory containing nlohmann/json.hpp required}"
test_build=$(mktemp -d)
trap 'rm -rf "$test_build"' EXIT
"${CXX:-g++}" -std=c++20 -pthread -I "$host_root" -I "$PLANK_JSON_INCLUDE" \
  -I "$PLANK_GTEST_SOURCE/include" -I "$PLANK_GTEST_SOURCE" \
  "$host_root/src/session/collaboration.cpp" "$host_root/src/session/collaboration_ui.cpp" \
  "$host_root/tests/collaboration/test_monitor.cpp" \
  "$PLANK_GTEST_SOURCE/src/gtest-all.cc" "$PLANK_GTEST_SOURCE/src/gtest_main.cc" \
  -o "$test_build/monitor"
"$test_build/monitor"
