#!/usr/bin/env bash
set -euo pipefail
# Run only on a disposable Linux builder with Xvfb; no desktop access required.
repo=$(cd "$(dirname "$0")/../.." && pwd)
scratch=$(mktemp -d)
xvfb_pid=
cleanup() {
  if [[ -n "$xvfb_pid" ]]; then kill "$xvfb_pid" 2>/dev/null || true; wait "$xvfb_pid" 2>/dev/null || true; fi
  rm -rf "$scratch"
}
trap cleanup EXIT
"${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror -DSUNSHINE_BUILD_X11 \
  -I"$repo/tests/clipboard/include" -I"$repo" \
  "$repo/src/platform/linux/x11_clipboard.cpp" "$repo/tests/clipboard/x11-backend.cxx" \
  $(pkg-config --cflags --libs xcb x11) -o "$scratch/clipboard-test"
# No TCP listener; Xvfb is private to this disposable test process/container.
Xvfb -displayfd 3 -screen 0 640x480x24 -nolisten tcp -ac 3>"$scratch/display" >"$scratch/xvfb.log" 2>&1 &
xvfb_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
  [[ -s "$scratch/display" ]] && break
  kill -0 "$xvfb_pid"
  sleep 0.05
done
test -s "$scratch/display"
DISPLAY=":$(cat "$scratch/display")" "$scratch/clipboard-test"
