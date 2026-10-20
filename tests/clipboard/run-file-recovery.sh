#!/usr/bin/env bash
set -euo pipefail
# Runs on Linux or macOS, without X11, a desktop, or a transport connection.
repo=$(cd "$(dirname "$0")/../.." && pwd)
transport=${PLANK_TRANSPORT_DIR:-"$repo/../../../protocol/plank-transport"}
if [[ ! -f "$transport/include/plank_clipboard_file_wire.h" ]]; then
  echo 'Set PLANK_TRANSPORT_DIR to the superproject protocol/plank-transport checkout.' >&2
  exit 1
fi
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
"${CXX:-c++}" -std=c++23 -pthread -Wall -Wextra -Werror \
  -I"$repo/tests/clipboard/include" -I"$repo" -I"$transport/include" \
  "$repo/tests/clipboard/file-recovery.cxx" \
  $(pkg-config --cflags --libs openssl) -o "$scratch/file-recovery"
"$scratch/file-recovery"
