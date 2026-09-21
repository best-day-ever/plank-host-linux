#!/usr/bin/env bash
# Build and run the host authentication unit tests, the root PAM broker and
# the GSSAPI probe without the full media-worker dependency set (FFmpeg,
# CUDA, Boost). Intended for a Rocky 9 builder with gcc-toolset-14,
# pam-devel, krb5-devel, openssl-devel and systemd-devel installed.
#
#   scripts/test-auth-standalone.sh [build-dir]
#
# Requires third-party/lizardbyte-common and its third-party/googletest
# submodule to be initialized (non-recursively is enough).
set -euo pipefail

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${1:-"$source_dir/cmake-build-auth"}
cxx=${CXX:-/opt/rh/gcc-toolset-14/root/usr/bin/g++}
gtest="$source_dir/third-party/lizardbyte-common/third-party/googletest/googletest"
[[ -f $gtest/src/gtest-all.cc ]] || {
  echo "googletest source missing at $gtest" >&2
  exit 1
}
mkdir -p "$build_dir"
flags=(-std=c++23 -O1 -g -Wall -Wextra -Werror -pthread -I"$source_dir")

build() {
  local output=$1
  shift
  echo "==> $output"
  "$cxx" "${flags[@]}" "$@" -o "$build_dir/$output"
}

"$cxx" -std=c++23 -O1 -pthread -I"$gtest/include" -I"$gtest" \
  -c "$gtest/src/gtest-all.cc" -o "$build_dir/gtest-all.o" &
"$cxx" -std=c++23 -O1 -pthread -I"$gtest/include" -I"$gtest" \
  -c "$gtest/src/gtest_main.cc" -o "$build_dir/gtest_main.o" &
wait

build plank-pam-broker \
  "$source_dir/src/auth/pam_broker.cpp" "$source_dir/src/auth/gssapi_acceptor.cpp" \
  -lpam -lgssapi_krb5 -lkrb5 -lcrypto
build plank-probe-gssapi \
  "$source_dir/tools/plank_probe_gssapi.cpp" "$source_dir/src/auth/gssapi_acceptor.cpp" \
  -lgssapi_krb5 -lkrb5 -lcrypto
# Existing upstream tests and pam_client.cpp are not -Wextra clean; the new
# broker and probe sources above are built with -Werror.
flags=(-std=c++23 -O1 -g -Wall -Wno-sign-compare -pthread -I"$source_dir")
build test-auth -DSUNSHINE_TESTS -I"$gtest/include" \
  "$source_dir/tests/unit/test_gssapi_admission.cpp" \
  "$source_dir/tests/unit/test_pam_broker_protocol.cpp" \
  "$source_dir/tests/unit/test_pam_broker_policy.cpp" \
  "$source_dir/tests/unit/test_web_auth.cpp" \
  "$source_dir/src/auth/pam_client.cpp" \
  "$source_dir/src/auth/web_auth.cpp" \
  "$source_dir/src/session/session_context.cpp" \
  "$build_dir/gtest-all.o" "$build_dir/gtest_main.o" \
  -lcrypto -lsystemd
"$build_dir/test-auth"
