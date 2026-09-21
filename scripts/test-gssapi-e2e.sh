#!/usr/bin/env bash
# Run tests/auth/gssapi-kdc-e2e.sh in a disposable Rocky Linux 9 container:
# builds the PAM broker, GSSAPI probe and auth unit tests, starts a throwaway
# MIT KDC, and exercises brokered Kerberos admission end to end. Needs Docker
# (or a compatible CLI) and the non-recursive googletest submodule:
#
#   git submodule update --init third-party/lizardbyte-common
#   git -C third-party/lizardbyte-common submodule update --init third-party/googletest
#   scripts/test-gssapi-e2e.sh [image]
set -euo pipefail
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
image=${1:-${PLANK_GSSAPI_E2E_IMAGE:-rockylinux/rockylinux:9}}
exec docker run --rm -v "$source_dir:/src:ro" "$image" bash /src/tests/auth/gssapi-kdc-e2e.sh
