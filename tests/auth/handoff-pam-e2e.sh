#!/usr/bin/env bash
# End-to-end check of pam_plank_handoff.so against real Linux-PAM, as root in
# a disposable Rocky Linux 9 container (never on a workstation: it replaces
# /etc/pam.d/gdm-password). Expects scripts/test-auth-standalone.sh to have
# built pam_plank_handoff.so and plank-probe-handoff into the build directory.
#
#   tests/auth/handoff-pam-e2e.sh [build-dir]
set -euo pipefail

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
build_dir=${1:-"$source_dir/cmake-build-auth"}
probe="$build_dir/plank-probe-handoff"
[[ $(id -u) == 0 && -f /.dockerenv || -n ${PLANK_HANDOFF_E2E_CONTAINER:-} ]] || {
  echo "run as root inside a disposable container" >&2
  exit 2
}

install -D -m 0755 "$build_dir/pam_plank_handoff.so" /usr/lib64/security/pam_plank_handoff.so
for service in gdm-password plank-handoff-other; do
  cat > "/etc/pam.d/$service" <<'PAM'
auth     sufficient                                pam_plank_handoff.so
auth     required                                  pam_deny.so
account  [success=done ignore=ignore default=bad]  pam_plank_handoff.so
account  required                                  pam_deny.so
PAM
done
mkdir -p /run/plank
id handoffa >/dev/null 2>&1 || useradd -M handoffa
id handoffb >/dev/null 2>&1 || useradd -M handoffb

failures=0
expect() {
  local want=$1 name=$2
  shift 2
  if "$@" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [[ $got == "$want" ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name (wanted $want)"
    failures=$((failures + 1))
  fi
}
uid_a=$(id -u handoffa)
pass_a=/run/plank/handoff/$uid_a

expect fail "no pass: gdm-password falls through to the password stack" "$probe" login gdm-password handoffa
"$probe" write handoffa >/dev/null
[[ $(stat -c '%u %a' /run/plank/handoff) == "0 700" ]] || { echo "FAIL directory mode"; failures=$((failures + 1)); }
[[ $(stat -c '%u %a' "$pass_a") == "0 600" ]] || { echo "FAIL pass mode"; failures=$((failures + 1)); }
expect fail "pass for another account does not admit" "$probe" login gdm-password handoffb
expect pass "pass admits its account without a prompt (auth + account)" "$probe" login gdm-password handoffa
expect fail "pass is single-use" "$probe" login gdm-password handoffa
[[ ! -e $pass_a ]] || { echo "FAIL consumed pass still on disk"; failures=$((failures + 1)); }

"$probe" write handoffa >/dev/null
expect fail "other PAM services ignore the pass" "$probe" login plank-handoff-other handoffa
expect pass "an ignored pass is left for gdm-password" "$probe" login gdm-password handoffa

"$probe" write handoffa >/dev/null
chmod 0644 "$pass_a"
expect fail "group/world-readable pass is refused" "$probe" login gdm-password handoffa
[[ ! -e $pass_a ]] || { echo "FAIL refused pass not deleted"; failures=$((failures + 1)); }

"$probe" write handoffa >/dev/null
sed -i "s/^expires=.*/expires=1/" "$pass_a"
expect fail "expired pass is refused" "$probe" login gdm-password handoffa

"$probe" write handoffa >/dev/null
sed -i "s/^expires=.*/expires=99999999999999/" "$pass_a"
expect fail "pass with a deadline beyond its lifetime is refused" "$probe" login gdm-password handoffa

printf 'PLANK-HANDOFF-1\nuid=%s\naccount=handoffa\nexpires=99\n' "$uid_a" > /tmp/handoff-target
ln -sf /tmp/handoff-target "$pass_a"
expect fail "symlinked pass is refused" "$probe" login gdm-password handoffa

expect fail "root is never handed off" "$probe" write root

if ((failures)); then
  echo "handoff_pam_e2e=fail failures=$failures"
  exit 1
fi
echo "handoff_pam_e2e=pass"
