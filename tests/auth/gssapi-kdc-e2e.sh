#!/usr/bin/env bash
# End-to-end GSSAPI admission test against a throwaway MIT KDC. PKINIT emits
# the "otp" auth indicator here (pkinit_indicator); FreeIPA emits the same
# indicator for OTP logins. Runs as root inside a disposable rockylinux:9
# container started by scripts/test-gssapi-e2e.sh, with this checkout at /src.
# It builds the broker, probe and auth unit tests, then checks admission,
# every denial class, replay protection, the plank-remote PAM service and
# that token bytes never reach the broker log. Exit status is the FAIL count.
set -uo pipefail
SRC_CLIENT=${SRC_CLIENT:-/src/tests/auth/pam-broker-client.py}
failures=0
export REALM=EXAMPLE.TEST
dnf -y -q install passwd krb5-server krb5-workstation krb5-pkinit krb5-devel pam-devel openssl openssl-devel \
  systemd-devel gcc-toolset-14-gcc-c++ python3 >/dev/null 2>&1 || { echo "dnf failed"; exit 1; }
SRC=/src; W=/work; mkdir -p $W; cd $W
cp -r $SRC/src $SRC/tests $SRC/tools $SRC/scripts . ; mkdir -p third-party/lizardbyte-common/third-party/googletest
cp -r $SRC/third-party/lizardbyte-common/third-party/googletest/googletest third-party/lizardbyte-common/third-party/googletest/
if bash scripts/test-auth-standalone.sh $W/build > $W/unit.log 2>&1; then
  echo "PASS auth unit tests: $(grep -E '^\[  PASSED' $W/unit.log)"
else
  failures=$((failures + 1)); echo "FAIL auth unit tests"; grep -E 'FAILED|error' $W/unit.log | head -20
fi
B=$W/build

cat > /etc/krb5.conf <<EOF
[libdefaults]
  default_realm = EXAMPLE.TEST
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
  dns_canonicalize_hostname = false
  pkinit_anchors = FILE:/kdc/ca.pem
[realms]
  EXAMPLE.TEST = {
    kdc = 127.0.0.1
  }
[domain_realm]
  .example.test = EXAMPLE.TEST
EOF
mkdir -p /kdc /var/kerberos/krb5kdc; cd /kdc
cat > /var/kerberos/krb5kdc/kdc.conf <<EOF
[kdcdefaults]
  kdc_ports = 88
[realms]
  EXAMPLE.TEST = {
    pkinit_identity = FILE:/kdc/kdc.pem,/kdc/kdckey.pem
    pkinit_anchors = FILE:/kdc/ca.pem
    pkinit_indicator = otp
  }
EOF
cat > ext.cnf <<'EOF'
[kdc_cert]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name
[kdc_princ_name]
realm=EXP:0,GeneralString:${ENV::REALM}
principal_name=EXP:1,SEQUENCE:kdc_principal_seq
[kdc_principal_seq]
name_type=EXP:0,INTEGER:2
name_string=EXP:1,SEQUENCE:kdc_principals
[kdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:${ENV::REALM}
[client_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name
[princ_name]
realm=EXP:0,GeneralString:${ENV::REALM}
principal_name=EXP:1,SEQUENCE:principal_seq
[principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:principals
[principals]
princ1=GeneralString:${ENV::CLIENT}
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=test-ca -keyout cakey.pem -out ca.pem 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj /CN=kdc -keyout kdckey.pem -out kdc.csr 2>/dev/null
CLIENT=x openssl x509 -req -in kdc.csr -CA ca.pem -CAkey cakey.pem -CAcreateserial -days 2 -extfile ext.cnf -extensions kdc_cert -out kdc.pem 2>/dev/null
for u in alice; do
  openssl req -new -newkey rsa:2048 -nodes -subj /CN=$u -keyout $u-key.pem -out $u.csr 2>/dev/null
  CLIENT=$u openssl x509 -req -in $u.csr -CA ca.pem -CAkey cakey.pem -CAcreateserial -days 2 -extfile ext.cnf -extensions client_cert -out $u.pem 2>/dev/null
done
kdb5_util create -s -r EXAMPLE.TEST -P "$(openssl rand -hex 16)" >/dev/null 2>&1
BOBPW=$(openssl rand -hex 12)
kadmin.local -q "addprinc -randkey +requires_preauth alice" >/dev/null
kadmin.local -q "addprinc -pw $BOBPW bob" >/dev/null
kadmin.local -q "addprinc -randkey plank/host.example.test" >/dev/null
kadmin.local -q "addprinc -randkey host/host.example.test" >/dev/null
kadmin.local -q "ktadd -k /etc/plank-test.keytab plank/host.example.test" >/dev/null
kadmin.local -q "ktadd -k /etc/host-test.keytab host/host.example.test" >/dev/null
chmod 600 /etc/plank-test.keytab /etc/host-test.keytab
krb5kdc || { echo "krb5kdc failed"; exit 1; }
sleep 1
useradd -M alice; useradd -M bob

T=/root/t; mkdir -p -m 700 $T
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 2 -subj /CN=host.example.test -keyout $T/key.pem -out $T/cert.pem 2>/dev/null
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 2 -subj /CN=other -keyout $T/okey.pem -out $T/other.pem 2>/dev/null
printf '[security]\ncert = %s/cert.pem\ngssapi_keytab = /etc/plank-test.keytab\n' $T > $T/host.conf
printf '[security]\ncert = %s/cert.pem\ngssapi_keytab = /etc/host-test.keytab\n' $T > $T/wrongsvc.conf
printf '[security]\ncert = %s/cert.pem\n' $T > $T/off.conf
chmod 600 $T/*.conf

P=$B/plank-probe-gssapi
check() { # name expected-result expected-reason-substring user token
  local out; out=$(echo "$5" | $P accept --config ${CONF:-$T/host.conf} --user "$4")
  local res=$(sed -n 's/^result=//p' <<<"$out") reason=$(sed -n 's/^reason=//p' <<<"$out")
  if [[ $res == "$2" && $reason == *"$3"* ]]; then echo "PASS $1: $res ($reason)"; else failures=$((failures + 1)); echo "FAIL $1: got '$res' '$reason'"; echo "$out" | sed 's/^/    /'; fi
}
ini() { $P initiate --service plank@host.example.test --cert ${CERT:-$T/cert.pem} "$@"; }

# alice: PKINIT login -> ticket carries auth indicator "otp"
kinit -X X509_user_identity=FILE:/kdc/alice.pem,/kdc/alice-key.pem alice || { failures=$((failures + 1)); echo "FAIL pkinit kinit"; }
klist -e 2>/dev/null | grep -q krbtgt && echo "info: alice TGT via PKINIT"
TOK=$(ini); check "otp initiator admitted" admitted admitted alice "$TOK"
check "replayed token" denied "context rejected" alice "$TOK"
check "localname mismatch (alice token for bob)" denied "does not map" bob "$(ini)"
check "root requested" denied "does not map" root "$(ini)"
check "wrong channel binding cert" denied "context rejected" alice "$(CERT=$T/other.pem ini)"
check "no channel bindings" denied "channel bindings absent" alice "$(ini --no-bindings)"
CONF=$T/off.conf check "gssapi not configured" denied "not configured" alice "$(ini)"
TOK=$($P initiate --service host@host.example.test --cert $T/cert.pem)
CONF=$T/wrongsvc.conf check "host/ service key instead of plank/" denied "not for a plank service" alice "$TOK"
printf '[security]\ncert = %s/cert.pem\ngssapi_keytab = /etc/plank-test.keytab\ngssapi_required_indicator = hardened\n' $T > $T/ind.conf; chmod 600 $T/ind.conf
CONF=$T/ind.conf check "different required indicator" denied "indicator absent" alice "$(ini)"
printf '[security]\ncert = %s/cert.pem\ngssapi_keytab = /etc/plank-test.keytab\ngssapi_required_indicator = passkey otp\n' $T > $T/anyof.conf; chmod 600 $T/anyof.conf
CONF=$T/anyof.conf check "any-of indicator list (passkey otp)" admitted admitted alice "$(ini)"
printf '[security]\ncert = %s/cert.pem\ngssapi_keytab = /etc/plank-test.keytab\ngssapi_required_indicator = passkey hardened\n' $T > $T/anyof-miss.conf; chmod 600 $T/anyof-miss.conf
CONF=$T/anyof-miss.conf check "any-of indicator list without otp" denied "indicator absent" alice "$(ini)"
chmod 640 /etc/plank-test.keytab
check "group-readable keytab" denied "configuration error" alice "$(ini)"
chmod 600 /etc/plank-test.keytab
kdestroy
# bob: password login -> no auth indicator
echo "$BOBPW" | kinit bob >/dev/null
check "password-only initiator (no otp indicator)" denied "indicator absent" bob "$(ini)"
kdestroy

# Full broker: GSSAPI path must skip auth (pam_deny) and use the plank-remote service.
# pam_unix auth would fail (no password is ever supplied) if the broker called
# pam_authenticate; its setcred succeeds as with the real system-auth stack.
cat > /etc/pam.d/plank-remote <<'EOF'
auth     required pam_unix.so
account  required pam_permit.so
session  required pam_permit.so
EOF
cat > /etc/pam.d/plank-host <<'EOF'
auth     required pam_deny.so
account  required pam_deny.so
session  required pam_deny.so
EOF
printf '[security]\ncert = %s/cert.pem\ngssapi_keytab = /etc/plank-test.keytab\n' $T > /etc/plank-host.conf; chmod 600 /etc/plank-host.conf
mkdir -p /run/plank
$B/plank-pam-broker --socket /run/plank/pam/auth.sock --config /etc/plank-host.conf > /tmp/broker.log 2>&1 &
BPID=$!; sleep 1
kinit -X X509_user_identity=FILE:/kdc/alice.pem,/kdc/alice-key.pem alice
TOK=$(ini)
r=$(python3 $SRC_CLIENT /run/plank/pam/auth.sock alice "$TOK"); [[ $r == "result phase=7 pam_status=0" ]] && echo "PASS broker admits via plank-remote: $r" || { failures=$((failures + 1)); echo "FAIL broker admit: $r"; }
r=$(python3 $SRC_CLIENT /run/plank/pam/auth.sock alice "$TOK"); [[ $r == "result phase=3 pam_status=7" ]] && echo "PASS broker denies replay: $r" || { failures=$((failures + 1)); echo "FAIL broker replay: $r"; }
r=$(python3 $SRC_CLIENT /run/plank/pam/auth.sock bob "$(ini)"); [[ $r == "result phase=3 pam_status=7" ]] && echo "PASS broker denies mismatched account: $r" || { failures=$((failures + 1)); echo "FAIL broker mismatch: $r"; }
r=$(python3 $SRC_CLIENT /run/plank/pam/auth.sock root "$(ini)"); [[ $r == "result phase=4 pam_status=6" ]] && echo "PASS broker denies root before GSSAPI: $r" || { failures=$((failures + 1)); echo "FAIL broker root: $r"; }
# account phase is enforced for the GSSAPI service
sed -i 's/^account .*/account  required pam_deny.so/' /etc/pam.d/plank-remote
r=$(python3 $SRC_CLIENT /run/plank/pam/auth.sock alice "$(ini)"); [[ $r == "result phase=4 pam_status=7" || $r == result\ phase=4* ]] && echo "PASS broker enforces plank-remote account policy: $r" || { failures=$((failures + 1)); echo "FAIL broker account: $r"; }
kill $BPID; wait $BPID 2>/dev/null
echo "--- broker log (token bytes must not appear)"; cat /tmp/broker.log
if grep -qF "$(echo "$TOK" | cut -c1-24)" /tmp/broker.log; then
  failures=$((failures + 1)); echo "FAIL token bytes appear in the broker log"
else
  echo "PASS token bytes absent from the broker log"
fi
echo "failures=$failures"
exit "$failures"
