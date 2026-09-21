# Brokered Kerberos (GSSAPI) admission

PLANK normally authenticates every connection with an interactive PAM
conversation (`POST /plank/auth/start` then `POST /plank/auth/respond`). A
host can additionally admit a client that presents a single Kerberos AP-REQ
created for it by a trusted remote-access broker. The host checks the token
itself against its own keytab, so a compromised broker cannot mint sessions.
It holds no key that the host trusts. The feature is off unless
`security.gssapi_keytab` is set.

## Flow

1. The broker holds the user's ticket-granting ticket, which was obtained with
   the user's own credentials. It builds an AP-REQ for `plank/<host fqdn>@REALM`
   with the raw Kerberos V5 mechanism (OID 1.2.840.113554.1.2.2), not SPNEGO,
   and with the channel bindings described below. It hands the AP-REQ to the
   client.
2. The client opens TLS to the host, pins the host leaf certificate, and sends
   `POST /plank/auth/start` with
   `{"username": "alice", "gssapi_token": "<standard padded base64>"}`.
3. The reply has the same shape as the password path: either
   `{"state": "authenticated", "session_token": ..., "expires_in": 300, ...}`
   or `{"state": "denied", "phase": ..., "pam_status": ...}`. There is never a
   `challenge`. The token can be used only once; a retry needs a new token.
4. Application list, launch, resume and the stream lifetime are unchanged.

A token that is malformed, not canonical base64, empty, or larger than 32 KiB
after decoding is denied without contacting the PAM broker. A non-string
`gssapi_token` is rejected as `invalid-request` (HTTP 400).

## Channel bindings

`application_data = "tls-server-end-point:" || SHA-256(DER of the host leaf certificate)`.
That is 21 ASCII bytes followed by the raw 32-byte digest (RFC 5929; the digest
is fixed to SHA-256). Initiator and acceptor address types are both
`GSS_C_AF_UNSPEC` (0), with empty addresses. This is what python-gssapi's
`ChannelBindings(application_data=...)` produces. The broker computes the
leaf digest from the certificate it pinned for the host. The host computes it
from the PEM file named by `cert` in `host.conf`, which is the certificate its
TLS listener serves. `plank-probe-gssapi bindings --cert <pem>` prints the
exact bytes for comparison.

MIT Kerberos accepts a token that carries no bindings even when the acceptor
supplies them. The host therefore also requires `GSS_C_CHANNEL_BOUND_FLAG` in
the returned context flags, so a token without bindings is denied.

## Admission policy (root `plank-pam-broker`)

The network-facing media worker never loads Kerberos code. It forwards the
decoded token to the root broker in a `begin_gssapi` message. The broker's
forked per-connection handler then does the following:

- acquires acceptor credentials with `gss_acquire_cred_from` and the
  `keytab` credential store element. No process-global keytab state is
  changed. The keytab must be a root-owned, nonempty regular file with no
  group or other permissions.
- calls `gss_accept_sec_context` with the channel bindings above. The
  library replay cache is used. At startup the broker removes any
  `KRB5RCACHETYPE`/`KRB5RCACHENAME` override. If `/var/cache/krb5rcache`
  exists and is root-owned, the broker points `KRB5RCACHEDIR` there, so
  replay state survives broker restarts even under `PrivateTmp=`.
- requires, and denies on any failure:
  - a complete context from a single token, using the Kerberos V5 mechanism;
  - verified channel bindings (`GSS_C_CHANNEL_BOUND_FLAG`);
  - a non-anonymous initiator;
  - an acceptor principal of the form `plank/<host>@<default realm>`;
  - a single-component initiator principal in the host's default realm;
  - `gss_localname()` (the host's `auth_to_local`/SSSD mapping) equal to the
    requested username;
  - at least one of the indicators listed in
    `security.gssapi_required_indicator` (a whitespace-separated list, default
    `otp`; for example `otp passkey`) among the KDC-authenticated
    `auth-indicators` name attribute values.
- skips `pam_authenticate()` after admission and runs `pam_acct_mgmt()`,
  `pam_setcred(PAM_ESTABLISH_CRED)` and `pam_open_session()` under the PAM
  service `security.gssapi_pam_service` (default `plank-remote`). From there
  it follows the password path exactly: the same result message, the same
  session lifetime and the same cleanup. The PAM conversation is
  non-interactive. Informational messages are dropped. A module that prompts,
  for example for an expired password, fails its phase.
- still applies `security.allow_root_login` before any Kerberos work.

A separate PAM service matters because FreeIPA HBAC and similar account
policy are evaluated per service name. `plank-host` (LAN password logins) and
`plank-remote` (brokered logins) can then be granted independently.

Denials are logged with the requested account, remote address, initiator
principal (when known) and reason. Token bytes are never logged.

## Local protocol

`begin_gssapi` is message type 6 in the version 1 PAM broker framing. Its
payload is the `begin` payload (username, remote host, logical TTY, each a
length-prefixed string) followed by one length-prefixed opaque field of 1 to
32768 bytes holding the token. The broker answers with exactly one `result`.
A caller that receives a `challenge` treats it as a protocol denial. A broker
built before this change rejects type 6 as malformed and closes the
connection, which the caller reports as denied.

## lock_on_disconnect

With `security.lock_on_disconnect = true`, the media worker waits 5 seconds
after the last authenticated stream ends. If no stream is running and no
launch is pending at that point, it locks the attached graphical session with
`org.freedesktop.login1.Manager.LockSession`, and falls back to
`loginctl lock-session <id>`. Only the supervisor-attested session is locked,
and only if it is still the active seat0 session with class `user`; the GDM
greeter is never locked. The grace period means that a reconnect or a session
takeover by the desktop owner (the only account that may launch a stream on
that desktop) does not land on a lock screen. The setting applies to both the
password and the GSSAPI path. The worker runs as root, and polkit always
authorizes root for `org.freedesktop.login1.lock-sessions`.

## Verification

- Unit tests: `tests/unit/test_gssapi_admission.cpp` (policy, bindings,
  base64), plus the GSSAPI additions to `test_pam_broker_protocol.cpp`,
  `test_pam_broker_policy.cpp` and `test_web_auth.cpp`.
  `scripts/test-auth-standalone.sh` builds and runs these tests, the broker and
  the probe without the media-worker dependency set.
- End to end: `scripts/test-gssapi-e2e.sh` starts a throwaway MIT KDC in a
  Rocky Linux 9 container. PKINIT's `pkinit_indicator` stands in for
  FreeIPA's OTP indicator. The script checks admission, each denial class,
  replay, the `plank-remote` PAM service, and that token bytes stay out of the
  log.
- On a real host: run `kinit` as the user through the normal OTP login, then
  `plank-probe-gssapi initiate --service plank@<fqdn> --cert /etc/plank/tls/cert.pem`
  and pipe the output into
  `sudo plank-probe-gssapi accept --user <name> --config /etc/plank/host.conf`.
  The probe does not run PAM, and a token it accepts is consumed.
