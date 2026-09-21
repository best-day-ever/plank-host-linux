# Desktop handoff: one login, one person per workstation

`security.desktop_handoff = true` finishes a PLANK login on the workstation
itself, so the person who just authenticated (password on the LAN, or the
broker's Kerberos ticket with the OTP/passkey indicator) never types a second
password, and a workstation serves one person at a time.

| Workstation state when the stream is admitted | What the host does |
| --- | --- |
| GDM greeter | Signs the account into GDM (below). |
| The account's own desktop, locked | Unlocks it through logind `UnlockSession`. |
| The account's own desktop, unlocked | Nothing extra. |
| Another account's desktop, no PLANK stream | Refuses with `409`, names the owner, offers sign-out. |
| Another account is streaming (desktop or greeter) | Refuses with `409`, names that account, no sign-out. |

The last row applies whether or not `desktop_handoff` is set: while one
account's stream or launch is active, a stream for any other account is
refused, including at the greeter. Session takeover (`plankTakeover=1`) only
moves a stream between clients of the same account.

## Greeter sign-in

1. The stream is admitted on the greeter worker. The worker writes a one-shot
   pass `/run/plank/handoff/<uid>` (root, `0600`, directory `0700`) naming the
   account and a `CLOCK_BOOTTIME` deadline 45 seconds out. The pass holds no
   secret.
2. Once the stream is live, the worker opens the greeter's X display and sends
   XTest key events: Shift (wakes a blanked greeter, which drops keys while it
   fades in), Escape, Tab (after a blank GNOME Shell leaves the entry without key
   focus; it is the only focusable control), Control+A and BackSpace (clear
   the entry), the account
   name, Return. Keysyms are resolved against the greeter's keymap, so any
   layout works. If GDM has not claimed the pass six seconds later, the
   sequence runs once more. Account names outside
   `[a-z0-9._-]` (at most 64 characters, not starting with `-`) are never typed.
3. GDM starts a `gdm-password` conversation. `pam_plank_handoff.so`, listed
   first, claims the pass with an atomic rename (single use across GDM's
   parallel conversations), checks owner, mode, account, UID and deadline,
   deletes it and returns success without prompting. Its account phase admits
   the same handle, because PLANK already ran the account phase (including
   FreeIPA HBAC) under `plank-host` or `plank-remote` seconds earlier.
4. GDM opens the desktop. The supervisor replaces the greeter worker, the
   Client receives the existing desktop-handoff notice and reconnects with a
   fresh login, exactly as after a manual greeter login.

Without a valid pass the module returns `PAM_IGNORE`, so desk logins use the
unchanged password stack. It honours only the `gdm-password` service. A pass
the GDM login never claims is deleted after its lifetime.

`/etc/pam.d/gdm-password` belongs to the `gdm` package, so the RPM does not
edit it. Add, before the existing lines of each phase:

```
auth     sufficient                                pam_plank_handoff.so
account  [success=done ignore=ignore default=bad]  pam_plank_handoff.so
```

Put the `account` line after `pam_nologin.so`, so `/run/nologin` still blocks
logins. The greeter must show an account-name entry rather than a user list
(`org/gnome/login-screen/disable-user-list=true` in the `gdm` dconf database).
Disable user switching (`org/gnome/desktop/lockdown/disable-user-switching=true`)
so no second desktop can start behind a locked one.

A login without a password cannot unlock the GNOME login keyring. Applications
that store secrets there prompt for the keyring password or should be
configured not to use it.

## Signing out an idle owner

A `/launch` or `/resume` from account B while account A owns the desktop and
no PLANK stream is active returns:

```xml
<root status_code="409" status_message="alice is signed in on this workstation">
  <PlankDesktopOwner>alice</PlankDesktopOwner>
  <PlankDesktopSignOut>available</PlankDesktopSignOut>
</root>
```

B's bearer token stays valid. Repeating the request with
`plankSignOutDesktop=1&plankSignOutOwner=alice` makes the worker re-check both
conditions and call logind `TerminateSession` for A's desktop. It answers `503`
with `PlankDesktopSignOut` `started`, and the token is consumed. GDM returns to
the greeter, and B's next full connect lands there and is signed in as above.
The worker logs which account ended which desktop. If A is streaming,
`PlankDesktopSignOut` is `connected` and nothing can be signed out. Hosts
advertise the behaviour with feature flag `0x400000`.

## Verification

- `tests/unit/test_desktop_handoff_pass.cpp` covers the pass format, the
  deadline and account rules, and the typeable-name filter.
- `tests/auth/handoff-pam-e2e.sh`, run as root in a disposable Rocky Linux 9
  container after `scripts/test-auth-standalone.sh`, drives real Linux-PAM:
  no pass, wrong account, single use, other service, file mode, expiry,
  deadline beyond the lifetime, symlink and root.
- On a workstation, `plank-probe-handoff write <account>` followed by
  `plank-probe-handoff login gdm-password <account>` exercises the installed
  stack without GDM. A successful login consumes the pass.
