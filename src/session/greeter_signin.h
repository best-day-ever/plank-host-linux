/**
 * @file src/session/greeter_signin.h
 * @brief Sign a PLANK-authenticated account into the GDM greeter it is streaming.
 */
#pragma once

#include <functional>
#include <string>
#include <sys/types.h>

namespace plank::session {
  /**
   * @brief Hand the greeter to the account that just authenticated with PLANK.
   *
   * Writes a one-shot handoff pass (auth/desktop_handoff_pass.h) and, once the
   * stream is live, types the account name and Return into the greeter on the
   * worker's X display through XTest. `pam_plank_handoff.so` in
   * `gdm-password` consumes the pass, so GDM starts the desktop without a
   * second password prompt. A later call supersedes an earlier one; the pass
   * is removed again after its lifetime if GDM never claimed it.
   *
   * @param uid Authenticated account UID (never root).
   * @param account Authenticated account name; must be typeable.
   * @param stream_live True while an authenticated stream of this worker runs.
   * @return False when the account cannot be handed off or the pass cannot be written.
   */
  bool sign_into_greeter(uid_t uid, const std::string &account, std::function<bool()> stream_live);

  /** Withdraw any pending handoff, for example when the stream ended first. */
  void cancel_greeter_signin();
}  // namespace plank::session
