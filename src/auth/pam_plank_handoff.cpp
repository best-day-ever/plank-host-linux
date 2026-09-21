/**
 * @file src/auth/pam_plank_handoff.cpp
 * @brief PAM module that finishes a PLANK login at the GDM greeter.
 *
 * Installed as `pam_plank_handoff.so` and listed first in `gdm-password`:
 *
 *     auth     sufficient                        pam_plank_handoff.so
 *     account  [success=done ignore=ignore default=bad] pam_plank_handoff.so
 *
 * The account was already authenticated by PLANK (password, or a broker
 * Kerberos ticket carrying the OTP/passkey indicator) and passed the
 * `plank-host`/`plank-remote` account phase, including FreeIPA HBAC. The PLANK
 * media worker then leaves a one-shot pass (desktop_handoff_pass.h) and types
 * the account name into the greeter. This module consumes that pass instead of
 * prompting again. Without a valid pass it returns PAM_IGNORE, so the normal
 * password stack runs unchanged. Only the `gdm-password` service is honoured.
 */
#include <cstring>
#include <pwd.h>
#include <string>
#include <syslog.h>
#include <vector>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "desktop_handoff_pass.h"

namespace {
  constexpr char data_key[] = "plank_handoff_admitted";
  constexpr char allowed_service[] = "gdm-password";

  bool service_allowed(pam_handle_t *handle) {
    const void *service = nullptr;
    return pam_get_item(handle, PAM_SERVICE, &service) == PAM_SUCCESS && service != nullptr &&
           std::strcmp(static_cast<const char *>(service), allowed_service) == 0;
  }

  bool account_uid(const char *account, uid_t &uid) {
    std::vector<char> buffer(16384);
    passwd entry {};
    passwd *result = nullptr;
    if (getpwnam_r(account, &entry, buffer.data(), buffer.size(), &result) != 0 || result == nullptr) {
      return false;
    }
    uid = result->pw_uid;
    return true;
  }

  void cleanup_flag(pam_handle_t *, void *, int) {}
}  // namespace

extern "C" {
  PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int, int, const char **) {
    if (!service_allowed(handle)) return PAM_IGNORE;
    // The greeter has already collected the account name; never prompt here.
    const void *item = nullptr;
    if (pam_get_item(handle, PAM_USER, &item) != PAM_SUCCESS || item == nullptr) return PAM_IGNORE;
    const std::string account {static_cast<const char *>(item)};
    uid_t uid {};
    if (!plank::auth::handoff::typeable_account_name(account) || !account_uid(account.c_str(), uid) ||
        uid == 0) {
      return PAM_IGNORE;
    }
    const auto pass = plank::auth::handoff::consume_pass(uid);
    if (!pass) return PAM_IGNORE;
    if (!plank::auth::handoff::admits(*pass, uid, account, plank::auth::handoff::boottime_ms())) {
      pam_syslog(handle, LOG_WARNING, "rejected an expired or mismatched PLANK handoff pass for %s",
                 account.c_str());
      return PAM_IGNORE;
    }
    // Static non-null marker: the account phase admits only this handle.
    static char admitted_marker = 1;
    if (pam_set_data(handle, data_key, &admitted_marker, cleanup_flag) != PAM_SUCCESS) {
      return PAM_IGNORE;
    }
    pam_syslog(handle, LOG_NOTICE, "PLANK handoff: signed %s in without a second prompt", account.c_str());
    return PAM_SUCCESS;
  }

  PAM_EXTERN int pam_sm_setcred(pam_handle_t *handle, int, int, const char **) {
    const void *admitted = nullptr;
    return pam_get_data(handle, data_key, &admitted) == PAM_SUCCESS && admitted != nullptr ?
      PAM_SUCCESS : PAM_IGNORE;
  }

  PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *handle, int, int, const char **) {
    // PLANK's own account phase (plank-host or plank-remote, with HBAC) ran
    // seconds ago for this account; it replaces the gdm-password HBAC check,
    // which a remote-only assignment does not grant.
    const void *admitted = nullptr;
    return service_allowed(handle) && pam_get_data(handle, data_key, &admitted) == PAM_SUCCESS &&
               admitted != nullptr ?
      PAM_SUCCESS : PAM_IGNORE;
  }
}
