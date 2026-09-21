/**
 * @file tools/plank_probe_handoff.cpp
 * @brief Operator probe for the GDM handoff pass and pam_plank_handoff.so.
 *
 *   plank-probe-handoff write <account>          write a pass as the worker would
 *   plank-probe-handoff login <service> <account> run auth + account phases
 *
 * `login` answers every PAM prompt with an error, so it succeeds only when a
 * module admits the account without asking (the handoff path). Exit status 0
 * means both phases returned PAM_SUCCESS. Root only; see
 * docs/plank-desktop-handoff.md.
 */
#include <cstdio>
#include <cstring>
#include <pwd.h>
#include <string>
#include <unistd.h>
#include <vector>

#include <security/pam_appl.h>

#include "src/auth/desktop_handoff_pass.h"

namespace {
  int refuse_prompts(int, const pam_message **, pam_response **, void *) {
    return PAM_CONV_ERR;
  }

  int usage() {
    std::fputs("usage: plank-probe-handoff write <account>\n"
               "       plank-probe-handoff login <service> <account>\n", stderr);
    return 2;
  }
}  // namespace

int main(int argc, char **argv) {
  if (geteuid() != 0) {
    std::fputs("plank-probe-handoff must run as root\n", stderr);
    return 2;
  }
  if (argc == 3 && std::strcmp(argv[1], "write") == 0) {
    std::vector<char> buffer(16384);
    passwd entry {};
    passwd *result = nullptr;
    if (getpwnam_r(argv[2], &entry, buffer.data(), buffer.size(), &result) != 0 || result == nullptr) {
      std::fputs("unknown account\n", stderr);
      return 1;
    }
    namespace handoff = plank::auth::handoff;
    const handoff::pass_t pass {result->pw_uid, argv[2], handoff::boottime_ms() + handoff::pass_lifetime_ms};
    if (pass.uid == 0 || !handoff::typeable_account_name(pass.account) || !handoff::write_pass(pass)) {
      std::fputs("pass not written\n", stderr);
      return 1;
    }
    std::puts("pass written");
    return 0;
  }
  if (argc == 4 && std::strcmp(argv[1], "login") == 0) {
    const pam_conv conversation {refuse_prompts, nullptr};
    pam_handle_t *handle = nullptr;
    int status = pam_start(argv[2], argv[3], &conversation, &handle);
    if (status != PAM_SUCCESS) {
      std::printf("pam_start: %s\n", pam_strerror(handle, status));
      return 1;
    }
    status = pam_authenticate(handle, 0);
    std::printf("authenticate: %s\n", pam_strerror(handle, status));
    if (status == PAM_SUCCESS) {
      status = pam_acct_mgmt(handle, 0);
      std::printf("account: %s\n", pam_strerror(handle, status));
    }
    pam_end(handle, status);
    return status == PAM_SUCCESS ? 0 : 1;
  }
  return usage();
}
