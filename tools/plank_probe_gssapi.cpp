/**
 * @file tools/plank_probe_gssapi.cpp
 * @brief Operator probe for PLANK brokered Kerberos GSSAPI admission.
 *
 * `initiate` builds the same single AP-REQ a PLANK broker hands to a client,
 * from the caller's own Kerberos credential cache (obtain it with `kinit`;
 * the probe never reads passwords). `accept` runs the root broker's exact
 * acceptor and admission policy on a token read from standard input, without
 * PAM. `bindings` prints the channel-binding application data so a broker
 * implementation can be cross-checked byte for byte.
 *
 *   plank-probe-gssapi initiate --service plank@host.example.com --cert cert.pem
 *   sudo plank-probe-gssapi accept --config /etc/plank/host.conf --user alice
 *   plank-probe-gssapi bindings --cert cert.pem
 *
 * `--no-bindings` makes `initiate` omit channel bindings; the host must deny
 * such a token. It exists only to demonstrate that negative case.
 *
 * An accepted token enters the host replay cache exactly as it would through
 * the broker, so a token accepted by the probe is consumed.
 */

#include "src/auth/gssapi_acceptor.h"
#include "src/auth/gssapi_admission.h"
#include "src/auth/pam_broker_policy.h"

#include <cstdio>
#include <cstring>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>

namespace gssapi = plank::auth::gssapi;

namespace {
  /**
   * @brief Print command-line syntax.
   *
   * @param program Program path.
   * @return Usage exit status.
   */
  int usage(const char *program) {
    std::cerr << "usage:\n"
              << "  " << program << " initiate --service plank@HOST --cert CERT.pem [--no-bindings]\n"
              << "  " << program << " accept --user NAME [--config /etc/plank/host.conf]\n"
              << "  " << program << " bindings --cert CERT.pem\n";
    return 2;
  }

  /**
   * @brief Find the value following a named option.
   *
   * @param argc Argument count.
   * @param argv Argument values.
   * @param name Option name.
   * @param fallback Value when the option is absent.
   * @return Option value.
   */
  std::string option(int argc, char **argv, std::string_view name, std::string fallback = {}) {
    for (int index = 2; index + 1 < argc; ++index) {
      if (name == argv[index]) {
        return argv[index + 1];
      }
    }
    return fallback;
  }

  /**
   * @brief Compute channel-binding application data from a certificate.
   *
   * @param certificate PEM certificate path.
   * @param data Receives the application data.
   * @return True on success.
   */
  bool bindings_for(const std::string &certificate, std::vector<std::uint8_t> &data) {
    std::string error;
    const auto digest = gssapi::certificate_digest(certificate, error);
    if (!digest) {
      std::cerr << error << '\n';
      return false;
    }
    data = gssapi::channel_binding_application_data(*digest);
    return true;
  }

  /**
   * @brief Create one Kerberos V5 initiator token with channel bindings.
   */
  int initiate(const std::string &service, const std::string &certificate, bool with_bindings) {
    std::vector<std::uint8_t> application_data;
    if (service.empty() || !bindings_for(certificate, application_data)) {
      return 2;
    }
    OM_uint32 minor = 0;
    gss_buffer_desc service_buffer {service.size(), const_cast<char *>(service.data())};
    gss_name_t target = GSS_C_NO_NAME;
    OM_uint32 major = gss_import_name(&minor, &service_buffer, GSS_C_NT_HOSTBASED_SERVICE,
                                      &target);
    if (GSS_ERROR(major)) {
      std::cerr << "unable to import service name\n";
      return 1;
    }
    gss_channel_bindings_struct bindings {};
    bindings.initiator_addrtype = GSS_C_AF_UNSPEC;
    bindings.acceptor_addrtype = GSS_C_AF_UNSPEC;
    bindings.application_data.length = application_data.size();
    bindings.application_data.value = application_data.data();
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_buffer_desc output {};
    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &context, target,
                                 const_cast<gss_OID>(gss_mech_krb5), 0, GSS_C_INDEFINITE,
                                 with_bindings ? &bindings : GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER, nullptr, &output, nullptr,
                                 nullptr);
    gss_release_name(&minor, &target);
    if (GSS_ERROR(major) || output.length == 0) {
      std::cerr << "gss_init_sec_context failed (major " << major << ", minor " << minor
                << "); is there a ticket-granting ticket in the credential cache?\n";
      gss_delete_sec_context(&minor, &context, GSS_C_NO_BUFFER);
      return 1;
    }
    std::cout << gssapi::encode_token(
                   {static_cast<const std::uint8_t *>(output.value), output.length})
              << '\n';
    gss_release_buffer(&minor, &output);
    gss_delete_sec_context(&minor, &context, GSS_C_NO_BUFFER);
    return 0;
  }

  /**
   * @brief Run the broker's acceptor and admission policy on a stdin token.
   */
  int accept(const std::string &config, const std::string &user) {
    if (user.empty()) {
      return 2;
    }
    std::string error;
    const auto policy = plank::auth::load_broker_policy(config, error);
    if (!policy) {
      std::cerr << "unable to load policy: " << error << '\n';
      return 2;
    }
    std::string encoded {std::istreambuf_iterator<char> {std::cin}, {}};
    while (!encoded.empty() && (encoded.back() == '\n' || encoded.back() == '\r')) {
      encoded.pop_back();
    }
    auto token = gssapi::decode_token(encoded);
    if (!token) {
      std::cout << "result=denied\nreason=malformed or oversize base64 token\n";
      return 1;
    }
    gssapi::configure_replay_cache();
    const auto acceptance = gssapi::accept_initiator(*policy, *token, user);
    const bool admitted = acceptance.result == gssapi::admission_e::admitted;
    std::cout << "result=" << (admitted ? "admitted" : "denied") << '\n'
              << "reason=" << gssapi::describe(acceptance.result) << '\n';
    if (!acceptance.initiator.empty()) {
      std::cout << "initiator=" << acceptance.initiator << '\n';
    }
    if (!acceptance.detail.empty()) {
      std::cout << "detail=" << acceptance.detail << '\n';
    }
    if (admitted) {
      std::cout << "pam_service=" << policy->gssapi_pam_service
                << " (account and session phases are not run by this probe)\n";
    }
    return admitted ? 0 : 1;
  }
}  // namespace

/**
 * @brief Run the probe.
 *
 * @param argc Argument count.
 * @param argv Argument values.
 * @return 0 on success or admission, 1 on failure or denial, 2 on usage error.
 */
int main(int argc, char **argv) {
  if (argc < 2) {
    return usage(argv[0]);
  }
  const std::string_view command {argv[1]};
  if (command == "initiate") {
    bool with_bindings = true;
    for (int index = 2; index < argc; ++index) {
      with_bindings = with_bindings && std::string_view {argv[index]} != "--no-bindings";
    }
    return initiate(option(argc, argv, "--service"), option(argc, argv, "--cert"), with_bindings);
  }
  if (command == "accept") {
    return accept(option(argc, argv, "--config", "/etc/plank/host.conf"),
                  option(argc, argv, "--user"));
  }
  if (command == "bindings") {
    std::vector<std::uint8_t> data;
    if (!bindings_for(option(argc, argv, "--cert"), data)) {
      return 1;
    }
    constexpr std::string_view digits = "0123456789abcdef";
    std::string hex;
    for (const auto byte : data) {
      hex.push_back(digits[byte >> 4U]);
      hex.push_back(digits[byte & 0x0fU]);
    }
    std::cout << "application_data_hex=" << hex << '\n';
    return 0;
  }
  return usage(argv[0]);
}
