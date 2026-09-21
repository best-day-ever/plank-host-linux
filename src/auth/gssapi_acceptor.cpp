/**
 * @file src/auth/gssapi_acceptor.cpp
 * @brief Kerberos GSSAPI acceptor used only by the root PLANK PAM broker.
 */

#include "gssapi_acceptor.h"
#include "pam_broker_protocol.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5/krb5.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace plank::auth::gssapi {
  namespace {
    constexpr char persistent_replay_cache_directory[] = "/var/cache/krb5rcache";

    /**
     * @brief Render GSSAPI major/minor status text without token contents.
     */
    std::string status_text(OM_uint32 major, OM_uint32 minor) {
      std::string text;
      const auto append = [&text](OM_uint32 code, int type) {
        OM_uint32 context = 0;
        do {
          OM_uint32 ignored = 0;
          gss_buffer_desc message {};
          if (GSS_ERROR(gss_display_status(&ignored, code, type, GSS_C_NO_OID, &context,
                                           &message))) {
            break;
          }
          if (!text.empty()) {
            text += "; ";
          }
          text.append(static_cast<const char *>(message.value), message.length);
          gss_release_buffer(&ignored, &message);
        } while (context != 0 && text.size() < 512);
      };
      append(major, GSS_C_GSS_CODE);
      if (minor != 0) {
        append(minor, GSS_C_MECH_CODE);
      }
      return text;
    }

    /**
     * @brief Convert a GSSAPI buffer to a string.
     */
    std::string buffer_string(const gss_buffer_desc &buffer) {
      if (buffer.value == nullptr || buffer.length == 0) {
        return {};
      }
      return {static_cast<const char *>(buffer.value), buffer.length};
    }

    /**
     * @brief Display a GSSAPI name.
     */
    std::string display_name(gss_name_t name) {
      OM_uint32 minor = 0;
      gss_buffer_desc buffer {};
      if (name == GSS_C_NO_NAME || GSS_ERROR(gss_display_name(&minor, name, &buffer, nullptr))) {
        return {};
      }
      auto value = buffer_string(buffer);
      gss_release_buffer(&minor, &buffer);
      return value;
    }

    /**
     * @brief Read the host's default Kerberos realm.
     */
    std::string default_realm() {
      krb5_context context = nullptr;
      if (krb5_init_context(&context) != 0) {
        return {};
      }
      char *realm = nullptr;
      std::string value;
      if (krb5_get_default_realm(context, &realm) == 0 && realm != nullptr) {
        value = realm;
        krb5_free_default_realm(context, realm);
      }
      krb5_free_context(context);
      return value;
    }

    /**
     * @brief Release all GSSAPI objects on scope exit.
     */
    struct resources_t {
      gss_cred_id_t credential {GSS_C_NO_CREDENTIAL};  ///< Acceptor credential.
      gss_ctx_id_t context {GSS_C_NO_CONTEXT};  ///< Accepted context.
      gss_name_t source {GSS_C_NO_NAME};  ///< Initiator name.
      gss_name_t target {GSS_C_NO_NAME};  ///< Acceptor name.
      gss_buffer_desc output {};  ///< Unused mutual-authentication reply.

      ~resources_t() {
        OM_uint32 minor = 0;
        if (output.value != nullptr) {
          gss_release_buffer(&minor, &output);
        }
        if (target != GSS_C_NO_NAME) {
          gss_release_name(&minor, &target);
        }
        if (source != GSS_C_NO_NAME) {
          gss_release_name(&minor, &source);
        }
        if (context != GSS_C_NO_CONTEXT) {
          gss_delete_sec_context(&minor, &context, GSS_C_NO_BUFFER);
        }
        if (credential != GSS_C_NO_CREDENTIAL) {
          gss_release_cred(&minor, &credential);
        }
      }
    };
  }  // namespace

  std::optional<std::array<std::uint8_t, certificate_digest_size>> certificate_digest(
    const std::string &path, std::string &error
  ) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio {BIO_new_file(path.c_str(), "r"), &BIO_free};
    if (!bio) {
      error = "unable to open certificate " + path;
      return std::nullopt;
    }
    std::unique_ptr<X509, decltype(&X509_free)> certificate {
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), &X509_free
    };
    if (!certificate) {
      error = "unable to parse certificate " + path;
      return std::nullopt;
    }
    std::array<std::uint8_t, certificate_digest_size> digest {};
    unsigned int size = 0;
    if (X509_digest(certificate.get(), EVP_sha256(), digest.data(), &size) != 1 ||
        size != digest.size()) {
      error = "unable to hash certificate " + path;
      return std::nullopt;
    }
    return digest;
  }

  bool keytab_is_private(const std::string &path, std::string &error) {
    const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
      error = "unable to open keytab " + path + ": " + std::strerror(errno);
      return false;
    }
    struct stat metadata {};
    const bool valid = fstat(descriptor, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
                       metadata.st_uid == 0 && (metadata.st_mode & 0077) == 0 &&
                       metadata.st_size > 0;
    close(descriptor);
    if (!valid) {
      error = path + " must be a nonempty root-owned regular file without group or other access";
    }
    return valid;
  }

  void configure_replay_cache() {
    // An inherited KRB5RCACHETYPE=none or KRB5RCACHENAME=none: would silently
    // disable replay detection. The default replay cache type is always used.
    unsetenv("KRB5RCACHETYPE");
    unsetenv("KRB5RCACHENAME");
    struct stat metadata {};
    if (getenv("KRB5RCACHEDIR") == nullptr &&
        lstat(persistent_replay_cache_directory, &metadata) == 0 &&
        S_ISDIR(metadata.st_mode) && metadata.st_uid == 0 &&
        (metadata.st_mode & (S_IWGRP | S_IWOTH)) == 0) {
      setenv("KRB5RCACHEDIR", persistent_replay_cache_directory, 1);
    }
  }

  acceptance_t accept_initiator(const broker_policy_t &policy,
                                std::span<const std::uint8_t> token,
                                std::string_view requested_username) {
    acceptance_t acceptance;
    if (!policy.gssapi_enabled()) {
      acceptance.result = admission_e::disabled;
      return acceptance;
    }
    if (token.empty() || token.size() > maximum_gssapi_token_size) {
      acceptance.result = admission_e::context_error;
      acceptance.detail = "token size out of range";
      return acceptance;
    }
    if (!keytab_is_private(policy.gssapi_keytab, acceptance.detail)) {
      return acceptance;
    }
    const auto digest = certificate_digest(policy.tls_certificate, acceptance.detail);
    if (!digest) {
      return acceptance;
    }
    const auto realm = default_realm();
    if (realm.empty()) {
      acceptance.detail = "no default Kerberos realm";
      return acceptance;
    }

    resources_t resources;
    OM_uint32 minor = 0;
    gss_key_value_element_desc store_element {"keytab", policy.gssapi_keytab.c_str()};
    gss_key_value_set_desc store {1, &store_element};
    gss_OID_desc kerberos_oid = *gss_mech_krb5;
    gss_OID_set_desc mechanisms {1, &kerberos_oid};
    OM_uint32 major = gss_acquire_cred_from(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE, &mechanisms,
                                            GSS_C_ACCEPT, &store, &resources.credential,
                                            nullptr, nullptr);
    if (GSS_ERROR(major)) {
      acceptance.detail = "unable to acquire acceptor credential: " + status_text(major, minor);
      return acceptance;
    }

    auto application_data = channel_binding_application_data(*digest);
    gss_channel_bindings_struct bindings {};
    bindings.initiator_addrtype = GSS_C_AF_UNSPEC;
    bindings.acceptor_addrtype = GSS_C_AF_UNSPEC;
    bindings.application_data.length = application_data.size();
    bindings.application_data.value = application_data.data();

    std::vector<std::uint8_t> input_bytes(token.begin(), token.end());
    gss_buffer_desc input {input_bytes.size(), input_bytes.data()};
    gss_OID mechanism = GSS_C_NO_OID;
    OM_uint32 flags = 0;
    major = gss_accept_sec_context(&minor, &resources.context, resources.credential, &input,
                                   &bindings, &resources.source, &mechanism, &resources.output,
                                   &flags, nullptr, nullptr);
    explicit_bzero(input_bytes.data(), input_bytes.size());
    if (GSS_ERROR(major)) {
      acceptance.result = admission_e::context_error;
      acceptance.detail = status_text(major, minor);
      return acceptance;
    }
    if ((major & GSS_S_CONTINUE_NEEDED) != 0) {
      acceptance.result = admission_e::incomplete;
      return acceptance;
    }

    accepted_context_t context;
    context.kerberos_mechanism = mechanism != GSS_C_NO_OID &&
                                 mechanism->length == gss_mech_krb5->length &&
                                 std::memcmp(mechanism->elements, gss_mech_krb5->elements,
                                             mechanism->length) == 0;
    context.channel_bound = (flags & GSS_C_CHANNEL_BOUND_FLAG) != 0;
    context.anonymous = (flags & GSS_C_ANON_FLAG) != 0;
    context.initiator = display_name(resources.source);
    acceptance.initiator = context.initiator;
    if (!GSS_ERROR(gss_inquire_context(&minor, resources.context, nullptr, &resources.target,
                                       nullptr, nullptr, nullptr, nullptr, nullptr))) {
      context.acceptor = display_name(resources.target);
    }

    gss_buffer_desc localname {};
    if (!GSS_ERROR(gss_localname(&minor, resources.source, gss_mech_krb5, &localname))) {
      context.localname = buffer_string(localname);
      gss_release_buffer(&minor, &localname);
    }

    static constexpr char indicator_attribute[] = "auth-indicators";
    gss_buffer_desc attribute {sizeof(indicator_attribute) - 1,
                               const_cast<char *>(indicator_attribute)};
    int more = -1;
    for (int count = 0; more != 0 && count < 64; ++count) {
      int authenticated = 0;
      int complete = 0;
      gss_buffer_desc value {};
      gss_buffer_desc display {};
      if (GSS_ERROR(gss_get_name_attribute(&minor, resources.source, &attribute, &authenticated,
                                           &complete, &value, &display, &more))) {
        break;
      }
      // Only KDC-verified (CAMMAC) indicators are reported as authenticated.
      if (authenticated != 0) {
        context.indicators.push_back(buffer_string(value));
      }
      gss_release_buffer(&minor, &value);
      gss_release_buffer(&minor, &display);
    }

    acceptance.result = evaluate(context, realm, requested_username,
                                 policy.gssapi_required_indicator);
    if (acceptance.result == admission_e::wrong_service) {
      acceptance.detail = "acceptor " + context.acceptor;
    }
    return acceptance;
  }
}  // namespace plank::auth::gssapi
