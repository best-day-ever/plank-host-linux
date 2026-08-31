/**
 * @file src/httpcommon.cpp
 * @brief Definitions for common HTTP.
 */
// standard includes
#include <filesystem>
// local includes
#include "config.h"
#include "crypto.h"
#include "file_handler.h"
#include "httpcommon.h"
#include "logging.h"

namespace http {
  using namespace std::literals;
  namespace fs = std::filesystem;

  std::string unique_id;  ///< Unique ID.

  /**
   * @brief Load persisted HTTP credentials and initialize shared request state.
   */
  int init() {
    if ((!fs::exists(config::nvhttp.pkey) || !fs::exists(config::nvhttp.cert)) && create_creds(config::nvhttp.pkey, config::nvhttp.cert)) {
      return -1;
    }
    return 0;
  }

  /**
   * @brief Generate HTTPS credential files from the provided key and certificate paths.
   */
  int create_creds(const std::string &pkey, const std::string &cert) {
    fs::path pkey_path = pkey;
    fs::path cert_path = cert;

    auto creds = crypto::gen_creds("StationConnect Host"sv, 3072);

    auto pkey_dir = pkey_path;
    auto cert_dir = cert_path;
    pkey_dir.remove_filename();
    cert_dir.remove_filename();

    std::error_code err_code {};
    fs::create_directories(pkey_dir, err_code);
    if (err_code) {
      BOOST_LOG(error) << "Couldn't create directory ["sv << pkey_dir << "] :"sv << err_code.message();
      return -1;
    }

    fs::create_directories(cert_dir, err_code);
    if (err_code) {
      BOOST_LOG(error) << "Couldn't create directory ["sv << cert_dir << "] :"sv << err_code.message();
      return -1;
    }

    if (file_handler::write_file(
          pkey.c_str(),
          creds.pkey,
          fs::perms::owner_read | fs::perms::owner_write)) {
      BOOST_LOG(error) << "Couldn't open ["sv << config::nvhttp.pkey << ']';
      return -1;
    }

    if (file_handler::write_file(
          cert.c_str(),
          creds.x509,
          fs::perms::owner_read | fs::perms::owner_write |
            fs::perms::group_read | fs::perms::others_read)) {
      BOOST_LOG(error) << "Couldn't open ["sv << config::nvhttp.cert << ']';
      return -1;
    }

    return 0;
  }

}  // namespace http
