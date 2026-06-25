#include "url.hh"
#include "http1/http_parser.h"
#include <cstdint>
#include <glog/logging.h>
#include <iostream>
#include <iterator>
#include <string_view>

namespace http {
bool Url::initialize(std::string_view absolute_url, bool is_connect) {
  struct http_parser_url u;
  http_parser_url_init(&u);
  const int result = http_parser_parse_url(
      absolute_url.data(), absolute_url.length(), is_connect, &u);
  if (result != 0) {
    std::cout << "http_parser_parse_url err:  " << result << std::endl;
    return false;
  }

  // if ((u.field_set & (1 << UF_HOST)) != (1 << UF_HOST) &&
  //     (u.field_set & (1 << UF_SCHEMA)) != (1 << UF_SCHEMA)) {
  //   std::cout << "invalid fields" << std::endl;
  //   return false;
  // }

  scheme_ = std::string_view(absolute_url.data() + u.field_data[UF_SCHEMA].off,
                             u.field_data[UF_SCHEMA].len);

  uint64_t host_len = u.field_data[UF_HOST].len;
//   if ((u.field_set & (1 << UF_PORT)) == (1 << UF_PORT)) {
//     authority_len = authority_len + u.field_data[UF_PORT].len + 1;
//   }

  uint64_t host_beginning = u.field_data[UF_HOST].off;
  host_ = std::string_view(absolute_url.data()+ host_beginning, host_len);

  uint64_t path_beginning = u.field_data[UF_PATH].off;
  uint64_t path_len = u.field_data[UF_PATH].len;
  path_ = std::string_view(absolute_url.data()+ path_beginning, path_len);
  VLOG(8) << "url path: " << path_ ;
  
  //   const bool is_ipv6 = maybeAdjustForIpv6(absolute_url,
  //   authority_beginning, authority_len);
//   host_and_port_ = std::string_view(absolute_url.data() + authority_beginning,
//                                     authority_len);
  //   if (is_ipv6 && !parseAuthority(host_and_port_).is_ip_address_) {
  //     return false;
  //   }

  // RFC allows the absolute-uri to not end in /, but the absolute path form
  // must start with. Determine if there's a non-zero path, and if so determine
  // the length of the path, query params etc.
//   uint64_t path_etc_len =
//       absolute_url.length() - (authority_beginning + host_and_port_.length());
//   if (path_etc_len > 0) {
//     uint64_t path_beginning = authority_beginning + host_and_port_.length();
//     path_and_query_params_ =
//         std::string_view(absolute_url.data() + path_beginning, path_etc_len);
//   } else if (!is_connect) {
//     // ASSERT((u.field_set & (1 << UF_PATH)) == 0);
//     path_and_query_params_ = std::string_view(kDefaultPath, 1);
//   }

  return true;
}
} // namespace http