#pragma once

#include <string_view>

namespace http {
class Url {
public:
  bool initialize(std::string_view url, bool is_connect);
  std::string_view host() const { return host_; }
  std::string_view path() const { return path_; }

private:
  std::string_view host_;
  std::string_view path_;
  std::string_view scheme_;
};
} // namespace http