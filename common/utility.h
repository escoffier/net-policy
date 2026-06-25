#pragma once

#include <algorithm>
#include <cctype>
#include <string>
namespace utility {
inline std::string toLow(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  
  return s;
};
} // namespace utility
