#pragma once

// #include <array>
// #include <cstddef>

#include <array>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <utility>

namespace common {

template <typename Value, size_t Max> class array_map {
  std::array<Value, Max> _a{};

public:
  array_map(std::initializer_list<std::pair<size_t, Value>> i) {
    for (auto kv : i) {
      _a[kv.first] = kv.second;
    }
  }
  Value &operator[](size_t key) { return _a[key]; }
  const Value &operator[](size_t key) const { return _a[key]; }

  Value &at(size_t key) {
    if (key >= Max) {
      throw std::out_of_range(std::to_string(key) +
                              " >= " + std::to_string(Max));
    }
    return _a[key];
  }
};
} // namespace