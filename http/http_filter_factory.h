#pragma once

#include "http/filter.h"
#include <cstddef>
#include <functional>
#include <list>
#include <memory>
namespace http {

using FilterCB = std::function<std::shared_ptr<HttpFilterBase>(size_t id, uint32_t from, uint32_t to)>;

class HttpFilterFactory {
public:
  static HttpFilterFactory &getInstance() {
    static HttpFilterFactory instance; // Guaranteed to be destroyed.
    // Instantiated on first use.
    return instance;
  }

public:
  HttpFilterFactory(HttpFilterFactory const &) = delete;
  void operator=(HttpFilterFactory const &) = delete;

  void registerFilter(FilterCB cb);

  void traverse(std::function<void(FilterCB)>);

private:
  HttpFilterFactory() {}

private:
  std::list<FilterCB> filterCbs_;
};
} // namespace http