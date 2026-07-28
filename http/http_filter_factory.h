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
  HttpFilterFactory() = default;
  HttpFilterFactory(HttpFilterFactory const &) = delete;
  void operator=(HttpFilterFactory const &) = delete;

  void registerFilter(FilterCB cb);

  void traverse(std::function<void(FilterCB)>);

private:
  std::list<FilterCB> filterCbs_;
};
} // namespace http