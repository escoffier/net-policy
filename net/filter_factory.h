#pragma once
#include "net/filter.h"
#include <functional>
#include <list>
#include <memory>

namespace net {

using FilterCB = std::function<std::shared_ptr<NetworkFilterBase>(size_t id)>;

class NetworkFilterFactory {
public:
  static NetworkFilterFactory &getInstance() {
    static NetworkFilterFactory instance; // Guaranteed to be destroyed.
    // Instantiated on first use.
    return instance;
  }

public:
  NetworkFilterFactory(NetworkFilterFactory const &) = delete;
  
  void operator=(NetworkFilterFactory const &) = delete;

  void registerFilter(FilterCB cb);

  void traverse(std::function<void(FilterCB)>);

private:
  NetworkFilterFactory() {}

private:
  std::list<FilterCB> filterCbs_;
};
}