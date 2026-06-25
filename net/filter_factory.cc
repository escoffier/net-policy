#include "filter_factory.h"

namespace net {
void NetworkFilterFactory::registerFilter(FilterCB cb) { filterCbs_.emplace_back(cb); }

void NetworkFilterFactory::traverse(std::function<void(FilterCB)> f) {
  std::for_each(filterCbs_.begin(), filterCbs_.end(), [f](FilterCB& cb) { f(cb); });
}
} // namespace net