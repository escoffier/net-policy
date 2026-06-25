#include "http_filter_factory.h"
#include <algorithm>

namespace http {
void HttpFilterFactory::registerFilter(FilterCB cb) {
  filterCbs_.push_back(cb);
}

void HttpFilterFactory::traverse(std::function<void (FilterCB)> f) {
    std::for_each(filterCbs_.begin(), filterCbs_.end(), [f](FilterCB &cb) {
        f(cb);
    });
}
} // namespace http