#include "cjson.h"
#include "gperftools/heap-profiler.h"

#include "profile.h"
#include <cstring>
#include <glog/logging.h>
#include <string_view>

namespace admin {

const char* heap_profile_path = "agent.prof";

bool Heap::startProfiler(const std::string& output_path) {
  HeapProfilerStart(output_path.c_str());
  return true;
}

bool Heap::stopProfiler() {
  if (!IsHeapProfilerRunning()) {
    return false;
  }
  HeapProfilerDump("stop and dump");
  HeapProfilerStop();
  return true;
}

bool Heap::isProfilerStarted() { return IsHeapProfilerRunning(); }

bool Heap::profilerEnabled() { return true; }

Status Heap::handleHeapProfile(std::string_view data) {
  cJSON* root = cJSON_Parse(data.data());

  auto item = cJSON_GetObjectItem(root, "enable");
  std::string_view value{item->valuestring, strlen(item->valuestring)};
  if (value != "y" && value != "n") {
    LOG(ERROR) << "invalid enable: " << value;
    return Status::ERR_INVALID_PARAM;
  }

  bool enable = value == "y";
  if (enable) {
    if (Heap::isProfilerStarted()) {
      LOG(ERROR) << "heap dump already started";
      return Status::ERR_ALREADY_STARTED;
    }
    Heap::startProfiler(heap_profile_path);
  } else {
    if (Heap::isProfilerStarted()) {
      Heap::stopProfiler();
      return Status::OK;
    }
    LOG(ERROR) << "heap dump not started";
    return Status::ERR_NOT_STARTED;
  }
  return Status::OK;
}

} // namespace admin