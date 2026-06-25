
#include <string>
#include <string_view>

namespace admin {

enum class Status {
  OK,
  ERR_ALREADY_STARTED,
  ERR_NOT_STARTED,
  ERR_INVALID_PARAM
};


class Heap {
public:
  /**
   * @return whether the profiler is enabled in this build or not.
   */
  static bool profilerEnabled();

  /**
   * @return whether the profiler is started or not
   */
  static bool isProfilerStarted();

  /**
   * Start the profiler and write to the specified path.
   * @return bool whether the call to start the profiler succeeded.
   */
  static bool startProfiler(const std::string& output_path);

  /**
   * Stop the profiler.
   * @return bool whether the file is dumped
   */
  static bool stopProfiler();

  /**
   * Handle heap profile.
   * @return int the status of dump
   */
  static Status handleHeapProfile(std::string_view data);
};
} // namespace admin