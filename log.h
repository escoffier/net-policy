#pragma once

#include <atomic>

/*process-wide log-level threshold; the one deliberate exception to "no
 *global state" in this codebase -- LOG_D/LOG_V/LOG_T are used at hundreds of
 *call sites across every file, so threading a context object through all of
 *them is disproportionate for a single cross-cutting flag. atomic<int>
 *rather than plain int since it may now be read from multiple threads.*/
extern std::atomic<int> g_log_level;

#define POLICY_LOG_LEVEL  "POLICY_LOG_LEVEL"
#define POLICY_WAF_ENABLE "POLICY_WAF_ENABLE"

extern std::string TimeToString();

#define LOG_E(fmt, ...) {\
    fprintf(stderr, "[ERROR] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_I(fmt, ...) {\
    fprintf(stderr, "[INFO] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_W(fmt, ...) {\
    fprintf(stderr, "[WARN] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_D(fmt, ...) {\
    if(g_log_level > 0) fprintf(stderr, "[DEBUG] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_V(fmt, ...) {\
    if(g_log_level > 1) fprintf(stderr, "[VERBOSE] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_T(fmt, ...) {\
    if(g_log_level > 2) fprintf(stderr, "[TRACE] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define RETURN_ERROR(ret, fmt, ...) {\
    fprintf(stderr, "[ERROR] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    return ret;\
}

#define RETURN_INFO(ret, fmt, ...) {\
    fprintf(stderr, "[INFO] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    return ret;\
}

#define RETURN_WARN(ret, fmt, ...) {\
    fprintf(stderr, "[WARN] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    return ret;\
}

#define BREAK_ERROR(fmt, ...) {\
    fprintf(stderr, "[ERROR] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    break;\
}

#define CONTINUE_ERROR(fmt, ...) {\
    fprintf(stderr, "[ERROR] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    continue;\
}

#define CONTINUE_WARN(fmt, ...) {\
    fprintf(stderr, "[WARN] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    continue;\
}

#define GOTO_ERROR(state, fmt, ...) {\
    fprintf(stderr, "[ERROR] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    goto state;\
}
