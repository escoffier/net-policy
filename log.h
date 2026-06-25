#pragma once

extern int gzLogLevel;

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
    if(gzLogLevel > 0) fprintf(stderr, "[DEBUG] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_V(fmt, ...) {\
    if(gzLogLevel > 1) fprintf(stderr, "[VERBOSE] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_T(fmt, ...) {\
    if(gzLogLevel > 2) fprintf(stderr, "[TRACE] [%s] [line:%d] [%s] [policy] " fmt "\n", TimeToString().c_str(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
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
