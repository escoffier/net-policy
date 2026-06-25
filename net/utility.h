#pragma once

#include "net/filter.h"
#include <cstdint>
#include <string>

namespace net {
std::string ipv4ToString(uint32_t ip);

enum class NetStatus {
    OK,
    Drop
};

struct NetworkStat {
    uint64_t tcp_conn_;
};

}