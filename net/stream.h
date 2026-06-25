#pragma once

#include <cstdint>
#include <string>

namespace net {
struct ConnectionInfo {
     std::string from;
     std::string to;
     uint16_t sourcePort;
     uint16_t destPort;
};
}