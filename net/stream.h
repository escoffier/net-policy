#pragma once

#include <cstdint>
#include <string>

namespace net {
struct ConnectionInfo {
     std::string from_;
     std::string to_;
     uint16_t source_port_;
     uint16_t dest_port_;
};
}