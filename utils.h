#include <netinet/in.h>
#include <string>
#include <string_view>
namespace utility {

constexpr std::string_view Deny  = "Deny";
constexpr std::string_view Allow = "Allow";
constexpr std::string_view Alert = "Alert";

inline std::string_view actionString(int action) {
  switch (action) {
  case 0:
    return Deny;
  case 1:
    return Allow;
  case 2:
    return Alert;
  default:
    return "Unknown";
  };
};

inline std::string_view directionString(int direction) {
  switch (direction) {
  case 0:
    return "ingress";
  case 1:
    return "egress";
  default:
    return "unknown";
  }
}

inline std::string_view protocolString(int protocol) {
  switch (protocol) {
  case IPPROTO_TCP:
    return "TCP";
  case IPPROTO_UDP:
    return "UDP";
  case IPPROTO_ICMP:
    return "ICMP";
  default:
    return "";
  }
}
} // namespace utility