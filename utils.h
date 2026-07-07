#include <netinet/in.h>
#include <string>
#include <string_view>
#include <type_traits>
namespace utility {

constexpr std::string_view Deny  = "Deny";
constexpr std::string_view Allow = "Allow";
constexpr std::string_view Alert = "Alert";

template <typename T>
inline std::string_view actionString(T action) {
  switch (static_cast<int>(action)) {
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

template <typename T>
inline std::string_view directionString(T direction) {
  switch (static_cast<int>(direction)) {
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