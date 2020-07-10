#include "extensions/filters/udp/dns_filter/dns_filter_utils.h"

#include <algorithm>

#include "envoy/common/platform.h"

#include "common/common/empty_string.h"
#include "common/common/logger.h"
#include "common/network/address_impl.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {
namespace Utils {

std::string getProtoName(const DnsTable::DnsServiceProtocol& protocol) {
  std::string proto = protocol.name();
  if (proto.empty()) {
    switch (protocol.number()) {
    case 6:
      proto = "tcp";
      break;
    case 17:
      proto = "udp";
      break;
    default: {
      struct protoent* pe = getprotobynumber(protocol.number());
      if (pe == nullptr) {
        ENVOY_LOG_MISC(debug, "Unable to determine name for protocol number [{}]",
                       protocol.number());
        return EMPTY_STRING;
      }
      proto = std::string(pe->p_name);
    }
    } // end switch
  }
  return proto;
}

} // namespace Utils
} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
