#pragma once

#include "envoy/extensions/filters/udp/dns_filter/v3alpha/dns_filter.pb.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {
namespace Utils {

constexpr size_t MAX_LABEL_LENGTH = 63;
constexpr size_t MAX_NAME_LENGTH = 255;

using envoy::data::dns::v3::DnsTable;

std::string getProtoName(const DnsTable::DnsServiceProtocol& protocol);
char* getStringPointer(std::string* data, size_t data_length);

} // namespace Utils
} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
