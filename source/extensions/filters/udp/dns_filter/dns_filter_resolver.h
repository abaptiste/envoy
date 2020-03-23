#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/event/dispatcher.h"
#include "envoy/network/dns.h"

#include "common/buffer/buffer_impl.h"

#include "extensions/filters/udp/dns_filter/dns_parser.h"

#include "absl/synchronization/notification.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

using AddressConstPtrVec = std::vector<Network::Address::InstanceConstSharedPtr>;

enum class DnsFilterResolverStatus { Pending, Complete };

class DnsFilterResolver : Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilterResolver(Network::DnsResolverSharedPtr resolver)
      : resolver_(resolver), active_query_(nullptr) {}

  virtual ~DnsFilterResolver(){};
  virtual void resolve_query(const DnsQueryRecordPtr& domain);
  virtual AddressConstPtrVec& get_resolved_hosts() { return resolved_hosts_; }
  virtual DnsFilterResolverStatus& get_resolution_status() { return resolution_status_; };

private:
  const Network::DnsResolverSharedPtr resolver_;
  Network::ActiveDnsQuery* active_query_;

  DnsFilterResolverStatus resolution_status_;
  AddressConstPtrVec resolved_hosts_;
};

using DnsFilterResolverPtr = std::unique_ptr<DnsFilterResolver>;

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
