#pragma once

#include "extensions/filters/udp/dns_filter/dns_parser.h"

#include "envoy/event/dispatcher.h"
#include "envoy/buffer/buffer.h"
#include "envoy/network/dns.h"

#include "common/buffer/buffer_impl.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

using AddressConstPtrVec = std::vector<Network::Address::InstanceConstSharedPtr>;

class DnsFilterResolver : Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilterResolver(Network::DnsResolverSharedPtr resolver)
    :resolver_(resolver) {};
#if 0
                    Event::Dispatcher& dispatcher,
                    std::vector<Network::Address::InstanceConstSharedPtr>& resolvers)
      : resolver_(dispatcher.createDnsResolver(resolvers, false /* use tcp for dns lookups */)){};
#endif

  virtual ~DnsFilterResolver(){};

  virtual void resolve_query(const DnsQueryRecordPtr& domain);
  virtual AddressConstPtrVec& get_resolved_hosts() { return resolved_hosts_; }

private:
  const Network::DnsResolverSharedPtr resolver_;

  AddressConstPtrVec resolved_hosts_;
};

using DnsFilterResolverPtr = std::unique_ptr<DnsFilterResolver>;

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
