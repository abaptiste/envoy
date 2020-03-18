#include "extensions/filters/udp/dns_filter/dns_filter_resolver.h"

#include "common/network/utility.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

void DnsFilterResolver::resolve_query(const DnsQueryRecordPtr& domain) {

  // TODO: How do we handle timeouts

  resolved_hosts_.clear();

  Network::DnsLookupFamily lookup_family;
  switch (domain->type_) {
  case DnsRecordType::A:
    lookup_family = Network::DnsLookupFamily::V4Only;
    break;
  case DnsRecordType::AAAA:
    lookup_family = Network::DnsLookupFamily::V6Only;
    break;
  default:
    ENVOY_LOG(error, "Unknown query type [{}] for upstream lookup", domain->type_);
    return;
  }

  // Resolve the address in the query and addd to the resolved_hosts vector
  resolver_->resolve(domain->name_, lookup_family,
                     [this](Network::DnsResolver::ResolutionStatus status,
                            std::list<Network::DnsResponse>&& response) -> void {
                       // ENVOY_LOG(trace, "async query for name {}", domain->name_);

                       // TODO: Cache returned addresses until TTL expires
                       if (status == Network::DnsResolver::ResolutionStatus::Success) {
                         resolved_hosts_.reserve(response.size());
                         for (const auto& resp : response) {
                           ASSERT(resp.address_ != nullptr);
                           // ENVOY_LOG(trace, "address {} returned for name {}", resp.address_,
                           //          domain->name_);
                           resolved_hosts_.push_back(
                               Network::Utility::getAddressWithPort(*(resp.address_), 0));
                         }
                       }
                     });
}

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
