#include "extensions/filters/udp/dns_filter/dns_filter_resolver.h"

#include "common/network/utility.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

void DnsFilterResolver::resolve_query(const DnsQueryRecordPtr& domain){

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

  ENVOY_LOG(trace, "Resolving name [{}]", domain->name_);

  resolution_status_ = DnsFilterResolverStatus::Pending;
  resolver_timer_->disableTimer();
  resolver_timer_->enableTimer(resolve_timeout_ms_);

  // Resolve the address in the query and add to the resolved_hosts vector
  resolver_->resolve(
      domain->name_, lookup_family,
      [this](Network::DnsResolver::ResolutionStatus status,
             std::list<Network::DnsResponse>&& response) -> void {
        if (resolution_status_ != DnsFilterResolverStatus::Pending) {
          ENVOY_LOG(debug, "Resolution timed out before callback was executed");
          return;
        }

        ENVOY_LOG(trace, "async query status returned. Entries {}", response.size());

        // TODO: Cache returned addresses until TTL expires
        if (status == Network::DnsResolver::ResolutionStatus::Success) {
          resolved_hosts_.reserve(response.size());
          for (const auto& resp : response) {
            ASSERT(resp.address_ != nullptr);
            ENVOY_LOG(trace, "Received address: {}", resp.address_->ip()->addressAsString());
            resolved_hosts_.push_back(Network::Utility::getAddressWithPort(*(resp.address_), 0));

            resolution_status_ = DnsFilterResolverStatus::Complete;
          }
        }
      });
}

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
