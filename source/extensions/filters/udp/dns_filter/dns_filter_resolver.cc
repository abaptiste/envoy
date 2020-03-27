#include "extensions/filters/udp/dns_filter/dns_filter_resolver.h"

#include "common/network/utility.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

void DnsFilterResolver::resolve_query(const DnsQueryRecordPtr& domain_query) {

  Network::DnsLookupFamily lookup_family;
  switch (domain_query->type_) {
  case DnsRecordType::A:
    lookup_family = Network::DnsLookupFamily::V4Only;
    break;
  case DnsRecordType::AAAA:
    lookup_family = Network::DnsLookupFamily::V6Only;
    break;
  default:
    ENVOY_LOG(error, "Unknown query type [{}] for upstream lookup", domain_query->type_);
    invokeCallback();
    return;
  }

  ENVOY_LOG(trace, "Resolving name [{}]", domain_query->name_);

  resolution_status_ = DnsFilterResolverStatus::Pending;

  if (active_query_ != nullptr) {
    active_query_->cancel();
  }

  query_rec_ = domain_query;

  // Re-arm the timeout timer
  resolver_timer_->disableTimer();
  resolver_timer_->enableTimer(timeout_);

  // Resolve the address in the query and add to the resolved_hosts vector
  resolved_hosts_.clear();
  active_query_ = resolver_->resolve(
      domain_query->name_, lookup_family,
      [this](Network::DnsResolver::ResolutionStatus status,
             std::list<Network::DnsResponse>&& response) -> void {
        active_query_ = nullptr;

        if (resolution_status_ != DnsFilterResolverStatus::Pending) {
          ENVOY_LOG(debug, "Resolution timed out before callback was executed");
          return;
        }

        ENVOY_LOG(trace, "async query status returned. Entries {}", response.size());

        // C-ares doesn't expose the TTL in the data available here.
        if (status == Network::DnsResolver::ResolutionStatus::Success) {
          for (const auto resp : response) {
            ASSERT(resp.address_ != nullptr);
            ENVOY_LOG(trace, "Received address: {}", resp.address_->ip()->addressAsString());
            resolved_hosts_.push_back(std::move(resp.address_));
          }
        }

        // We are processing the response, so we cannot timeout. Cancel the timer
        resolver_timer_->disableTimer();
        invokeCallback();
      });
}

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
