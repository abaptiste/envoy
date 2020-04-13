#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/event/dispatcher.h"
#include "envoy/network/dns.h"

#include "common/buffer/buffer_impl.h"
#include "common/runtime/runtime_impl.h"

#include "extensions/filters/udp/dns_filter/dns_parser.h"

#include "absl/synchronization/notification.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

enum class DnsFilterResolverStatus { Pending, Complete, TimedOut };

/*
 * This class encapsulates the logic of handling an asynchronous DNS request for the DNS filter.
 * External request timeouts are handled here.
 */
class DnsFilterResolver : Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilterResolver(AnswerCallback& callback, AddressConstPtrVec resolvers,
                    std::chrono::milliseconds timeout, Event::Dispatcher& dispatcher)
      : resolver_(dispatcher.createDnsResolver(resolvers, false /* use_tcp_for_dns_lookups */)),
        callback_(callback), timeout_(timeout),
        resolver_timer_(dispatcher.createTimer([this]() -> void { onResolveTimeout(); })),
        active_query_(nullptr) {}

  ~DnsFilterResolver() = default;

  /**
   * @brief entry point to resolve the name in a DnsQueryRecord
   *
   * This function uses the query object to determine whether it is requesting an A or AAAA record
   * for the given name. When the resolver callback executes, this will execute a DNS Filter
   * callback in order to build the answer object returned to the client.
   *
   * @param domain_query the query record object containing the name for which we are resolving
   */
  void resolve_query(DnsQueryContextPtr context, const DnsQueryRecordPtr& domain_query);

private:
  /**
   * @brief invokes the DNS Filter callback only if our state indicates we have not timed out
   * waiting for a response from the external resolver
   */
  void invokeCallback() {
    // We've timed out. Guard against sending a response
    if (resolution_status_ == DnsFilterResolverStatus::TimedOut) {
      return;
    }
    resolver_timer_->disableTimer();
    callback_(std::move(external_context_), query_rec_, resolved_hosts_);
  }

  /**
   * Invoke the DNS Filter callback after explicitly clearing the resolved hosts list. The filter
   * will respond appropriately.
   */
  void onResolveTimeout() {
    // If the resolution status is not Pending, then we've already completed the lookup and
    // responded to the client.
    if (resolution_status_ != DnsFilterResolverStatus::Pending) {
      return;
    }
    resolution_status_ = DnsFilterResolverStatus::TimedOut;
    resolved_hosts_.clear();
    callback_(std::move(external_context_), query_rec_, resolved_hosts_);
  }

  const Network::DnsResolverSharedPtr resolver_;

  AnswerCallback& callback_;
  std::chrono::milliseconds timeout_;
  Event::TimerPtr resolver_timer_;

  const DnsQueryRecord* query_rec_;
  Network::ActiveDnsQuery* active_query_;

  Runtime::RandomGeneratorImpl rng_;
  DnsFilterResolverStatus resolution_status_;
  AddressConstPtrVec resolved_hosts_;

  DnsQueryContextPtr external_context_;
};

using DnsFilterResolverPtr = std::unique_ptr<DnsFilterResolver>;

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
