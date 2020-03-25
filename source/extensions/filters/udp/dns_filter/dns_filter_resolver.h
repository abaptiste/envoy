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

using AddressConstPtrVec = std::vector<Network::Address::InstanceConstSharedPtr>;

enum class DnsFilterResolverStatus { Pending, Complete, TimedOut };

class DnsFilterResolver : Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilterResolver(AnswerCallback& callback, AddressConstPtrVec resolvers,
                    std::chrono::milliseconds& timeout, Event::Dispatcher& dispatcher)
      : resolver_(dispatcher.createDnsResolver(resolvers, false /* use tcp for lookups */)),
        callback_(callback), timeout_(timeout),
        resolver_timer_(dispatcher.createTimer([this]() -> void { onResolveTimeout(); })),
        active_query_(nullptr) {}

  virtual ~DnsFilterResolver(){};
  virtual void resolve_query(const DnsQueryRecordPtr& domain_query);
  // virtual AddressConstPtrVec& get_resolved_hosts() { return resolved_hosts_; }
  // virtual DnsFilterResolverStatus& get_resolution_status() { return resolution_status_; };

private:
  void invokeCallback(Network::Address::InstanceConstSharedPtr address) {
    // We've timed out. Guard against sending a response
    if (resolution_status_ == DnsFilterResolverStatus::TimedOut) {
      return;
    }
    resolver_timer_->disableTimer();
    callback_(query_rec_, address);
  }

  void onResolveTimeout() {
    // If the resolution status is not Pending, we've already completed
    // the lookup and responded to the client
    if (resolution_status_ != DnsFilterResolverStatus::Pending) {
      return;
    }
    resolution_status_ = DnsFilterResolverStatus::TimedOut;
    callback_(query_rec_, nullptr);
  }

  const Network::DnsResolverSharedPtr resolver_;
  AnswerCallback& callback_;
  std::chrono::milliseconds timeout_;
  Event::TimerPtr resolver_timer_;

  DnsQueryRecordPtr query_rec_;
  Network::ActiveDnsQuery* active_query_;

  Runtime::RandomGeneratorImpl rng_;
  DnsFilterResolverStatus resolution_status_;
  AddressConstPtrVec resolved_hosts_;
};

using DnsFilterResolverPtr = std::unique_ptr<DnsFilterResolver>;

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
