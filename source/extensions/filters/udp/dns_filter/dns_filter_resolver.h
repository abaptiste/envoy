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

enum class DnsFilterResolverStatus { Pending, Complete, Timeout };

class DnsFilterResolver : Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilterResolver(Network::DnsResolverSharedPtr resolver, const std::chrono::milliseconds timeout,
                    Event::Dispatcher& dispatcher)
      : resolver_(resolver), resolve_timeout_ms_(timeout), dispatcher_(dispatcher) {

    resolver_timer_ = dispatcher_.createTimer([this]() -> void { onResolveTimeout(); });
  }

  virtual ~DnsFilterResolver(){};
  virtual void resolve_query(const DnsQueryRecordPtr& domain, absl::Notification* notifier);
  virtual AddressConstPtrVec& get_resolved_hosts() { return resolved_hosts_; }
  virtual DnsFilterResolverStatus& get_resolution_status() { return resolution_status_; };

private:
  void onResolveTimeout() {
    ENVOY_LOG(debug, "Resolution timeout");
    resolution_status_ = DnsFilterResolverStatus::Timeout;
    notify();
  }

  void notify() {
    if (notifier_) {
      notifier_->Notify();
    }
  }

  const Network::DnsResolverSharedPtr resolver_;
  const std::chrono::milliseconds resolve_timeout_ms_;
  Event::TimerPtr resolver_timer_;

  Event::Dispatcher& dispatcher_;
  DnsFilterResolverStatus resolution_status_;
  AddressConstPtrVec resolved_hosts_;
  absl::Notification* notifier_;
};

using DnsFilterResolverPtr = std::unique_ptr<DnsFilterResolver>;

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
