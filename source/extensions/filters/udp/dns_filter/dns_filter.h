#pragma once

#include "envoy/config/filter/udp/dns_filter/v2alpha/dns_filter.pb.h"
#include "envoy/event/file_event.h"
#include "envoy/event/timer.h"
#include "envoy/network/filter.h"
#include "envoy/upstream/cluster_manager.h"

#include "common/buffer/buffer_impl.h"
#include "common/config/config_provider_impl.h"
#include "common/network/utility.h"
#include "common/runtime/runtime_impl.h"

#include "extensions/filters/udp/dns_filter/dns_filter_resolver.h"
#include "extensions/filters/udp/dns_filter/dns_parser.h"

#include "absl/container/flat_hash_set.h"
#include "absl/synchronization/notification.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

/**
 * All Dns Filter stats. @see stats_macros.h
 * Track the number of answered and un-answered queries for A and AAAA records
 */
#define ALL_DNS_FILTER_STATS(COUNTER)                                                              \
  COUNTER(queries_a_record)                                                                        \
  COUNTER(noanswers_a_record)                                                                      \
  COUNTER(answers_a_record)                                                                        \
  COUNTER(queries_aaaa_record)                                                                     \
  COUNTER(noanswers_aaaa_record)                                                                   \
  COUNTER(answers_aaaa_record)

/**
 * Struct definition for all Dns Filter stats. @see stats_macros.h
 */
struct DnsFilterStats {
  ALL_DNS_FILTER_STATS(GENERATE_COUNTER_STRUCT)
};

using AddressConstPtrVec = std::vector<Network::Address::InstanceConstSharedPtr>;
using DnsVirtualDomainConfig = absl::flat_hash_map<std::string, AddressConstPtrVec>;

class DnsFilterEnvoyConfig {
public:
  DnsFilterEnvoyConfig(
      Server::Configuration::ListenerFactoryContext& context,
      const envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig& config);

  DnsFilterStats& stats() const { return stats_; }
  DnsVirtualDomainConfig& domains() const { return virtual_domains_; }
  absl::flat_hash_set<std::string>& known_domains() const { return known_domains_; }
  AddressConstPtrVec& resolvers() const { return resolvers_; }
  bool forward_queries() const { return forward_queries_; }
  std::chrono::milliseconds& resolver_timeout() const { return resolver_timeout_ms_; }

private:
  static DnsFilterStats generateStats(const std::string& stat_prefix, Stats::Scope& scope) {
    const auto final_prefix = absl::StrCat("dns_filter.", stat_prefix);
    return {ALL_DNS_FILTER_STATS(POOL_COUNTER_PREFIX(scope, final_prefix))};
  }

  Stats::Scope& root_scope;
  Upstream::ClusterManager& cluster_manager_;

  mutable DnsFilterStats stats_;
  mutable DnsVirtualDomainConfig virtual_domains_;
  mutable absl::flat_hash_set<std::string> known_domains_;
  bool forward_queries_;
  mutable AddressConstPtrVec resolvers_;
  Network::DnsResolverSharedPtr resolver_;
  mutable std::chrono::milliseconds resolver_timeout_ms_;
};

using DnsFilterEnvoyConfigSharedPtr = std::shared_ptr<const DnsFilterEnvoyConfig>;

class DnsFilter : public Network::UdpListenerReadFilter, Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilter(Network::UdpReadFilterCallbacks& callbacks,
            const DnsFilterEnvoyConfigSharedPtr& config);

  // Network::UdpListenerReadFilter callbacks
  void onData(Network::UdpRecvData& client_request) override;
  void onReceiveError(Api::IoError::IoErrorCode error_code) override;

  absl::optional<std::string> isKnownDomain(const std::string& domain_name);

private:
  virtual void sendDnsResponse(const Network::UdpRecvData& request_data);
  virtual DnsAnswerRecordPtr getResponseForQuery();

  const DnsFilterEnvoyConfigSharedPtr config_;

  DnsMessageParserPtr message_parser_;

  Network::UdpListener& listener_;
  Runtime::RandomGeneratorImpl rng_;
  DnsAnswerRecordPtr answer_rec_;
  DnsFilterResolverPtr resolver_;
  // Network::DnsResolverSharedPtr resolver_;
};

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
