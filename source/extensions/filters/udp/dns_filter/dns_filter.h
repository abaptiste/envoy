#pragma once

#include "envoy/config/filter/udp/dns_filter/v2alpha/dns_filter.pb.h"
#include "envoy/event/file_event.h"
#include "envoy/network/filter.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/matchers.h"
#include "common/config/config_provider_impl.h"
#include "common/network/utility.h"

#include "extensions/filters/udp/dns_filter/dns_parser.h"

#include "absl/container/flat_hash_set.h"

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

using DnsVirtualDomainConfig = absl::flat_hash_map<std::string, AddressConstPtrVec>;

/**
 * DnsFilter configuration class abstracting access to data necessary for the filter's operation
 */
class DnsFilterEnvoyConfig {
public:
  DnsFilterEnvoyConfig(
      Server::Configuration::ListenerFactoryContext& context,
      const envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig& config);

  DnsFilterStats& stats() const { return stats_; }
  DnsVirtualDomainConfig& domains() const { return virtual_domains_; }
  std::list<Matchers::StringMatcherPtr>& known_suffixes() const { return known_suffixes_; }
  absl::flat_hash_map<std::string, uint64_t>& domain_ttl() const { return domain_ttl_; }
  AddressConstPtrVec& resolvers() const { return resolvers_; }
  bool forward_queries() const { return forward_queries_; }
  std::chrono::milliseconds& resolver_timeout() const { return resolver_timeout_ms_; }

  static constexpr uint64_t DefaultResolverTimeoutMs = 500;
  static constexpr uint64_t DefaultResolverTTLs = 300;

private:
  static DnsFilterStats generateStats(const std::string& stat_prefix, Stats::Scope& scope) {
    const auto final_prefix = absl::StrCat("dns_filter.", stat_prefix);
    return {ALL_DNS_FILTER_STATS(POOL_COUNTER_PREFIX(scope, final_prefix))};
  }

  Stats::Scope& root_scope;

  mutable DnsFilterStats stats_;
  mutable DnsVirtualDomainConfig virtual_domains_;
  mutable std::list<Matchers::StringMatcherPtr> known_suffixes_;
  mutable absl::flat_hash_map<std::string, uint64_t> domain_ttl_;
  bool forward_queries_;
  mutable AddressConstPtrVec resolvers_;
  mutable std::chrono::milliseconds resolver_timeout_ms_;
};

using DnsFilterEnvoyConfigSharedPtr = std::shared_ptr<const DnsFilterEnvoyConfig>;

enum class DnsLookupResponseCode { Success, Failure, External };

/**
 * This class is responsible for handling incoming DNS datagrams and responding to the queries.
 * The filter will attempt to resolve the query via its configuration or direct to an external
 * resolver when necessary
 */
class DnsFilter : public Network::UdpListenerReadFilter, Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilter(Network::UdpReadFilterCallbacks& callbacks, const DnsFilterEnvoyConfigSharedPtr& config)
      : UdpListenerReadFilter(callbacks), config_(config), listener_(callbacks.udpListener()),
        message_parser_(std::make_unique<DnsMessageParser>()) {}

  // Network::UdpListenerReadFilter callbacks
  void onData(Network::UdpRecvData& client_request) override;
  void onReceiveError(Api::IoError::IoErrorCode) override;

  /**
   * @return bool true if the domain_name is a known domain for which we respond to queries
   */
  bool isKnownDomain(const absl::string_view domain_name);

private:
  /**
   * Prepare the response buffer and send it to the client
   */
  virtual void sendDnsResponse();

  /**
   * @brief Encapsulates all of the logic required to find an answer for a DNS query
   *
   * @return DnsLookupResponseCode indicating whether we were able to respond to the query or send
   * the query to an external resolver
   */
  virtual DnsLookupResponseCode getResponseForQuery();

  /**
   * @return uint32_t retrieves the configured per domain TTL to be inserted into answer records
   */
  uint32_t getDomainTTL(const absl::string_view domain);

  /**
   * Resolves the supplied query from configured hosts
   * @param query query object containing the name to be resolved
   * @return bool true if the requested name matches a configured domain and answer records can be
   * constructed
   */
  bool resolveViaConfiguredHosts(const DnsQueryRecord& query);

  const DnsFilterEnvoyConfigSharedPtr config_;
  Network::UdpListener& listener_;

  DnsMessageParserPtr message_parser_;

  Network::Address::InstanceConstSharedPtr local_;
  Network::Address::InstanceConstSharedPtr peer_;
  Buffer::OwnedImpl response_;

  AnswerCallback answer_callback_;
};

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
