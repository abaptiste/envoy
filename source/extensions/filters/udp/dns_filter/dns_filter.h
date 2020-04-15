#pragma once

#include "envoy/event/file_event.h"
#include "envoy/extensions/filter/udp/dns_filter/v3alpha/dns_filter.pb.h"
#include "envoy/network/filter.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/matchers.h"
#include "common/config/config_provider_impl.h"
#include "common/network/utility.h"

#include "extensions/filters/udp/dns_filter/dns_filter_resolver.h"
#include "extensions/filters/udp/dns_filter/dns_parser.h"

#include "absl/container/flat_hash_set.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

/**
 * All DNS Filter stats. @see stats_macros.h
 */
#define ALL_DNS_FILTER_STATS(COUNTER, HISTOGRAM)                                                   \
  COUNTER(a_record_queries)                                                                        \
  COUNTER(aaaa_record_queries)                                                                     \
  COUNTER(cluster_a_record_answers)                                                                \
  COUNTER(cluster_aaaa_record_answers)                                                             \
  COUNTER(cluster_unsupported_answers)                                                             \
  COUNTER(downstream_rx_errors)                                                                    \
  COUNTER(downstream_rx_invalid_queries)                                                           \
  COUNTER(downstream_rx_queries)                                                                   \
  COUNTER(external_a_record_queries)                                                               \
  COUNTER(external_a_record_answers)                                                               \
  COUNTER(external_aaaa_record_answers)                                                            \
  COUNTER(external_aaaa_record_queries)                                                            \
  COUNTER(external_unsupported_answers)                                                            \
  COUNTER(external_unsupported_queries)                                                            \
  COUNTER(externally_resolved_queries)                                                             \
  COUNTER(known_domain_queries)                                                                    \
  COUNTER(local_a_record_answers)                                                                  \
  COUNTER(local_aaaa_record_answers)                                                               \
  COUNTER(local_unsupported_answers)                                                               \
  COUNTER(unanswered_queries)                                                                      \
  COUNTER(unsupported_queries)                                                                     \
  COUNTER(downstream_tx_responses)                                                                 \
  HISTOGRAM(downstream_rx_bytes, Bytes)                                                            \
  HISTOGRAM(downstream_rx_query_latency, Milliseconds)                                             \
  HISTOGRAM(downstream_tx_bytes, Bytes)

/**
 * Struct definition for all DNS Filter stats. @see stats_macros.h
 */
struct DnsFilterStats {
  ALL_DNS_FILTER_STATS(GENERATE_COUNTER_STRUCT, GENERATE_HISTOGRAM_STRUCT)
};

using DnsVirtualDomainConfig = absl::flat_hash_map<std::string, AddressConstPtrVec>;

/**
 * DnsFilter configuration class abstracting access to data necessary for the filter's operation
 */
class DnsFilterEnvoyConfig {
public:
  DnsFilterEnvoyConfig(
      Server::Configuration::ListenerFactoryContext& context,
      const envoy::extensions::filter::udp::dns_filter::v3alpha::DnsFilterConfig& config);

  DnsFilterStats& stats() const { return stats_; }
  const DnsVirtualDomainConfig& domains() const { return virtual_domains_; }
  const std::vector<Matchers::StringMatcherPtr>& knownSuffixes() const { return known_suffixes_; }
  const absl::flat_hash_map<std::string, uint64_t>& domainTtl() const { return domain_ttl_; }
  Upstream::ClusterManager& clusterManager() const { return cluster_manager_; }
  const AddressConstPtrVec& resolvers() const { return resolvers_; }
  bool forwardQueries() const { return forward_queries_; }
  std::chrono::milliseconds resolverTimeout() const { return resolver_timeout_ms_; }

  static constexpr uint64_t DefaultResolverTimeoutMs = 500;
  static constexpr uint64_t DefaultResolverTTLs = 300;

private:
  static DnsFilterStats generateStats(const std::string& stat_prefix, Stats::Scope& scope) {
    const auto final_prefix = absl::StrCat("dns_filter.", stat_prefix);
    return {ALL_DNS_FILTER_STATS(POOL_COUNTER_PREFIX(scope, final_prefix),
                                 POOL_HISTOGRAM_PREFIX(scope, final_prefix))};
  }

  bool loadServerConfig(const envoy::extensions::filter::udp::dns_filter::v3alpha::DnsFilterConfig::
                            ServerContextConfig& config,
                        envoy::data::dns::v3::DnsTable& table);

  Stats::Scope& root_scope_;
  Upstream::ClusterManager& cluster_manager_;
  Network::DnsResolverSharedPtr resolver_;
  Api::Api& api_;

  mutable DnsFilterStats stats_;
  DnsVirtualDomainConfig virtual_domains_;
  std::vector<Matchers::StringMatcherPtr> known_suffixes_;
  absl::flat_hash_map<std::string, uint64_t> domain_ttl_;
  bool forward_queries_;
  AddressConstPtrVec resolvers_;
  std::chrono::milliseconds resolver_timeout_ms_;
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
  DnsFilter(Network::UdpReadFilterCallbacks& callbacks,
            const DnsFilterEnvoyConfigSharedPtr& config);

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
  void sendDnsResponse(DnsQueryContextPtr context);

  /**
   * @brief Encapsulates all of the logic required to find an answer for a DNS query
   *
   * @return DnsLookupResponseCode indicating whether we were able to respond to the query or send
   * the query to an external resolver
   */
  DnsLookupResponseCode getResponseForQuery(DnsQueryContextPtr& context);

  /**
   * @return uint32_t retrieves the configured per domain TTL to be inserted into answer records
   */
  uint32_t getDomainTTL(const absl::string_view domain);

  /**
   * @brief Resolves the supplied query from configured clusters
   *
   * @param query query object containing the name to be resolved
   * @return bool true if the requested name matched a cluster and an answer record was constructed
   */
  bool resolveViaClusters(DnsQueryContextPtr& context, const DnsQueryRecord& query);

  /**
   * @brief Resolves the supplied query from configured hosts
   *
   * @param query query object containing the name to be resolved
   * @return bool true if the requested name matches a configured domain and answer records can be
   * constructed
   */
  bool resolveViaConfiguredHosts(DnsQueryContextPtr& context, const DnsQueryRecord& query);

  /**
   * @brief Increment the counter for the given query type for external queries
   *
   * @param query_type indicate the type of record being resolved (A, AAAA, or other).
   */
  void incrementExternalQueryTypeCount(const uint16_t query_type) {
    switch (query_type) {
    case DnsRecordType::A:
      config_->stats().external_a_record_queries_.inc();
      break;
    case DnsRecordType::AAAA:
      config_->stats().external_aaaa_record_queries_.inc();
      break;
    default:
      config_->stats().external_unsupported_queries_.inc();
      break;
    }
  }

  /**
   * @brief Increment the counter for the parsed query type
   *
   * @param queries a vector of all the incoming queries received from a client
   */
  void incrementQueryTypeCount(const DnsQueryPtrVec& queries) {
    for (const auto& query : queries) {
      incrementQueryTypeCount(query->type_);
    }
  }

  /**
   * @brief Increment the counter for the given query type.
   *
   * @param query_type indicate the type of record being resolved (A, AAAA, or other).
   */
  void incrementQueryTypeCount(const uint16_t query_type) {
    switch (query_type) {
    case DnsRecordType::A:
      config_->stats().a_record_queries_.inc();
      break;
    case DnsRecordType::AAAA:
      config_->stats().aaaa_record_queries_.inc();
      break;
    default:
      config_->stats().unsupported_queries_.inc();
      break;
    }
  }

  /**
   * @brief Increment the counter for answers for the given query type resolved via cluster names
   *
   * @param query_type indicate the type of answer record returned to the client
   */
  void incrementClusterQueryTypeAnswerCount(const uint16_t query_type) {
    switch (query_type) {
    case DnsRecordType::A:
      config_->stats().cluster_a_record_answers_.inc();
      break;
    case DnsRecordType::AAAA:
      config_->stats().cluster_aaaa_record_answers_.inc();
      break;
    default:
      config_->stats().cluster_unsupported_answers_.inc();
      break;
    }
  }

  /**
   * @brief Increment the counter for answers for the given query type resolved from the local
   * configuration.
   *
   * @param query_type indicate the type of answer record returned to the client
   */
  void incrementLocalQueryTypeAnswerCount(const uint16_t query_type) {
    switch (query_type) {
    case DnsRecordType::A:
      config_->stats().local_a_record_answers_.inc();
      break;
    case DnsRecordType::AAAA:
      config_->stats().local_aaaa_record_answers_.inc();
      break;
    default:
      config_->stats().local_unsupported_answers_.inc();
      break;
    }
  }

  /**
   * @brief Increment the counter for answers for the given query type resolved via an external
   * resolver
   *
   * @param query_type indicate the type of answer record returned to the client
   */
  void incrementExternalQueryTypeAnswerCount(const uint16_t query_type) {
    switch (query_type) {
    case DnsRecordType::A:
      config_->stats().external_a_record_answers_.inc();
      break;
    case DnsRecordType::AAAA:
      config_->stats().external_aaaa_record_answers_.inc();
      break;
    default:
      config_->stats().external_unsupported_answers_.inc();
      break;
    }
  }

  const DnsFilterEnvoyConfigSharedPtr config_;
  Network::UdpListener& listener_;

  Upstream::ClusterManager& cluster_manager_;

  DnsMessageParserPtr message_parser_;
  DnsFilterResolverPtr resolver_;

  Network::Address::InstanceConstSharedPtr local_;
  Network::Address::InstanceConstSharedPtr peer_;

  AnswerCallback answer_callback_;
};

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
