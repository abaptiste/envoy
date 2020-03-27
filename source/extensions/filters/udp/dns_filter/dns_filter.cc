#include "extensions/filters/udp/dns_filter/dns_filter.h"

#include "envoy/network/listener.h"
#include "envoy/type/matcher/v3/string.pb.h"

#include "common/common/empty_string.h"
#include "common/network/address_impl.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

DnsFilterEnvoyConfig::DnsFilterEnvoyConfig(
    Server::Configuration::ListenerFactoryContext& context,
    const envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig& config)
    : root_scope(context.scope()), cluster_manager_(context.clusterManager()),
      stats_(generateStats(config.stat_prefix(), root_scope)) {

  using envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig;

  const auto& server_config = config.server_config();

  // TODO: Read the external DataSource
  if (server_config.has_inline_dns_table()) {

    const auto& dns_table = server_config.inline_dns_table();
    const size_t entries = dns_table.virtual_domains().size();

    // TODO: support wildcard matching to eventually eliminate having two sets of domains
    virtual_domains_.reserve(entries);
    for (const auto& virtual_domain : dns_table.virtual_domains()) {
      AddressConstPtrVec addrs{};

      if (virtual_domain.endpoint().has_address_list()) {
        const auto& address_list = virtual_domain.endpoint().address_list().address();
        addrs.reserve(address_list.size());
        // This will throw an exception if the configured_address string is malformed
        for (const auto& configured_address : address_list) {
          const auto ipaddr = Network::Utility::parseInternetAddress(configured_address, 0, true);
          addrs.push_back(ipaddr);
        }
      }
      virtual_domains_.emplace(virtual_domain.name(), std::move(addrs));
    }

    // Add known domains
    for (const auto& suffix : dns_table.known_suffixes()) {
      // TODO: We support only suffixes here. Expand this to support other StringMatcher types
      envoy::type::matcher::v3::StringMatcher matcher;
      matcher.set_suffix(suffix.suffix());
      auto matcher_ptr = std::make_unique<Matchers::StringMatcherImpl>(matcher);
      known_suffixes_.push_back(std::move(matcher_ptr));
    }
  }

  const auto& client_config = config.client_config();
  forward_queries_ = client_config.forward_query();
  if (forward_queries_) {
    const auto& upstream_resolvers = client_config.upstream_resolvers();
    resolvers_.reserve(upstream_resolvers.size());
    for (const auto& resolver : upstream_resolvers) {
      const auto ipaddr = Network::Utility::parseInternetAddress(resolver, 0, true);
      resolvers_.push_back(std::move(ipaddr));
    }
  }

  static constexpr uint64_t DefaultResolverTimeoutMs = 500;
  resolver_timeout_ms_ = std::chrono::milliseconds(
      PROTOBUF_GET_MS_OR_DEFAULT(client_config, resolver_timeout, DefaultResolverTimeoutMs));
}

DnsFilter::DnsFilter(Network::UdpReadFilterCallbacks& callbacks,
                     const DnsFilterEnvoyConfigSharedPtr& config)
    : UdpListenerReadFilter(callbacks), config_(config),
      cluster_manager_(config_->cluster_manager()), listener_(callbacks.udpListener())

{
  message_parser_ = std::make_unique<DnsMessageParser>();

  // TODO retries, TTL.

  // This callback is executed when the dns resolution completes. At that time
  // we build an answer record from each IP resolved, then send it to the client
  answer_callback_ = [this](DnsQueryRecordPtr& query, AddressConstPtrVec& iplist) -> void {
    for (const auto& ip : iplist) {
      message_parser_->buildDnsAnswerRecord(query, 300, std::move(ip));
    }
    sendDnsResponse();
  };

  resolver_ = std::make_unique<DnsFilterResolver>(
      answer_callback_, config->resolvers(), config->resolver_timeout(), listener_.dispatcher());
}

bool DnsFilter::isKnownDomain(const absl::string_view domain_name) {

  const auto& known_suffixes = config_->known_suffixes();

  // If we don't have a list of whitelisted domain suffixes, we will immediately
  // resolve the name with an upstream DNS server
  if (known_suffixes.empty()) {
    ENVOY_LOG(trace, "Known domains list is empty");
    return false;
  }

  // TODO: Use a trie to find match instead of iterating through the list
  for (auto& suffix : known_suffixes) {
    if (suffix->match(domain_name)) {
      return true;
    }
  }

  return false;
}

void DnsFilter::onData(Network::UdpRecvData& client_request) {

  // Save the connection endpoints so that we can respond
  local_ = client_request.addresses_.local_;
  peer_ = client_request.addresses_.peer_;

  // Parse the query
  message_parser_->parseDnsObject(client_request.buffer_);

  // Resolve the requested name
  auto response = getResponseForQuery();

  // We were not able to satisfy the request locally. Return an
  // empty response to the client
  if (response == DnsLookupResponse::Failure) {
    sendDnsResponse();
    return;
  }

  // Externally resolved. We'll respond to the client when the
  // external DNS resolution callback returns
  if (response == DnsLookupResponse::External) {
    return;
  }

  // We have an answer. Send it to the client
  sendDnsResponse();
}

DnsLookupResponse DnsFilter::getResponseForQuery() {

  Network::Address::InstanceConstSharedPtr ipaddr = nullptr;
  const auto& queries = message_parser_->getQueries();

  // It appears to be a rare case where we would have more than one query in a single request. It is
  // allowed by the protocol but not widely supported:
  //
  // https://stackoverflow.com/a/4083071

  const auto& domains = config_->domains();

  // TODO: Do we assert that there is only one query here?
  for (const auto& query : queries) {

    // Try to resolve the query locally. If forwarding the query externally is disabled we will
    // always attempt to resolve with the configured domains
    if (isKnownDomain(query->name_) || !config_->forward_queries()) {

      // Ref source/extensions/filters/network/redis_proxy/conn_pool_impl.cc

      // Determine whether the name is a cluster
      Upstream::ThreadLocalCluster* cluster = cluster_manager_.get(query->name_);
      if (cluster != nullptr) {

        for (const auto& i : cluster->prioritySet().hostSetsPerPriority()) {
          for (auto& host : i->hosts()) {
            message_parser_->buildDnsAnswerRecord(query, 300, host->address());
          }
        }
        continue;
      }

      // TODO: If we have a large ( > 100) domain list, use a binary search.
      const auto iter = domains.find(query->name_);
      if (iter == domains.end()) {
        ENVOY_LOG(debug, "Domain [{}] is not a configured entry", query->name_);
        continue;
      }

      const auto& configured_address_list = iter->second;
      if (configured_address_list.empty()) {
        ENVOY_LOG(debug, "Domain [{}] list is empty", query->name_);
        continue;
      }

      // Build the answer records from each IP address we have
      for (const auto& configured_address : configured_address_list) {
        ASSERT(configured_address != nullptr);
        ENVOY_LOG(debug, "using address {} for domain [{}]",
                  configured_address->ip()->addressAsString(), query->name_);
        message_parser_->buildDnsAnswerRecord(query, 300, configured_address);
      }

      return DnsLookupResponse::Success;
    }
    // We don't have a statically configured record for the domain or it's unknown resolve it
    // externally
    if (ipaddr == nullptr) {
      ENVOY_LOG(debug, "Domain [{}] is not known", query->name_);

      // When the callback executes it will execute a callback to build a response and send it to
      // the client
      resolver_->resolve_query(query);

      return DnsLookupResponse::External;
    }
  }

  // No address found. Response to the client appropriately
  return DnsLookupResponse::Failure;
}

void DnsFilter::sendDnsResponse() {

  // Clear any cruft in the outgoing buffer
  response_.drain(response_.length());

  if (!message_parser_->buildResponseBuffer(response_)) {
    ENVOY_LOG(error, "Unable to build a response for the client");
  }

  Network::UdpSendData response_data{local_->ip(), *peer_, response_};
  listener_.send(response_data);
}

void DnsFilter::onReceiveError(Api::IoError::IoErrorCode error_code) {
  // config_->stats().downstream_sess_rx_errors_.inc();
  UNREFERENCED_PARAMETER(error_code);
}

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
