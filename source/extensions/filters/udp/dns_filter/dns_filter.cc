#include "extensions/filters/udp/dns_filter/dns_filter.h"

#include "envoy/network/listener.h"
#include "envoy/type/matcher/v3/string.pb.h"

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

      uint64_t ttl = virtual_domain.has_answer_ttl()
                         ? DurationUtil::durationToSeconds(virtual_domain.answer_ttl())
                         : DefaultResolverTTLs;
      domain_ttl_.emplace(virtual_domain.name(), ttl);
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

  resolver_timeout_ms_ = std::chrono::milliseconds(
      PROTOBUF_GET_MS_OR_DEFAULT(client_config, resolver_timeout, DefaultResolverTimeoutMs));
}

DnsFilter::DnsFilter(Network::UdpReadFilterCallbacks& callbacks,
                     const DnsFilterEnvoyConfigSharedPtr& config)
    : UdpListenerReadFilter(callbacks), config_(config), listener_(callbacks.udpListener()),
      cluster_manager_(config_->cluster_manager()),
      message_parser_(std::make_unique<DnsMessageParser>())

{
  // TODO retries

  // This callback is executed when the dns resolution completes. At that time
  // we build an answer record from each IP resolved, then send it to the client
  answer_callback_ = [this](DnsQueryRecordPtr& query, AddressConstPtrVec& iplist) -> void {
    for (const auto& ip : iplist) {
      uint16_t ttl = getDomainTTL(query->name_);
      message_parser_->buildDnsAnswerRecord(*query, ttl, std::move(ip));
    }
    sendDnsResponse();
  };

  resolver_ = std::make_unique<DnsFilterResolver>(
      answer_callback_, config->resolvers(), config->resolver_timeout(), listener_.dispatcher());
}

void DnsFilter::onData(Network::UdpRecvData& client_request) {

  // Save the connection endpoints so that we can respond
  local_ = client_request.addresses_.local_;
  peer_ = client_request.addresses_.peer_;

  // Parse the query, if it fails return an response to the client
  if (!message_parser_->parseDnsObject(client_request.buffer_)) {
    sendDnsResponse();
    return;
  }

  // Resolve the requested name
  auto response = getResponseForQuery();

  // We were not able to satisfy the request locally. Return an
  // empty response to the client
  if (response == DnsLookupResponseCode::Failure) {
    sendDnsResponse();
    return;
  }

  // Externally resolved. We'll respond to the client when the
  // external DNS resolution callback returns
  if (response == DnsLookupResponseCode::External) {
    return;
  }

  // We have an answer. Send it to the client
  sendDnsResponse();
}

void DnsFilter::sendDnsResponse() {

  // Clear any cruft in the outgoing buffer
  response_.drain(response_.length());

  // This serializes the generated response to the parse query from the client. If there is a
  // parsing error or the incoming query is invalid, we will still generate a valid DNS response
  message_parser_->buildResponseBuffer(response_);

  Network::UdpSendData response_data{local_->ip(), *peer_, response_};
  listener_.send(response_data);
}

DnsLookupResponseCode DnsFilter::getResponseForQuery() {

  auto& query_map = message_parser_->getActiveQueryRecords();

  // It appears to be a rare case where we would have more than one query in a single request.
  // It is allowed by the protocol but not widely supported:
  //
  // https://stackoverflow.com/a/4083071

  const uint16_t id = message_parser_->getCurrentQueryId();
  const auto& query_iter = query_map.find(id);

  if (query_iter == query_map.end()) {
    ENVOY_LOG_MISC(error, "Unable to find queries for the current transaction id: {}", id);
  }

  // The number of queries will almost always be one. This governed by the 'questions' field in
  // the flags. Since the protocol allows for more than one query, we will handle this case.
  for (const auto& query : query_iter->second) {

    // Try to resolve the query locally. If forwarding the query externally is disabled we will
    // always attempt to resolve with the configured domains
    if (isKnownDomain(query->name_) || !config_->forward_queries()) {

      // Determine whether the name is a cluster. Move on to the next query if successful
      if (resolveViaClusters(*query)) {
        continue;
      }

      // Determine whether we an answer this query with the static configuration
      if (resolveViaConfiguredHosts(*query)) {
        continue;
      }
    }

    ENVOY_LOG(debug, "resolving name [{}] via external resolvers", query->name_);
    resolver_->resolve_query(query);
    return DnsLookupResponseCode::External;
  }

  if (message_parser_->queriesUnanswered(id)) {
    return DnsLookupResponseCode::Failure;
  }
  return DnsLookupResponseCode::Success;
}

uint32_t DnsFilter::getDomainTTL(const absl::string_view domain) {
  uint32_t ttl;

  const auto& domain_ttl_config = config_->domain_ttl();
  const auto& iter = domain_ttl_config.find(domain);

  if (iter == domain_ttl_config.end()) {
    ttl = static_cast<uint32_t>(DnsFilterEnvoyConfig::DefaultResolverTTLs);
  } else {
    ttl = static_cast<uint32_t>(iter->second);
  }

  return ttl;
}

bool DnsFilter::isKnownDomain(const absl::string_view domain_name) {

  const auto& known_suffixes = config_->known_suffixes();

  // If we don't have a list of whitelisted domain suffixes, we will resolve the name with an
  // external DNS server
  if (known_suffixes.empty()) {
    ENVOY_LOG(trace, "Known domains list is empty");
    return false;
  }

  // TODO: Use a trie to find a match instead of iterating through the list
  for (auto& suffix : known_suffixes) {
    if (suffix->match(domain_name)) {
      return true;
    }
  }

  return false;
}

bool DnsFilter::resolveViaClusters(const DnsQueryRecord& query) {

  Upstream::ThreadLocalCluster* cluster = cluster_manager_.get(query.name_);
  if (cluster == nullptr) {
    ENVOY_LOG(debug, "Did not find a cluster for name [{}]", query.name_);
    return false;
  }

  // Return the address for all discovered endpoints
  size_t discovered_endpoints = 0;
  const uint32_t ttl = getDomainTTL(query.name_);
  for (const auto& hostsets : cluster->prioritySet().hostSetsPerPriority()) {
    for (const auto& host : hostsets->hosts()) {
      ++discovered_endpoints;
      ENVOY_LOG(debug, "using cluster host address {} for domain [{}]",
                host->address()->ip()->addressAsString(), query.name_);
      message_parser_->buildDnsAnswerRecord(query, ttl, host->address());
    }
  }
  return (discovered_endpoints != 0);
}

bool DnsFilter::resolveViaConfiguredHosts(const DnsQueryRecord& query) {

  const auto& domains = config_->domains();

  // TODO: If we have a large ( > 100) domain list, use a binary search.
  const auto iter = domains.find(query.name_);
  if (iter == domains.end()) {
    ENVOY_LOG(debug, "Domain [{}] is not a configured entry", query.name_);
    return false;
  }

  const auto& configured_address_list = iter->second;
  if (configured_address_list.empty()) {
    ENVOY_LOG(debug, "Domain [{}] address list is empty", query.name_);
    return false;
  }

  // Build an answer record from each configured IP address
  uint64_t hosts_found = 0;
  for (const auto& configured_address : configured_address_list) {
    ASSERT(configured_address != nullptr);
    ENVOY_LOG(debug, "using address {} for domain [{}]",
              configured_address->ip()->addressAsString(), query.name_);
    ++hosts_found;
    const uint32_t ttl = getDomainTTL(query.name_);
    message_parser_->buildDnsAnswerRecord(query, ttl, configured_address);
  }
  return (hosts_found > 0);
}

void DnsFilter::onReceiveError(Api::IoError::IoErrorCode) {
  // config_->stats().downstream_sess_rx_errors_.inc();
}

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
