#include "extensions/filters/udp/dns_filter/dns_filter.h"

#include "envoy/network/listener.h"

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

  static constexpr uint64_t ResolverTimeoutMs = 500;

  using envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig;

  // store configured data for server context
  const auto& server_config = config.server_config();

  if (server_config.has_control_plane_config()) {

    const auto& cp_config = server_config.control_plane_config();
    const size_t entries = cp_config.virtual_domains().size();

    // TODO: Investigate how easy it would be to support wildcard
    // matching so that we can eliminate having two sets of domains
    virtual_domains_.reserve(entries);
    for (const auto& virtual_domain : cp_config.virtual_domains()) {
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

      // TODO: Should we check whether the virtual domain exists in the known domains
      // and add it to the known domain list if missing?
      virtual_domains_.emplace(std::make_pair(virtual_domain.name(), addrs));
    }

    // Add known domains
    for (const auto& domain : cp_config.known_domains()) {
      // TODO: Ensure that the known domains don't start with a period
      if (known_domains_.find(domain) == known_domains_.end()) {
        known_domains_.emplace(domain);
      }
    }
  }

  // TODO: store configured data for client context
  const auto& client_config = config.client_config();
  forward_queries_ = client_config.forward_query();
  if (forward_queries_) {
    // Instantiate resolver with external servers
    const auto& upstream_resolvers = client_config.upstream_resolvers();
    resolvers_.reserve(upstream_resolvers.size());
    for (const auto& resolver : upstream_resolvers) {
      const auto ipaddr = Network::Utility::parseInternetAddress(resolver, 0, true);
      resolvers_.push_back(ipaddr);
    }
  }

  resolver_timeout_ms_ = std::chrono::milliseconds(
      PROTOBUF_GET_MS_OR_DEFAULT(client_config, resolver_timeout, ResolverTimeoutMs));
}

DnsFilter::DnsFilter(Network::UdpReadFilterCallbacks& callbacks,
                     const DnsFilterEnvoyConfigSharedPtr& config)
    : UdpListenerReadFilter(callbacks), config_(config),
      message_parser_(std::make_unique<DnsMessageParser>()), listener_(callbacks.udpListener())

{

  resolver_ = std::make_unique<DnsFilterResolver>(/*dns_resolver_, */ config->resolver_timeout(),
                                                  listener_.dispatcher());
}

absl::optional<std::string> DnsFilter::isKnownDomain(const std::string& domain_name) {

  const auto known_domains = config_->known_domains();

  // If we don't have a list of whitelisted domains, we will immediately
  // resolve the name with an upstream DNS server
  if (known_domains.empty()) {
    ENVOY_LOG(trace, "Known domains list is empty");
    return absl::nullopt;
  }

  // Search for the last dot in the name.  If there is no name separator
  // we don't need any additional logic to handle this case
  const auto end = domain_name.find_last_of('.');

  // We need to continually strip sub-domains off of the domain_name
  // until we find a match or reach the last period in the input name
  auto iter = domain_name.find_first_of('.');
  while (iter != end) {
    const std::string subdomain = domain_name.substr(++iter);

    ENVOY_LOG(trace, "Searching for [{}] pos[{}:{}]", subdomain, iter, end);

    auto found = known_domains.find(subdomain);
    if (found != known_domains.end()) {
      return absl::make_optional<std::string>(*found);
    }

    iter = domain_name.find_first_of('.', iter);
  }
  return absl::nullopt;
}

void DnsFilter::onData(Network::UdpRecvData& client_request) {
  // TODO: Error handling

  answer_rec_.release();

  // Parse the query
  if (!message_parser_->parseDnsObject(client_request.buffer_)) {
    sendDnsResponse(client_request);
    return;
  }

  // Determine if the hostname is known
  answer_rec_ = getResponseForQuery();
  ENVOY_LOG(trace, "Parsed address for query: {}",
            answer_rec_ != nullptr ? answer_rec_->ip_addr_->ip()->addressAsString() : "None");

  // respond to client
  sendDnsResponse(client_request);
}

DnsAnswerRecordPtr DnsFilter::getResponseForQuery() {

  Network::Address::InstanceConstSharedPtr ipaddr = nullptr;
  const auto& queries = message_parser_->getQueries();

  // It appears to be a rare case where we would have more than
  // one query in a single request. It is allowed by the protocol
  // but not widely supported:
  //
  // https://stackoverflow.com/a/4083071

  const auto& domains = config_->domains();

  // Determine whether we can answer the query
  for (const auto& query : queries) {

    // Try to resolve the query locally.  If forwarding the query externally is
    // disabled we will always attempt to resolve with the configured domains
    auto known_domain = isKnownDomain(query->name_);
    if (known_domain.has_value() || !config_->forward_queries()) {

      // TODO: Determine whether the name is a cluster

      // TODO: If we have a large ( > 100) domain list, use a binary search.
      const auto iter = domains.find(query->name_);
      if (iter == domains.end()) {
        ENVOY_LOG(debug, "Domain [{}] is not a configured entry", query->name_);
        break;
      }

      const auto& configured_address_list = iter->second;
      if (configured_address_list.empty()) {
        ENVOY_LOG(debug, "Domain [{}] list is empty", query->name_);
        break;
      }

      const size_t index = rng_.random() % configured_address_list.size();
      ipaddr = configured_address_list[index];
      ENVOY_LOG(debug, "returning address {} for domain [{}]", ipaddr->ip()->addressAsString(),
                query->name_);
    }

    // We don't have a statically configured record for the domain or it's unknown
    // resolve it externally
    if (ipaddr == nullptr) {
      ENVOY_LOG(debug, "Domain [{}] is not known", query->name_);

      // TODO retries
      resolver_->resolve_query(query);

      auto resolved_addresses = resolver_->get_resolved_hosts();

      ENVOY_LOG(debug, "Resolved [{}] addresses for [{}]", resolved_addresses.size(), query->name_);

      if (resolved_addresses.empty()) {
        break;
      }

      const size_t index = rng_.random() % resolved_addresses.size();
      ipaddr = resolved_addresses[index];
    }

    // Build an answer record with the discovered address
    ASSERT(ipaddr != nullptr);
    switch (query->type_) {
    case DnsRecordType::AAAA:
      if (ipaddr->ip()->ipv6() == nullptr) {
        ENVOY_LOG(error, "Unable to return IPV6 address for query");
        return nullptr;
      }
      break;

    case DnsRecordType::A:
      if (ipaddr->ip()->ipv4() == nullptr) {
        ENVOY_LOG(error, "Unable to return IPV4 address for query");
        return nullptr;
      }
      break;

    default:
      ENVOY_LOG(error, "record type [{}] not supported", query->type_);
      return nullptr;
    }

    // The answer record could contain types other than IP's. We will support only IP
    // addresses for the moment
    return std::make_unique<DnsAnswerRecord>(query->name_, query->type_, query->class_, 300 /*ttl*/,
                                             ipaddr);
  }

  return nullptr;
}

void DnsFilter::sendDnsResponse(const Network::UdpRecvData& request_data) {

  Buffer::OwnedImpl response{};
  if (!message_parser_->buildResponseBuffer(response, answer_rec_)) {
    // TODO:  Do we send an empty buffer back to the client or
    //        craft a fixed response here? We will need a minimum
    //        of the query id from the request
    ENVOY_LOG(error, "Unable to build a response for the client");
    response.drain(response.length());
  }

  ENVOY_LOG(trace, "Sending response from: {} to: {}",
            request_data.addresses_.local_->asStringView(),
            request_data.addresses_.peer_->asStringView());

  auto local = request_data.addresses_.local_->ip();
  auto peer = request_data.addresses_.peer_;

  Network::UdpSendData response_data{local, *peer, response};
  listener_.send(response_data);
}

void DnsFilter::onReceiveError(Api::IoError::IoErrorCode error_code) {
  // config_->stats().downstream_sess_rx_errors_.inc();
  (void)error_code;
}

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
