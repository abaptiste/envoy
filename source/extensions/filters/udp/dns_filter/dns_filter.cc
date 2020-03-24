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

  // We cannot create the dns server here since the dispatcher loop is running
  // in a different thread than the one where the filter is created
}

DnsFilter::DnsFilter(Network::UdpReadFilterCallbacks& callbacks,
                     const DnsFilterEnvoyConfigSharedPtr& config)
    : UdpListenerReadFilter(callbacks), config_(config), listener_(callbacks.udpListener())

{
  message_parser_ = std::make_unique<DnsMessageParser>(/*response_callback*/);

  // Instantiate the dns server here so that the event loop runs in the same thread
  // as this object
  //
  // TODO retries

  answer_callback_ = [this](DnsQueryRecordPtr& query,
                                          Network::Address::InstanceConstSharedPtr ipaddr) -> void {
    // This callback is executed when the dns resolution completes.  At that time
    // we build an Address::InstanceConstSharedPtr from one of the addresses returned
    // and send it to the client
    serializeAndSendResponse(query, ipaddr);
  };

  auto dns_resolver = listener_.dispatcher().createDnsResolver(config_->resolvers(), false);
  resolver_ = std::make_unique<DnsFilterResolver>(dns_resolver, answer_callback_);
}

void DnsFilter::serializeAndSendResponse(DnsQueryRecordPtr& query,
                                Network::Address::InstanceConstSharedPtr ipaddr) {
    auto answer = message_parser_->buildDnsAnswerRecord(query.get(), 300, ipaddr);
    sendDnsResponse(std::move(answer));
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

  // Clear any cruft
  response_.drain(response_.length());

  // Save the connection endpoints so that we can respond
  local_ = client_request.addresses_.local_;
  peer_ = client_request.addresses_.peer_;

  // Parse the query
  message_parser_->parseDnsObject(client_request.buffer_);

  // still need to do the resolution
  auto response = getResponseForQuery();
  if (!response.has_value()) {
    // error
    sendDnsResponse(nullptr);
    return;
  }

  auto response_value = std::move(response.value());

  // Externally resolved.  We'll respond to the client when the
  // DNS resolution callback returns
  if (response_value == nullptr) {
    return;
  }

  // We have an answer. Send it to the client
  sendDnsResponse(std::move(response_value));
}

absl::optional<DnsAnswerRecordPtr> DnsFilter::getResponseForQuery() {

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

      // When the callback executes it will execuate a callback to build
      // a response and send it to the client
      resolver_->resolve_query(query);
      return absl::make_optional<DnsAnswerRecordPtr>(nullptr);
    }

    return absl::make_optional<DnsAnswerRecordPtr>(
        message_parser_->buildDnsAnswerRecord(query.get(), 300, ipaddr));
  }

  return absl::nullopt;
}

void DnsFilter::sendDnsResponse(DnsAnswerRecordPtr answer) {

  if (!message_parser_->buildResponseBuffer(response_, std::move(answer))) {
    // TODO:  Do we send an empty buffer back to the client or
    //        craft a fixed response here? We will need a minimum
    //        of the query id from the request
    ENVOY_LOG(error, "Unable to build a response for the client");
  }

  ENVOY_LOG(trace, "Sending response from: {} to: {}", local_->asStringView(),
            peer_->asStringView());

  Network::UdpSendData response_data{local_->ip(), *peer_, response_};
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
