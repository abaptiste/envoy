#include "extensions/filters/udp/dns_filter/dns_filter.h"

#include "envoy/network/listener.h"

#include "common/network/address_impl.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

DnsFilterEnvoyConfig::DnsFilterEnvoyConfig(
    Server::Configuration::ListenerFactoryContext& context,
    const envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig& config)
    : root_scope(context.scope()), stats_(generateStats(config.stat_prefix(), root_scope)) {

  using envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig;

  // store configured data for server context
  const auto& server_config = config.server_config();

  if (server_config.has_control_plane_cfg()) {

    const auto& cfg = server_config.control_plane_cfg();
    const size_t entries = cfg.virtual_domains().size();

    virtual_domains_.reserve(entries);
    for (const auto& virtual_domain : cfg.virtual_domains()) {
      DnsAddressList addresses{};

      if (virtual_domain.endpoint().has_addresslist()) {
        const auto& address_list = virtual_domain.endpoint().addresslist().address();
        addresses.reserve(address_list.size());
        for (const auto& configured_address : address_list) {
          // This will throw an exception if the configured_address string is malformed
          const auto ipaddr = Network::Utility::parseInternetAddress(configured_address, 0, true);
          addresses.push_back(ipaddr);
        }
      }

      virtual_domains_.emplace(std::make_pair(virtual_domain.name(), addresses));
    }
  }

  // TODO: store configured data for client context
}

void DnsFilter::onData(Network::UdpRecvData& client_request) {
  // TODO: Error handling

  answer_rec_.release();

  // Parse the query
  if (!query_parser_->parseDnsObject(client_request.buffer_)) {
    sendDnsResponse(client_request);
    return;
  }

  // Determine if the hostname is known
  answer_rec_ = getResponseForQuery();
  ENVOY_LOG(trace, "Parsed address for query: {}",
            answer_rec_ != nullptr ? answer_rec_->ip_addr_->ip()->addressAsString() : "None");

  // TODO: Determine whether we should send the query to a different server

  // respond to client
  sendDnsResponse(client_request);
}

DnsAnswerRecordPtr DnsFilter::getResponseForQuery() {

  const auto& queries = query_parser_->getQueries();

  // It appears to be a rare case where we would have more than
  // one query in a single request. It is allowed by the protocol
  // but not widely supported:
  //
  // https://stackoverflow.com/a/4083071

  const auto& domains = config_->domains();

  for (const auto& rec : queries) {

    // TODO: If we have a sufficiently large ( > 100) list of domains, we should use a binary
    // search.
    const auto iter = domains.find(rec->name_);
    if (iter == domains.end()) {
      ENVOY_LOG(debug, "Domain [{}] is not a configured entry", rec->name_);
      return nullptr;
    }

    const auto& configured_address_list = iter->second;
    if (configured_address_list.empty()) {
      ENVOY_LOG(debug, "Domain [{}] list is empty", rec->name_);
      return nullptr;
    }

    const size_t index = rng_.random() % configured_address_list.size();
    const auto ipaddr = configured_address_list[index];
    // ENVOY_LOG(debug, "returning address {} for domain [{}]", address_str, rec->name_);

    switch (rec->type_) {
    case DnsRecordType::AAAA:
      if (ipaddr->ip()->ipv6() == nullptr) {
        ENVOY_LOG(error, "Invalid record type requested. Unable to return IPV6 address for query");
        return nullptr;
      }
      break;

    case DnsRecordType::A:
      if (ipaddr->ip()->ipv4() == nullptr) {
        ENVOY_LOG(error, "Invalid record type requested. Unable to return IPV4 address for query");
        return nullptr;
      }
      break;

    default:
      ENVOY_LOG(error, "record type [{}] not yet supported", rec->type_);
      return nullptr;
    }

    // The answer record could contain types other than IP's so we cannot limit the address
    return std::make_unique<DnsAnswerRecord>(rec->name_, rec->type_, rec->class_, 300 /*ttl*/,
                                             ipaddr);
  }

  return nullptr;
}

void DnsFilter::sendDnsResponse(const Network::UdpRecvData& request_data) {

  Buffer::OwnedImpl response{};
  if (!query_parser_->buildResponseBuffer(response, answer_rec_)) {
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
