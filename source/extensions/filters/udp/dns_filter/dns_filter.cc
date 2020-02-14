#include "extensions/filters/udp/dns_filter/dns_filter.h"

#include "envoy/network/listener.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

DnsProxyFilterConfig::DnsProxyFilterConfig(
    Server::Configuration::ListenerFactoryContext& context,
    const envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig& config)
    : root_scope(context.scope()), stats_(generateStats(config.stat_prefix(), root_scope)) {

  // store configured data for server context
  const size_t entries = config.server_config().virtual_domains().size();

  virtual_domains_.reserve(entries);
  for (const auto& virtual_domain : config.server_config().virtual_domains()) {
    DnsAddressList addresses{};

    for (const auto& configured_address : virtual_domain.address()) {
      addresses.push_back(configured_address);
    }
    virtual_domains_.emplace(std::make_pair(virtual_domain.name(), addresses));
  }

  // TODO: store configured data for client context
}

void DnsFilter::onData(Network::UdpRecvData& client_request) {

  // Parse the query
  query_parser_->parseQueryData(client_request.buffer_);

  // Determine if the hostname is known
  DnsAnswerRecordPtr response_rec = getResponseForQuery();
  ENVOY_LOG(trace, "Parsed address for query: {}",
            response_rec != nullptr ? response_rec->address_ : "None");

  // TODO:
  // Determine whether we should upstream the query
  // if not, return a response to the client

  // return to client
  sendDnsResponse(client_request, response_rec);
}

DnsAnswerRecordPtr DnsFilter::getResponseForQuery() {

  const auto& queries = query_parser_->getQueries();

  // It appears to be a rare case where we would have more than
  // one query in a single request.  It is allowed by the protocol
  // but not widely supported:
  //
  // https://stackoverflow.com/a/4083071

  const DnsVirtualDomainConfig& domains = config_->domains();

  for (const auto& rec : queries) {
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

    // TODO: Verify the address class is the same as the query

    size_t index = rng_.random() % configured_address_list.size();
    const std::string& address = configured_address_list.at(index);
    ENVOY_LOG(debug, "returning address {} for domain [{}]", address, rec->name_);

    size_t address_size;
    switch (rec->class_) {
    case 0x28: // AAAA
      address_size = 16;
      break;
    case 1: // A
			// intentional fallthrough
    default:
      address_size = 4;
    }

    DnsAnswerRecordPtr answer_rec = std::make_unique<DnsAnswerRecord>(
        rec->name_, rec->type_, rec->class_, 300 /*ttl*/, address_size /*Address size*/, address);
    return answer_rec;
  }

  return nullptr;
}

void DnsFilter::sendDnsResponse(const Network::UdpRecvData& request_data,
                                DnsAnswerRecordPtr& answer_record) {

  Buffer::OwnedImpl response{};
  (void)query_parser_->buildResponseBuffer(response, answer_record);

  ENVOY_LOG(debug, "Sending response from: {} to: {}",
            request_data.addresses_.local_->asStringView(),
            request_data.addresses_.peer_->asStringView());

  auto local = request_data.addresses_.local_->ip();
  auto peer = request_data.addresses_.peer_;

  Network::UdpSendData response_data{local, *peer, response};
  listener_.send(response_data);
}

void DnsFilter::onReceiveError(Api::IoError::IoErrorCode) {
  // config_->stats().downstream_sess_rx_errors_.inc();
}
} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
