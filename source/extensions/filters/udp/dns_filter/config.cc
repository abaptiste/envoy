#include "extensions/filters/udp/dns_filter/config.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

Network::UdpListenerFilterFactoryCb DnsFilterConfigFactory::createFilterFactoryFromProto(
    const Protobuf::Message& config, Server::Configuration::ListenerFactoryContext& context) {
  auto shared_config = std::make_shared<DnsFilterEnvoyConfig>(
      context, MessageUtil::downcastAndValidate<
<<<<<<< HEAD
                   const envoy::extensions::filter::udp::dns_filter::v3alpha::DnsFilterConfig&>(
=======
                   const envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig&>(
>>>>>>> master
                   config, context.messageValidationVisitor()));

  return [shared_config](Network::UdpListenerFilterManager& filter_manager,
                         Network::UdpReadFilterCallbacks& callbacks) -> void {
    filter_manager.addReadFilter(std::make_unique<DnsFilter>(callbacks, shared_config));
  };
}

ProtobufTypes::MessagePtr DnsFilterConfigFactory::createEmptyConfigProto() {
<<<<<<< HEAD
  return std::make_unique<envoy::extensions::filter::udp::dns_filter::v3alpha::DnsFilterConfig>();
=======
  return std::make_unique<envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig>();
>>>>>>> master
}

std::string DnsFilterConfigFactory::name() const { return "envoy.filters.udp.dns_filter"; }

/**
 * Static registration for the DNS Filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<DnsFilterConfigFactory,
                                 Server::Configuration::NamedUdpListenerFilterConfigFactory>
    register_;

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
