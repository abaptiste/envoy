#include "extensions/filters/udp/dns_filter/dns_filter_cluster_manager.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

void DnsFilterClusterMgr::onClusterAddOrUpdate(Upstream::ThreadLocalCluster& cluster) {
  ENVOY_LOG(debug, "Adding or updating cluster [{}]", cluster.info()->name());
}

void DnsFilterClusterMgr::onClusterRemoval(const std::string& cluster_name) {
  ENVOY_LOG(debug, "Removing cluster [{}]", cluster_name);
}

void DnsFilterClusterMgr::getAddressForCluster(const absl::string_view& cluster_name) {
  (void)cluster_manager_;
  ENVOY_LOG(debug, "Removing cluster [{}]", cluster_name);
}

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
