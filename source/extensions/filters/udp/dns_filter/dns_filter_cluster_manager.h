#pragma once

#include "envoy/upstream/cluster_manager.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

class DnsFilterClusterMgr : public Upstream::ClusterUpdateCallbacks,
                            Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilterClusterMgr(Upstream::ClusterManager& cluster_manager)
      : cluster_manager_(cluster_manager) {}
  virtual ~DnsFilterClusterMgr(){};

  void onClusterAddOrUpdate(Upstream::ThreadLocalCluster& cluster);
  void onClusterRemoval(const std::string& cluster_name);

  virtual void getAddressForCluster(const absl::string_view& cluster_name);

private:
  absl::flat_hash_set<std::string> registered_cluster_set_;
  Upstream::ClusterManager& cluster_manager_;
};

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
