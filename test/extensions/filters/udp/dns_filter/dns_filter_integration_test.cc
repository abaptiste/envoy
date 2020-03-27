#include "envoy/config/bootstrap/v3/bootstrap.pb.h"

#include "extensions/filters/udp/dns_filter/dns_filter.h"

#include "test/integration/integration.h"
#include "test/test_common/network_utility.h"

#include "dns_filter_test_utils.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {
namespace {

class DnsFilterIntegrationTest : public testing::TestWithParam<Network::Address::IpVersion>,
                                 public BaseIntegrationTest {
public:
  DnsFilterIntegrationTest() : BaseIntegrationTest(GetParam(), configToUse()) {}

  static std::string configToUse() {
    return ConfigHelper::BASE_UDP_LISTENER_CONFIG + R"EOF(
    listener_filters:
      name: "envoy.filters.udp.dns_filter"
      typed_config:
        '@type': 'type.googleapis.com/envoy.config.filter.udp.dns_filter.v2alpha.DnsFilterConfig'
        stat_prefix: "my_prefix"
        client_config:
          forward_query: true
          upstream_resolvers:
          - "1.1.1.1"
          - "8.8.8.8"
          - "8.8.4.4"
        server_config:
          inline_dns_table:
            external_retry_count: 3
            known_suffixes:
            - suffix: foo1.com
            - suffix: foo2.com
            - suffix: foo3.com
            virtual_domains:
            - name: "www.foo1.com"
              endpoint:
                address_list:
                  address:
                  - 10.0.0.1
                  - 10.0.0.2
            - name: "www.foo2.com"
              endpoint:
                address_list:
                  address:
                  - 2001:8a:c1::2800:7
            - name: "www.foo3.com"
              endpoint:
                address_list:
                  address:
                  - 10.0.3.1
      )EOF";
  }

  void setup(uint32_t upstream_count) {
    udp_fake_upstream_ = true;
    if (upstream_count > 1) {
      setDeterministic();
      setUpstreamCount(upstream_count);
      config_helper_.addConfigModifier(
          [upstream_count](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
            for (uint32_t i = 1; i < upstream_count; i++) {
              bootstrap.mutable_static_resources()
                  ->mutable_clusters(0)
                  ->mutable_load_assignment()
                  ->mutable_endpoints(0)
                  ->add_lb_endpoints()
                  ->mutable_endpoint()
                  ->MergeFrom(ConfigHelper::buildEndpoint(
                      Network::Test::getLoopbackAddressString(GetParam())));
            }
          });
    }
    BaseIntegrationTest::initialize();
  }

  /**
   *  Destructor for an individual test.
   */
  void TearDown() override {
    test_server_.reset();
    fake_upstreams_.clear();
  }

  void requestResponseWithListenerAddress(const Network::Address::Instance& listener_address,
                                          const std::string& data_to_send,
                                          Network::UdpRecvData& response_datagram) {
    // Send datagram to be proxied.
    Network::Test::UdpSyncPeer client(version_);
    client.write(data_to_send, listener_address);

    // Read the response
    client.recv(response_datagram);
  }

  DnsMessageParser response_parser_;
};

INSTANTIATE_TEST_SUITE_P(IpVersions, DnsFilterIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// Basic External Lookup test.
TEST_P(DnsFilterIntegrationTest, ExternalLookupTest) {
  setup(0);
  const uint32_t port = lookupPort("listener_0");
  const auto listener_address = Network::Utility::resolveUrl(
      fmt::format("tcp://{}:{}", Network::Test::getLoopbackAddressUrlString(version_), port));

  Network::UdpRecvData response;
  std::string query = Utils::buildQueryForDomain(
      "www.google.com", Extensions::UdpFilters::DnsFilter::DnsRecordType::A,
      Extensions::UdpFilters::DnsFilter::DnsRecordClass::IN);
  requestResponseWithListenerAddress(*listener_address, query, response);

  ASSERT_TRUE(response_parser_.parseDnsObject(response.buffer_));

  ASSERT_EQ(1, response_parser_.getQueries().size());
  ASSERT_GE(1, response_parser_.getAnswers().size());
  ASSERT_EQ(0, response_parser_.getQueryResponseCode());
}

TEST_P(DnsFilterIntegrationTest, ExternalLookupTestIPv6) {
  setup(0);
  const uint32_t port = lookupPort("listener_0");
  const auto listener_address = Network::Utility::resolveUrl(
      fmt::format("tcp://{}:{}", Network::Test::getLoopbackAddressUrlString(version_), port));

  Network::UdpRecvData response;
  std::string query = Utils::buildQueryForDomain(
      "www.google.com", Extensions::UdpFilters::DnsFilter::DnsRecordType::AAAA,
      Extensions::UdpFilters::DnsFilter::DnsRecordClass::IN);
  requestResponseWithListenerAddress(*listener_address, query, response);

  ASSERT_TRUE(response_parser_.parseDnsObject(response.buffer_));

  ASSERT_EQ(1, response_parser_.getQueries().size());
  ASSERT_GE(1, response_parser_.getAnswers().size());
  ASSERT_EQ(0, response_parser_.getQueryResponseCode());
}

TEST_P(DnsFilterIntegrationTest, LocalLookupTest) {
  setup(0);
  const uint32_t port = lookupPort("listener_0");
  const auto listener_address = Network::Utility::resolveUrl(
      fmt::format("tcp://{}:{}", Network::Test::getLoopbackAddressUrlString(version_), port));

  Network::UdpRecvData response;
  std::string query = Utils::buildQueryForDomain(
      "www.foo1.com", Extensions::UdpFilters::DnsFilter::DnsRecordType::A,
      Extensions::UdpFilters::DnsFilter::DnsRecordClass::IN);
  requestResponseWithListenerAddress(*listener_address, query, response);

  ASSERT_TRUE(response_parser_.parseDnsObject(response.buffer_));

  ASSERT_EQ(1, response_parser_.getQueries().size());
  ASSERT_EQ(2, response_parser_.getAnswers().size());
  ASSERT_EQ(0, response_parser_.getQueryResponseCode());
}
} // namespace
} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
