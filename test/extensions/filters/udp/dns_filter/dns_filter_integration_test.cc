#include "envoy/config/bootstrap/v3/bootstrap.pb.h"

#include "extensions/filters/udp/dns_filter/dns_filter.h"

#include "test/integration/integration.h"
#include "test/test_common/network_utility.h"

namespace Envoy {
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
          control_plane_config:
            external_retry_count: 3
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

  std::string buildQueryForDomain(const std::string& name, uint16_t rec_type, uint16_t rec_class) {

    Extensions::UdpFilters::DnsFilter::DnsMessageStruct query{};

    // Generate a random query ID
    query.id = rng_.random() & 0xFFFF;

    // Signify that this is a query
    query.f.flags.qr = 0;

    // This should usually be zero
    query.f.flags.opcode = 0;

    query.f.flags.aa = 0;
    query.f.flags.tc = 0;

    // Set Recursion flags (at least one bit set so that the flags are not all zero)
    query.f.flags.rd = 1;
    query.f.flags.ra = 0;

    // reserved flag is not set
    query.f.flags.z = 0;

    // Set the authenticated flags to zero
    query.f.flags.ad = 0;
    query.f.flags.cd = 0;

    query.questions = 1;
    query.answers = 0;
    query.authority_rrs = 0;
    query.additional_rrs = 0;

    Buffer::OwnedImpl buffer_;
    buffer_.writeBEInt<uint16_t>(query.id);
    buffer_.writeBEInt<uint16_t>(query.f.val);
    buffer_.writeBEInt<uint16_t>(query.questions);
    buffer_.writeBEInt<uint16_t>(query.answers);
    buffer_.writeBEInt<uint16_t>(query.authority_rrs);
    buffer_.writeBEInt<uint16_t>(query.additional_rrs);

    Extensions::UdpFilters::DnsFilter::DnsQueryRecordPtr query_ptr =
        std::make_unique<Extensions::UdpFilters::DnsFilter::DnsQueryRecord>(name, rec_type,
                                                                            rec_class);

    buffer_.add(query_ptr->serialize());

    return buffer_.toString();
  }

  Runtime::RandomGeneratorImpl rng_;
};

INSTANTIATE_TEST_SUITE_P(IpVersions, DnsFilterIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// Basic loopback test.
TEST_P(DnsFilterIntegrationTest, HelloWorldOnLoopback) {
  setup(0);
  const uint32_t port = lookupPort("listener_0");
  const auto listener_address = Network::Utility::resolveUrl(
      fmt::format("tcp://{}:{}", Network::Test::getLoopbackAddressUrlString(version_), port));

  Network::UdpRecvData response;
  std::string query =
      buildQueryForDomain("www.google.com", Extensions::UdpFilters::DnsFilter::DnsRecordType::A,
                          Extensions::UdpFilters::DnsFilter::DnsRecordClass::IN);
  requestResponseWithListenerAddress(*listener_address, query, response);
}

#if 0
// Verifies calling sendmsg with a non-local address. Note that this test is only fully complete for
// IPv4. See the comment below for more details.
TEST_P(DnsFilterIntegrationTest, HelloWorldOnNonLocalAddress) {
  setup(1);
  const uint32_t port = lookupPort("listener_0");
  Network::Address::InstanceConstSharedPtr listener_address;
  if (version_ == Network::Address::IpVersion::v4) {
    // Kernel regards any 127.x.x.x as local address.
    listener_address.reset(new Network::Address::Ipv4Instance(
#ifndef __APPLE__
        "127.0.0.3",
#else
        "127.0.0.1",
#endif
        port));
  } else {
    // IPv6 doesn't allow any non-local source address for sendmsg. And the only
    // local address guaranteed in tests in loopback. Unfortunately, even if it's not
    // specified, kernel will pick this address as source address. So this test
    // only checks if IoSocketHandle::sendmsg() sets up CMSG_DATA correctly,
    // i.e. cmsg_len is big enough when that code path is executed.
    listener_address.reset(new Network::Address::Ipv6Instance("::1", port));
  }

  requestResponseWithListenerAddress(*listener_address);
}

// Make sure multiple clients are routed correctly to a single upstream host.
TEST_P(DnsFilterIntegrationTest, MultipleClients) {
  setup(1);
  const uint32_t port = lookupPort("listener_0");
  const auto listener_address = Network::Utility::resolveUrl(
      fmt::format("tcp://{}:{}", Network::Test::getLoopbackAddressUrlString(version_), port));

  Network::Test::UdpSyncPeer client1(version_);
  client1.write("client1_hello", *listener_address);

  Network::Test::UdpSyncPeer client2(version_);
  client2.write("client2_hello", *listener_address);
  client2.write("client2_hello_2", *listener_address);

  Network::UdpRecvData client1_request_datagram;
  ASSERT_TRUE(fake_upstreams_[0]->waitForUdpDatagram(client1_request_datagram));
  EXPECT_EQ("client1_hello", client1_request_datagram.buffer_->toString());

  Network::UdpRecvData client2_request_datagram;
  ASSERT_TRUE(fake_upstreams_[0]->waitForUdpDatagram(client2_request_datagram));
  EXPECT_EQ("client2_hello", client2_request_datagram.buffer_->toString());
  ASSERT_TRUE(fake_upstreams_[0]->waitForUdpDatagram(client2_request_datagram));
  EXPECT_EQ("client2_hello_2", client2_request_datagram.buffer_->toString());

  // We should not be getting datagrams from the same peer.
  EXPECT_NE(*client1_request_datagram.addresses_.peer_, *client2_request_datagram.addresses_.peer_);

  // Send two datagrams back to client 2.
  fake_upstreams_[0]->sendUdpDatagram("client2_world", client2_request_datagram.addresses_.peer_);
  fake_upstreams_[0]->sendUdpDatagram("client2_world_2", client2_request_datagram.addresses_.peer_);
  Network::UdpRecvData response_datagram;
  client2.recv(response_datagram);
  EXPECT_EQ("client2_world", response_datagram.buffer_->toString());
  client2.recv(response_datagram);
  EXPECT_EQ("client2_world_2", response_datagram.buffer_->toString());

  // Send 1 datagram back to client 1.
  fake_upstreams_[0]->sendUdpDatagram("client1_world", client1_request_datagram.addresses_.peer_);
  client1.recv(response_datagram);
  EXPECT_EQ("client1_world", response_datagram.buffer_->toString());
}

// Make sure sessions correctly forward to the same upstream host when there are multiple upstream
// hosts.
TEST_P(DnsFilterIntegrationTest, MultipleUpstreams) {
  setup(2);
  const uint32_t port = lookupPort("listener_0");
  const auto listener_address = Network::Utility::resolveUrl(
      fmt::format("tcp://{}:{}", Network::Test::getLoopbackAddressUrlString(version_), port));

  Network::Test::UdpSyncPeer client(version_);
  client.write("hello1", *listener_address);
  client.write("hello2", *listener_address);
  Network::UdpRecvData request_datagram;
  ASSERT_TRUE(fake_upstreams_[0]->waitForUdpDatagram(request_datagram));
  EXPECT_EQ("hello1", request_datagram.buffer_->toString());
  ASSERT_TRUE(fake_upstreams_[0]->waitForUdpDatagram(request_datagram));
  EXPECT_EQ("hello2", request_datagram.buffer_->toString());

  fake_upstreams_[0]->sendUdpDatagram("world1", request_datagram.addresses_.peer_);
  fake_upstreams_[0]->sendUdpDatagram("world2", request_datagram.addresses_.peer_);
  Network::UdpRecvData response_datagram;
  client.recv(response_datagram);
  EXPECT_EQ("world1", response_datagram.buffer_->toString());
  client.recv(response_datagram);
  EXPECT_EQ("world2", response_datagram.buffer_->toString());
}
#endif

} // namespace
} // namespace Envoy
