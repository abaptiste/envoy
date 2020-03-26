#include "envoy/config/filter/udp/dns_filter/v2alpha/dns_filter.pb.h"
#include "envoy/config/filter/udp/dns_filter/v2alpha/dns_filter.pb.validate.h"

#include "common/common/logger.h"

#include "extensions/filters/udp/dns_filter/dns_filter.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/server/mocks.h"
#include "test/test_common/environment.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::AtLeast;
using testing::ByMove;
using testing::InSequence;
using testing::Mock;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {
namespace {

Api::IoCallUint64Result makeNoError(uint64_t rc) {
  auto no_error = Api::ioCallUint64ResultNoError();
  no_error.rc_ = rc;
  return no_error;
}
static constexpr uint64_t MAX_UDP_DNS_SIZE{512};

class DnsFilterTest : public testing::Test {
public:
  DnsFilterTest()
      : listener_address_(Network::Utility::parseInternetAddressAndPort("127.0.2.1:5353")) {
    // TODO: Consume the log setting from the command line
    // Logger::Registry::setLogLevel(TestEnvironment::getOptions().logLevel());
    Logger::Registry::setLogLevel(spdlog::level::trace);

    EXPECT_CALL(callbacks_, udpListener()).Times(AtLeast(0));
    EXPECT_CALL(callbacks_.udp_listener_, send(_))
        .WillRepeatedly(
            Invoke([this](const Network::UdpSendData& send_data) -> Api::IoCallUint64Result {
              response_ptr = std::make_unique<Buffer::OwnedImpl>();
              response_ptr->move(send_data.buffer_);
              return makeNoError(response_ptr->length());
            }));

    EXPECT_CALL(callbacks_.udp_listener_, dispatcher()).WillRepeatedly(ReturnRef(dispatcher_));
  }

  ~DnsFilterTest() { EXPECT_CALL(callbacks_.udp_listener_, onDestroy()); }

  void setup(const std::string& yaml) {
    envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig config;
    TestUtility::loadFromYamlAndValidate(yaml, config);
    auto store = stats_store_.createScope("dns_scope");
    EXPECT_CALL(listener_factory_, scope()).WillOnce(ReturnRef(*store));
    EXPECT_CALL(listener_factory_, dispatcher()).Times(AtLeast(0));
    EXPECT_CALL(listener_factory_, clusterManager()).Times(AtLeast(0));

    resolver_ = std::make_shared<Network::MockDnsResolver>();
    EXPECT_CALL(dispatcher_, createDnsResolver(_, _)).WillOnce(Return(resolver_));
    EXPECT_CALL(dispatcher_, createTimer_(_)).Times(AtLeast(0));

    config_ = std::make_shared<DnsFilterEnvoyConfig>(listener_factory_, config);
    filter_ = std::make_unique<DnsFilter>(callbacks_, config_);
  }

  void sendQueryFromClient(const std::string& peer_address, const std::string& buffer) {
    Network::UdpRecvData data;
    data.addresses_.peer_ = Network::Utility::parseInternetAddressAndPort(peer_address);
    data.addresses_.local_ = listener_address_;
    data.buffer_ = std::make_unique<Buffer::OwnedImpl>(buffer);
    data.receive_time_ = MonotonicTime(std::chrono::seconds(0));
    filter_->onData(data);
  }

  std::string buildQueryForDomain(const std::string& name, uint16_t rec_type, uint16_t rec_class) {

    DnsMessageStruct query{};

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

    DnsQueryRecordPtr query_ptr = std::make_unique<DnsQueryRecord>(name, rec_type, rec_class);

    buffer_.add(query_ptr->serialize());

    return buffer_.toString();
  }

  void verifyAddress(const std::list<std::string>& addresses, const DnsAnswerRecordPtr& answer) {

    ASSERT_TRUE(answer != nullptr);
    ASSERT_TRUE(answer->ip_addr_ != nullptr);

    const auto resolved_address = answer->ip_addr_->ip()->addressAsString();
    if (addresses.size() == 1) {
      const auto expected = addresses.begin();
      ASSERT_EQ(*expected, resolved_address);
      return;
    }

    const auto iter = std::find(addresses.begin(), addresses.end(), resolved_address);
    ASSERT_TRUE(iter != addresses.end());
  }

  const Network::Address::InstanceConstSharedPtr listener_address_;
  Server::Configuration::MockListenerFactoryContext listener_factory_;
  DnsFilterEnvoyConfigSharedPtr config_;

  std::unique_ptr<DnsFilter> filter_;
  Network::MockUdpReadFilterCallbacks callbacks_;
  Stats::IsolatedStoreImpl stats_store_;
  Buffer::InstancePtr response_ptr;
  DnsMessageParser response_parser_;
  Runtime::RandomGeneratorImpl rng_;

  Event::MockDispatcher dispatcher_;
  std::shared_ptr<Network::MockDnsResolver> resolver_;

  // This config has external resolution disabled and is used to verify local lookups.  With
  // external resolution disabled, it eliminates having to setup mocks for the resolver callbacks in
  // each test.
  const std::string forward_query_off_config = R"EOF(
stat_prefix: "my_prefix"
client_config:
  forward_query: false
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

  // This config has external resolution enabled.  Each test must setup the mock to save and execute
  // the resolver callback
  const std::string forward_query_on_config = R"EOF(
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
    virtual_domains:
      - name: "www.foo1.com"
        endpoint:
          address_list:
            address:
              - 10.0.0.1
  )EOF";
};

TEST_F(DnsFilterTest, InvalidQuery) {
  InSequence s;

  setup(forward_query_off_config);

  // TODO: Validate that the response is addressed to this client
  sendQueryFromClient("10.0.0.1:1000", "hello");

  ASSERT_TRUE(response_parser_.parseDnsObject(response_ptr));

  ASSERT_EQ(0, response_parser_.getQueries().size());
  ASSERT_EQ(0, response_parser_.getAnswers().size());
  ASSERT_EQ(3, response_parser_.getQueryResponseCode());
}

TEST_F(DnsFilterTest, SingleTypeAQuery) {
  InSequence s;

  setup(forward_query_off_config);

  const std::string query =
      buildQueryForDomain("www.foo3.com", DnsRecordType::A, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  sendQueryFromClient("10.0.0.1:1000", query);

  ASSERT_TRUE(response_parser_.parseDnsObject(response_ptr));

  ASSERT_EQ(1, response_parser_.getQueries().size());
  ASSERT_EQ(1, response_parser_.getAnswers().size());
  ASSERT_EQ(0, response_parser_.getQueryResponseCode());

  // Verify the address returned
  const auto answer_iter = response_parser_.getAnswers().begin();
  const DnsAnswerRecordPtr& answer = *answer_iter;

  std::list<std::string> expected{"10.0.3.1"};
  verifyAddress(expected, answer);
}

TEST_F(DnsFilterTest, SingleTypeAQueryFail) {
  InSequence s;

  setup(forward_query_off_config);

  const std::string query =
      buildQueryForDomain("www.foo2.com", DnsRecordType::A, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  sendQueryFromClient("10.0.0.1:1000", query);

  ASSERT_TRUE(response_parser_.parseDnsObject(response_ptr));

  ASSERT_EQ(1, response_parser_.getQueries().size());
  ASSERT_EQ(0, response_parser_.getAnswers().size());
  ASSERT_EQ(3, response_parser_.getQueryResponseCode());
}

TEST_F(DnsFilterTest, SingleTypeAAAAQuery) {
  InSequence s;

  setup(forward_query_off_config);

  const std::string query =
      buildQueryForDomain("www.foo2.com", DnsRecordType::AAAA, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  sendQueryFromClient("10.0.0.1:1000", query);

  response_parser_.parseDnsObject(response_ptr);

  ASSERT_EQ(1, response_parser_.getQueries().size());
  ASSERT_EQ(1, response_parser_.getAnswers().size());
  ASSERT_EQ(0, response_parser_.getQueryResponseCode());

  // Verify the address returned
  const auto answer_iter = response_parser_.getAnswers().begin();
  const DnsAnswerRecordPtr& answer = *answer_iter;

  std::list<std::string> expected{"2001:8a:c1::2800:7"};
  verifyAddress(expected, answer);
}

TEST_F(DnsFilterTest, ExternalResolutionSingleAddress) {

  InSequence s;

  const std::string expected_address("130.207.244.251");
  const std::string query_host("www.foobaz.com");
  setup(forward_query_on_config);

  // Verify that we are calling the resolver with the expected name
  Network::DnsResolver::ResolveCb resolve_cb;
  EXPECT_CALL(*resolver_, resolve(query_host, _, _))
      .WillOnce(DoAll(SaveArg<2>(&resolve_cb), Return(&resolver_->active_query_)));

  const std::string query = buildQueryForDomain(query_host, DnsRecordType::A, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  // Send a query to for a name not in our configuration
  sendQueryFromClient("10.0.0.1:1000", query);

  // Execute resolve callback
  resolve_cb(Network::DnsResolver::ResolutionStatus::Success,
             TestUtility::makeDnsResponse({expected_address}));

  // parse the result
  response_parser_.parseDnsObject(response_ptr);

  ASSERT_EQ(1, response_parser_.getQueries().size());
  ASSERT_EQ(1, response_parser_.getAnswers().size());
  ASSERT_EQ(0, response_parser_.getQueryResponseCode());
  const auto answer_iter = response_parser_.getAnswers().begin();
  const DnsAnswerRecordPtr& answer = *answer_iter;

  std::list<std::string> expected{expected_address};
  verifyAddress(expected, answer);

  EXPECT_TRUE(Mock::VerifyAndClearExpectations(resolver_.get()));
}

TEST_F(DnsFilterTest, ExternalResolutionMultipleAddresses) {

  InSequence s;

  const std::list<std::string> expected_address{"130.207.244.251", "130.207.244.252",
                                                "130.207.244.253", "130.207.244.254"};
  const std::string query_host("www.foobaz.com");
  setup(forward_query_on_config);

  // Verify that we are calling the resolver with the expected name
  Network::DnsResolver::ResolveCb resolve_cb;
  EXPECT_CALL(*resolver_, resolve(query_host, _, _))
      .WillOnce(DoAll(SaveArg<2>(&resolve_cb), Return(&resolver_->active_query_)));

  const std::string query = buildQueryForDomain(query_host, DnsRecordType::A, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  // Send a query to for a name not in our configuration
  sendQueryFromClient("10.0.0.1:1000", query);

  // Execute resolve callback
  resolve_cb(Network::DnsResolver::ResolutionStatus::Success,
             TestUtility::makeDnsResponse({expected_address}));

  // parse the result
  response_parser_.parseDnsObject(response_ptr);

  ASSERT_LT(response_ptr->length(), MAX_UDP_DNS_SIZE);
  ASSERT_EQ(1, response_parser_.getQueries().size());
  ASSERT_EQ(expected_address.size(), response_parser_.getAnswers().size());
  ASSERT_EQ(0, response_parser_.getQueryResponseCode());
  for (const auto& answer : response_parser_.getAnswers()) {
    verifyAddress(expected_address, answer);
  }

  EXPECT_TRUE(Mock::VerifyAndClearExpectations(resolver_.get()));
}

TEST_F(DnsFilterTest, ExternalResolutionNoAddressReturned) {

  InSequence s;

  const std::string expected_address("130.207.244.251");
  const std::string query_host("www.foobaz.com");
  setup(forward_query_on_config);

  // Verify that we are calling the resolver with the expected name
  Network::DnsResolver::ResolveCb resolve_cb;
  EXPECT_CALL(*resolver_, resolve(query_host, _, _))
      .WillOnce(DoAll(SaveArg<2>(&resolve_cb), Return(&resolver_->active_query_)));

  const std::string query = buildQueryForDomain(query_host, DnsRecordType::A, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  // Send a query to for a name not in our configuration
  sendQueryFromClient("10.0.0.1:1000", query);

  // Execute resolve callback
  resolve_cb(Network::DnsResolver::ResolutionStatus::Success, TestUtility::makeDnsResponse({}));

  // parse the result
  response_parser_.parseDnsObject(response_ptr);

  ASSERT_EQ(1, response_parser_.getQueries().size());
  ASSERT_EQ(0, response_parser_.getAnswers().size());
  ASSERT_EQ(3, response_parser_.getQueryResponseCode());

  EXPECT_TRUE(Mock::VerifyAndClearExpectations(resolver_.get()));
}

} // namespace
} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
