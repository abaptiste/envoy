<<<<<<< HEAD
#include "envoy/extensions/filter/udp/dns_filter/v3alpha/dns_filter.pb.h"
#include "envoy/extensions/filter/udp/dns_filter/v3alpha/dns_filter.pb.validate.h"

#include "common/common/logger.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/server/mocks.h"
#include "test/test_common/environment.h"
#include "test/test_common/simulated_time_system.h"

#include "dns_filter_test_utils.h"
=======
#include "envoy/config/filter/udp/dns_filter/v2alpha/dns_filter.pb.h"
#include "envoy/config/filter/udp/dns_filter/v2alpha/dns_filter.pb.validate.h"

#include "common/common/logger.h"

#include "extensions/filters/udp/dns_filter/dns_filter.h"

#include "test/mocks/server/mocks.h"
#include "test/test_common/environment.h"

>>>>>>> master
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::AtLeast;
<<<<<<< HEAD
using testing::ByMove;
using testing::InSequence;
using testing::Mock;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;
=======
using testing::InSequence;
using testing::ReturnRef;
>>>>>>> master

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {
namespace {

<<<<<<< HEAD
Api::IoCallUint64Result makeNoError(uint64_t rc) {
  auto no_error = Api::ioCallUint64ResultNoError();
  no_error.rc_ = rc;
  return no_error;
}

class DnsFilterTest : public testing::Test {
public:
  DnsFilterTest()
      : listener_address_(Network::Utility::parseInternetAddressAndPort("127.0.2.1:5353")),
        api_(Api::createApiForTest()) {
    // TODO: Consume the log setting from the command line
    // Logger::Registry::setLogLevel(TestEnvironment::getOptions().logLevel());
    Logger::Registry::setLogLevel(spdlog::level::trace);

    udp_response_.addresses_.local_ = listener_address_;
    udp_response_.addresses_.peer_ = listener_address_;
    udp_response_.buffer_ = std::make_unique<Buffer::OwnedImpl>();

    setupResponseParser();
    EXPECT_CALL(callbacks_, udpListener()).Times(AtLeast(0));
    EXPECT_CALL(callbacks_.udp_listener_, send(_))
        .WillRepeatedly(
            Invoke([this](const Network::UdpSendData& send_data) -> Api::IoCallUint64Result {
              udp_response_.buffer_->move(send_data.buffer_);
              return makeNoError(udp_response_.buffer_->length());
            }));

    EXPECT_CALL(callbacks_.udp_listener_, dispatcher()).WillRepeatedly(ReturnRef(dispatcher_));
  }

  ~DnsFilterTest() { EXPECT_CALL(callbacks_.udp_listener_, onDestroy()); }

  void setupResponseParser() {
    histogram_.unit_ = Stats::Histogram::Unit::Milliseconds;
    response_parser_ = std::make_unique<DnsMessageParser>(api_->timeSource(), histogram_);
  }

  void setup(const std::string& yaml) {
    envoy::extensions::filter::udp::dns_filter::v3alpha::DnsFilterConfig config;
    TestUtility::loadFromYamlAndValidate(yaml, config);
    auto store = stats_store_.createScope("dns_scope");
    EXPECT_CALL(listener_factory_, scope()).WillOnce(ReturnRef(*store));
    EXPECT_CALL(listener_factory_, dispatcher()).Times(AtLeast(0));
    EXPECT_CALL(listener_factory_, clusterManager()).Times(AtLeast(0));
    EXPECT_CALL(listener_factory_, api()).WillOnce(ReturnRef(*api_));

    resolver_ = std::make_shared<Network::MockDnsResolver>();
    EXPECT_CALL(dispatcher_, createDnsResolver(_, _)).WillOnce(Return(resolver_));
    EXPECT_CALL(dispatcher_, createTimer_(_)).Times(AtLeast(0));
=======
class DnsFilterTest : public testing::Test {
public:
  DnsFilterTest()
      : listener_address_(Network::Utility::parseInternetAddressAndPort("127.0.2.1:5353")) {

    Logger::Registry::setLogLevel(spdlog::level::info);

    EXPECT_CALL(callbacks_, udpListener()).Times(AtLeast(0));
  }

  ~DnsFilterTest() override { EXPECT_CALL(callbacks_.udp_listener_, onDestroy()); }

  void setup(const std::string& yaml) {
    envoy::config::filter::udp::dns_filter::v2alpha::DnsFilterConfig config;
    TestUtility::loadFromYamlAndValidate(yaml, config);
    auto store = stats_store_.createScope("dns_scope");
    EXPECT_CALL(listener_factory_, scope()).WillOnce(ReturnRef(*store));
>>>>>>> master

    config_ = std::make_shared<DnsFilterEnvoyConfig>(listener_factory_, config);
    filter_ = std::make_unique<DnsFilter>(callbacks_, config_);
  }

<<<<<<< HEAD
  void sendQueryFromClient(const std::string& peer_address, const std::string& buffer) {
    Network::UdpRecvData data;
    data.addresses_.peer_ = Network::Utility::parseInternetAddressAndPort(peer_address);
    data.addresses_.local_ = listener_address_;
    data.buffer_ = std::make_unique<Buffer::OwnedImpl>(buffer);
    data.receive_time_ = MonotonicTime(std::chrono::seconds(0));
    filter_->onData(data);
  }

  const Network::Address::InstanceConstSharedPtr listener_address_;
  Server::Configuration::MockListenerFactoryContext listener_factory_;
  NiceMock<Stats::MockHistogram> histogram_;
=======
  const Network::Address::InstanceConstSharedPtr listener_address_;
  Server::Configuration::MockListenerFactoryContext listener_factory_;
  DnsFilterEnvoyConfigSharedPtr config_;
>>>>>>> master

  std::unique_ptr<DnsFilter> filter_;
  Network::MockUdpReadFilterCallbacks callbacks_;
  Stats::IsolatedStoreImpl stats_store_;
<<<<<<< HEAD
  Network::UdpRecvData udp_response_;

  Api::ApiPtr api_;
  NiceMock<Filesystem::MockInstance> file_system_;
  DnsFilterEnvoyConfigSharedPtr config_;
  std::unique_ptr<DnsMessageParser> response_parser_;

  Event::MockDispatcher dispatcher_;
  std::shared_ptr<Network::MockDnsResolver> resolver_;

  DnsQueryContextPtr query_ctx_;

  // This config has external resolution disabled and is used to verify local lookups. With
  // external resolution disabled, it eliminates having to setup mocks for the resolver callbacks in
  // each test.
  const std::string forward_query_off_config = R"EOF(
stat_prefix: "my_prefix"
client_config:
  forward_query: false
  resolver_timeout: 5s
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
          - 2001:8a:c1::2800:8
          - 2001:8a:c1::2800:9
    - name: "www.foo3.com"
      endpoint:
        address_list:
          address:
          - 10.0.3.1
  )EOF";

  // This config has external resolution enabled. Each test must setup the mock to save and execute
  // the resolver callback
  const std::string forward_query_on_config = R"EOF(
stat_prefix: "my_prefix"
client_config:
  forward_query: true
  resolver_timeout: 5s
  upstream_resolvers:
    - "1.1.1.1"
    - "8.8.8.8"
    - "8.8.4.4"
=======
  Runtime::RandomGeneratorImpl rng_;

  const std::string config_yaml = R"EOF(
stat_prefix: "my_prefix"
>>>>>>> master
server_config:
  inline_dns_table:
    external_retry_count: 3
    virtual_domains:
      - name: "www.foo1.com"
        endpoint:
          address_list:
            address:
              - 10.0.0.1
<<<<<<< HEAD
  )EOF";

  const std::string external_dns_table_config = R"EOF(
stat_prefix: "my_prefix"
client_config:
  forward_query: true
  resolver_timeout: 5s
  upstream_resolvers:
  - "1.1.1.1"
server_config:
  external_dns_table:
    filename: {}
)EOF";

  const std::string external_dns_table_json = R"EOF(
external_retry_count: 3,
known_suffixes: [ { suffix: "com" } ],
virtual_domains: [
  {
    name: "www.external_foo1.com",
    endpoint: { address_list: { address: [ "10.0.0.1", "10.0.0.2" ] } }
  },
  {
    name: "www.external_foo2.com",
    endpoint: { address_list: { address: [ "2001:8a:c1::2800:7" ] } }
  },
  {
    name: "www.external_foo3.com",
    endpoint: { address_list: { address: [ "10.0.3.1" ] } }
  }
]
)EOF";
};

TEST_F(DnsFilterTest, InvalidQuery) {
  InSequence s;

  setup(forward_query_off_config);

  sendQueryFromClient("10.0.0.1:1000", "hello");

  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_FALSE(query_ctx_->parse_status_);

  ASSERT_EQ(DnsResponseCode::FormatError, response_parser_->getQueryResponseCode());
  ASSERT_EQ(0, query_ctx_->answers_.size());

  // Validate stats
  ASSERT_EQ(0, config_->stats().a_record_queries_.value());
  ASSERT_EQ(1, config_->stats().downstream_rx_invalid_queries_.value());
  ASSERT_TRUE(config_->stats().downstream_rx_bytes_.used());
  ASSERT_TRUE(config_->stats().downstream_tx_bytes_.used());
}

TEST_F(DnsFilterTest, SingleTypeAQuery) {
  InSequence s;

  setup(forward_query_off_config);

  const std::string domain("www.foo3.com");
  const std::string query =
      Utils::buildQueryForDomain(domain, DnsRecordType::A, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  sendQueryFromClient("10.0.0.1:1000", query);

  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_TRUE(query_ctx_->parse_status_);

  ASSERT_EQ(DnsResponseCode::NoError, response_parser_->getQueryResponseCode());
  ASSERT_EQ(1, query_ctx_->answers_.size());

  // Verify that we have an answer record for the queried domain

  const DnsAnswerRecordPtr& answer = query_ctx_->answers_.find(domain)->second;

  // Verify the address returned
  const std::list<std::string> expected{"10.0.3.1"};
  Utils::verifyAddress(expected, answer);

  // Validate stats
  ASSERT_EQ(1, config_->stats().downstream_rx_queries_.value());
  ASSERT_EQ(1, config_->stats().known_domain_queries_.value());
  ASSERT_EQ(1, config_->stats().local_a_record_answers_.value());
  ASSERT_EQ(1, config_->stats().a_record_queries_.value());
  // ASSERT_EQ(query.size(), config_->stats().downstream_rx_bytes_.value());
}

TEST_F(DnsFilterTest, RepeatedTypeAQuery) {
  InSequence s;

  setup(forward_query_off_config);

  const std::string domain("www.foo3.com");
  const size_t count = 5;
  size_t total_query_bytes = 0;

  for (size_t i = 0; i < count; i++) {
    const std::string query =
        Utils::buildQueryForDomain(domain, DnsRecordType::A, DnsRecordClass::IN);
    total_query_bytes += query.size();
    ASSERT_FALSE(query.empty());
    sendQueryFromClient("10.0.0.1:1000", query);

    query_ctx_ = response_parser_->createQueryContext(udp_response_);
    ASSERT_TRUE(query_ctx_->parse_status_);

    ASSERT_EQ(DnsResponseCode::NoError, response_parser_->getQueryResponseCode());
    ASSERT_EQ(1, query_ctx_->answers_.size());

    // Verify that we have an answer record for the queried domain
    const DnsAnswerRecordPtr& answer = query_ctx_->answers_.find(domain)->second;

    // Verify the address returned
    std::list<std::string> expected{"10.0.3.1"};
    Utils::verifyAddress(expected, answer);
  }

  // Validate stats
  ASSERT_EQ(count, config_->stats().downstream_rx_queries_.value());
  ASSERT_EQ(count, config_->stats().known_domain_queries_.value());
  ASSERT_EQ(count, config_->stats().local_a_record_answers_.value());
  ASSERT_EQ(count, config_->stats().a_record_queries_.value());
}

TEST_F(DnsFilterTest, LocalTypeAQueryFail) {
  InSequence s;

  setup(forward_query_off_config);

  const std::string query =
      Utils::buildQueryForDomain("www.foo2.com", DnsRecordType::A, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  sendQueryFromClient("10.0.0.1:1000", query);
  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_TRUE(query_ctx_->parse_status_);

  ASSERT_EQ(3, response_parser_->getQueryResponseCode());
  ASSERT_EQ(0, query_ctx_->answers_.size());

  // Validate stats
  ASSERT_EQ(1, config_->stats().downstream_rx_queries_.value());
  ASSERT_EQ(1, config_->stats().known_domain_queries_.value());
  ASSERT_EQ(3, config_->stats().local_a_record_answers_.value());
  ASSERT_EQ(1, config_->stats().a_record_queries_.value());
  ASSERT_EQ(1, config_->stats().unanswered_queries_.value());
}

TEST_F(DnsFilterTest, LocalTypeAAAAQuery) {
  InSequence s;

  setup(forward_query_off_config);

  std::list<std::string> expected{"2001:8a:c1::2800:7", "2001:8a:c1::2800:8", "2001:8a:c1::2800:9"};
  const std::string domain("www.foo2.com");
  const std::string query =
      Utils::buildQueryForDomain(domain, DnsRecordType::AAAA, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  sendQueryFromClient("10.0.0.1:1000", query);
  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_TRUE(query_ctx_->parse_status_);

  ASSERT_EQ(DnsResponseCode::NoError, response_parser_->getQueryResponseCode());
  ASSERT_EQ(expected.size(), query_ctx_->answers_.size());

  // Verify the address returned
  for (const auto& answer : query_ctx_->answers_) {
    ASSERT_EQ(answer.first, domain);
    Utils::verifyAddress(expected, answer.second);
  }

  // Validate stats
  ASSERT_EQ(1, config_->stats().downstream_rx_queries_.value());
  ASSERT_EQ(1, config_->stats().known_domain_queries_.value());
  ASSERT_EQ(3, config_->stats().local_aaaa_record_answers_.value());
  ASSERT_EQ(1, config_->stats().aaaa_record_queries_.value());
}

TEST_F(DnsFilterTest, ExternalResolutionSingleAddress) {

  InSequence s;

  const std::string expected_address("130.207.244.251");
  const std::string domain("www.foobaz.com");
  setup(forward_query_on_config);

  // Verify that we are calling the resolver with the expected name
  Network::DnsResolver::ResolveCb resolve_cb;
  EXPECT_CALL(*resolver_, resolve(domain, _, _))
      .WillOnce(DoAll(SaveArg<2>(&resolve_cb), Return(&resolver_->active_query_)));

  const std::string query =
      Utils::buildQueryForDomain(domain, DnsRecordType::A, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  // Send a query to for a name not in our configuration
  sendQueryFromClient("10.0.0.1:1000", query);

  // Execute resolve callback
  resolve_cb(Network::DnsResolver::ResolutionStatus::Success,
             TestUtility::makeDnsResponse({expected_address}));

  // parse the result
  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_TRUE(query_ctx_->parse_status_);

  ASSERT_EQ(DnsResponseCode::NoError, response_parser_->getQueryResponseCode());
  ASSERT_EQ(1, query_ctx_->answers_.size());

  std::list<std::string> expected{expected_address};
  for (const auto& answer : query_ctx_->answers_) {
    ASSERT_EQ(answer.first, domain);
    Utils::verifyAddress(expected, answer.second);
  }

  // Validate stats
  ASSERT_EQ(1, config_->stats().downstream_rx_queries_.value());
  ASSERT_EQ(1, config_->stats().external_a_record_queries_.value());
  ASSERT_EQ(1, config_->stats().external_a_record_answers_.value());
  ASSERT_EQ(1, config_->stats().a_record_queries_.value());
  ASSERT_EQ(0, config_->stats().aaaa_record_queries_.value());
  ASSERT_EQ(0, config_->stats().unanswered_queries_.value());

  EXPECT_TRUE(Mock::VerifyAndClearExpectations(resolver_.get()));
}

TEST_F(DnsFilterTest, ExternalResolutionMultipleAddresses) {

  InSequence s;

  const std::list<std::string> expected_address{"130.207.244.251", "130.207.244.252",
                                                "130.207.244.253", "130.207.244.254"};
  const std::string domain("www.foobaz.com");
  setup(forward_query_on_config);

  // Verify that we are calling the resolver with the expected name
  Network::DnsResolver::ResolveCb resolve_cb;
  EXPECT_CALL(*resolver_, resolve(domain, _, _))
      .WillOnce(DoAll(SaveArg<2>(&resolve_cb), Return(&resolver_->active_query_)));

  const std::string query =
      Utils::buildQueryForDomain(domain, DnsRecordType::A, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  // Send a query to for a name not in our configuration
  sendQueryFromClient("10.0.0.1:1000", query);

  // Execute resolve callback
  resolve_cb(Network::DnsResolver::ResolutionStatus::Success,
             TestUtility::makeDnsResponse({expected_address}));

  // parse the result
  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_TRUE(query_ctx_->parse_status_);

  ASSERT_EQ(DnsResponseCode::NoError, response_parser_->getQueryResponseCode());
  ASSERT_EQ(expected_address.size(), query_ctx_->answers_.size());

  ASSERT_LT(udp_response_.buffer_->length(), Utils::MAX_UDP_DNS_SIZE);

  for (const auto& answer : query_ctx_->answers_) {
    ASSERT_EQ(answer.first, domain);
    Utils::verifyAddress(expected_address, answer.second);
  }

  // Validate stats
  ASSERT_EQ(1, config_->stats().downstream_rx_queries_.value());
  ASSERT_EQ(1, config_->stats().external_a_record_queries_.value());
  ASSERT_EQ(expected_address.size(), config_->stats().external_a_record_answers_.value());
  ASSERT_EQ(1, config_->stats().a_record_queries_.value());
  ASSERT_EQ(0, config_->stats().aaaa_record_queries_.value());
  ASSERT_EQ(0, config_->stats().unanswered_queries_.value());

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

  const std::string query =
      Utils::buildQueryForDomain(query_host, DnsRecordType::A, DnsRecordClass::IN);
  ASSERT_FALSE(query.empty());

  // Send a query to for a name not in our configuration
  sendQueryFromClient("10.0.0.1:1000", query);

  // Execute resolve callback
  resolve_cb(Network::DnsResolver::ResolutionStatus::Success, TestUtility::makeDnsResponse({}));

  // parse the result
  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_TRUE(query_ctx_->parse_status_);
  ASSERT_EQ(DnsResponseCode::NameError, response_parser_->getQueryResponseCode());
  ASSERT_EQ(0, query_ctx_->answers_.size());

  // Validate stats
  ASSERT_EQ(1, config_->stats().downstream_rx_queries_.value());
  ASSERT_EQ(1, config_->stats().external_a_record_queries_.value());
  ASSERT_EQ(0, config_->stats().external_a_record_answers_.value());
  ASSERT_EQ(1, config_->stats().a_record_queries_.value());
  ASSERT_EQ(0, config_->stats().aaaa_record_queries_.value());
  ASSERT_EQ(0, config_->stats().unanswered_queries_.value());

  EXPECT_TRUE(Mock::VerifyAndClearExpectations(resolver_.get()));
}

TEST_F(DnsFilterTest, ConsumeExternalTableTest) {

  InSequence s;

  std::string temp_path =
      TestEnvironment::writeStringToFileForTest("dns_table.json", external_dns_table_json);
  std::string config_to_use = fmt::format(external_dns_table_config, temp_path);

  setup(config_to_use);

  const std::string domain("www.external_foo1.com");
  const std::string query =
      Utils::buildQueryForDomain(domain, DnsRecordType::A, DnsRecordClass::IN);

  sendQueryFromClient("10.0.0.1:1000", query);

  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_TRUE(query_ctx_->parse_status_);
  ASSERT_EQ(DnsResponseCode::NoError, response_parser_->getQueryResponseCode());
  ASSERT_EQ(2, query_ctx_->answers_.size());

  // Verify the address returned
  const std::list<std::string> expected{"10.0.0.1", "10.0.0.2"};
  for (const auto& answer : query_ctx_->answers_) {
    ASSERT_EQ(answer.first, domain);
    Utils::verifyAddress(expected, answer.second);
  }

  // Validate stats
  ASSERT_EQ(1, config_->stats().downstream_rx_queries_.value());
  ASSERT_EQ(1, config_->stats().known_domain_queries_.value());
  ASSERT_EQ(2, config_->stats().local_a_record_answers_.value());
  ASSERT_EQ(1, config_->stats().a_record_queries_.value());
}

TEST_F(DnsFilterTest, RawBufferTest) {
  InSequence s;

  setup(forward_query_off_config);
  const std::string domain("www.foo3.com");

  char dns_request[] = {
      0x36, 0x6b,                               // Transaction ID
      0x01, 0x20,                               // Flags
      0x00, 0x01,                               // Questions
      0x00, 0x00,                               // Answers
      0x00, 0x00,                               // Authority RRs
      0x00, 0x00,                               // Additional RRs
      0x03, 0x77, 0x77, 0x77, 0x04, 0x66, 0x6f, // Query record for
      0x6f, 0x33, 0x03, 0x63, 0x6f, 0x6d, 0x00, // www.foo3.com
      0x00, 0x01,                               // Query Type - A
      0x00, 0x01,                               // Query Class - IN
  };

  const size_t count = sizeof(dns_request) / sizeof(dns_request[0]);
  const std::string query = Utils::buildQueryFromBytes(dns_request, count);

  sendQueryFromClient("10.0.0.1:1000", query);

  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_TRUE(query_ctx_->parse_status_);
  ASSERT_EQ(DnsResponseCode::NoError, response_parser_->getQueryResponseCode());
  ASSERT_EQ(0, response_parser_->getQueryResponseCode());
  ASSERT_EQ(1, query_ctx_->answers_.size());

  // Verify that we have an answer record for the queried domain
  const DnsAnswerRecordPtr& answer = query_ctx_->answers_.find(domain)->second;

  // Verify the address returned
  std::list<std::string> expected{"10.0.3.1"};
  Utils::verifyAddress(expected, answer);
}

TEST_F(DnsFilterTest, InvalidQueryNameTest) {
  InSequence s;

  setup(forward_query_off_config);

  // In this buffer the name segment sizes are incorrect. We should fail parsing
  char dns_request[] = {
      0x36, 0x6c,                               // Transaction ID
      0x01, 0x20,                               // Flags
      0x00, 0x01,                               // Questions
      0x00, 0x00,                               // Answers
      0x00, 0x00,                               // Authority RRs
      0x00, 0x00,                               // Additional RRs
      0x02, 0x77, 0x77, 0x77, 0x03, 0x66, 0x6f, // Query record for
      0x6f, 0x33, 0x01, 0x63, 0x6f, 0x6d, 0x00, // www.foo3.com
      0x00, 0x01,                               // Query Type - A
      0x00, 0x01,                               // Query Class - IN
  };

  const size_t count = sizeof(dns_request) / sizeof(dns_request[0]);
  const std::string query = Utils::buildQueryFromBytes(dns_request, count);

  sendQueryFromClient("10.0.0.1:1000", query);

  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_FALSE(query_ctx_->parse_status_);
  ASSERT_EQ(DnsResponseCode::FormatError, response_parser_->getQueryResponseCode());

  ASSERT_EQ(1, config_->stats().downstream_rx_invalid_queries_.value());
}

TEST_F(DnsFilterTest, MultipleQueryCountTest) {
  InSequence s;

  setup(forward_query_off_config);

  // In this buffer we have 2 queries for two different domains. This is a rare case
  // and serves to validate that we handle the protocol correctly.
  char dns_request[] = {
      0x36, 0x6d,                               // Transaction ID
      0x01, 0x20,                               // Flags
      0x00, 0x02,                               // Questions
      0x00, 0x00,                               // Answers
      0x00, 0x00,                               // Authority RRs
      0x00, 0x00,                               // Additional RRs
      0x03, 0x77, 0x77, 0x77, 0x04, 0x66, 0x6f, // begin query record for
      0x6f, 0x33, 0x03, 0x63, 0x6f, 0x6d, 0x00, // www.foo3.com
      0x00, 0x01,                               // Query Type - A
      0x00, 0x01,                               // Query Class - IN
      0x03, 0x77, 0x77, 0x77, 0x04, 0x66, 0x6f, // Query record for
      0x6f, 0x31, 0x03, 0x63, 0x6f, 0x6d, 0x00, // www.foo1.com
      0x00, 0x01,                               // Query Type - A
      0x00, 0x01,                               // Query Class - IN
  };

  const size_t count = sizeof(dns_request) / sizeof(dns_request[0]);
  const std::string query = Utils::buildQueryFromBytes(dns_request, count);

  sendQueryFromClient("10.0.0.1:1000", query);

  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_TRUE(query_ctx_->parse_status_);
  ASSERT_EQ(DnsResponseCode::NoError, response_parser_->getQueryResponseCode());

  ASSERT_EQ(0, config_->stats().downstream_rx_invalid_queries_.value());
  ASSERT_EQ(2, config_->stats().a_record_queries_.value());
  ASSERT_EQ(3, query_ctx_->answers_.size());

  // Verify that the answers contain an entry for each domain
  for (const auto& answer : query_ctx_->answers_) {
    if (answer.first == "www.foo1.com") {
      Utils::verifyAddress({"10.0.0.1", "10.0.0.2"}, answer.second);
    } else if (answer.first == "www.foo3.com") {
      Utils::verifyAddress({"10.0.3.1"}, answer.second);
    } else {
      FAIL() << "Unexpected domain in DNS response: " << answer.first;
    }
  }
}

TEST_F(DnsFilterTest, InvalidQueryCountTest) {
  InSequence s;

  setup(forward_query_off_config);

  // In this buffer the Questions count is incorrect. We will abort parsing and return a response
  // to the client.
  char dns_request[] = {
      0x36, 0x6e,                               // Transaction ID
      0x01, 0x20,                               // Flags
      0x00, 0x0a,                               // Questions
      0x00, 0x00,                               // Answers
      0x00, 0x00,                               // Authority RRs
      0x00, 0x00,                               // Additional RRs
      0x03, 0x77, 0x77, 0x77, 0x04, 0x66, 0x6f, // Query record for
      0x6f, 0x33, 0x03, 0x63, 0x6f, 0x6d, 0x00, // www.foo3.com
      0x00, 0x01,                               // Query Type - A
      0x00, 0x01,                               // Query Class - IN
  };

  const size_t count = sizeof(dns_request) / sizeof(dns_request[0]);
  const std::string query = Utils::buildQueryFromBytes(dns_request, count);

  sendQueryFromClient("10.0.0.1:1000", query);

  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_TRUE(query_ctx_->parse_status_);
  ASSERT_EQ(DnsResponseCode::FormatError, response_parser_->getQueryResponseCode());

  ASSERT_EQ(1, config_->stats().a_record_queries_.value());
  ASSERT_EQ(1, config_->stats().downstream_rx_invalid_queries_.value());
  ASSERT_EQ(0, query_ctx_->answers_.size());
}

TEST_F(DnsFilterTest, InvalidQueryCountTest2) {
  InSequence s;

  setup(forward_query_off_config);

  // In this buffer the Questions count is zero. This is an invalid query and is handled as such.
  char dns_request[] = {
      0x36, 0x6f,                               // Transaction ID
      0x01, 0x20,                               // Flags
      0x00, 0x00,                               // Questions
      0x00, 0x00,                               // Answers
      0x00, 0x00,                               // Authority RRs
      0x00, 0x00,                               // Additional RRs
      0x03, 0x77, 0x77, 0x77, 0x04, 0x66, 0x6f, // Query record for
      0x6f, 0x33, 0x03, 0x63, 0x6f, 0x6d, 0x00, // www.foo3.com
      0x00, 0x01,                               // Query Type - A
      0x00, 0x01,                               // Query Class - IN
  };

  const size_t count = sizeof(dns_request) / sizeof(dns_request[0]);
  const std::string query = Utils::buildQueryFromBytes(dns_request, count);

  sendQueryFromClient("10.0.0.1:1000", query);

  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_FALSE(query_ctx_->parse_status_);
  ASSERT_EQ(DnsResponseCode::FormatError, response_parser_->getQueryResponseCode());

  ASSERT_EQ(0, config_->stats().a_record_queries_.value());
  ASSERT_EQ(1, config_->stats().downstream_rx_invalid_queries_.value());
}

TEST_F(DnsFilterTest, NotImplementedQueryTest) {
  InSequence s;

  setup(forward_query_off_config);

  // In this buffer the Questions count is zero. This is an invalid query and is handled as such.
  char dns_request[] = {
      0x36, 0x70,                               // Transaction ID
      0x01, 0x20,                               // Flags
      0x00, 0x01,                               // Questions
      0x00, 0x00,                               // Answers
      0x00, 0x00,                               // Authority RRs
      0x00, 0x00,                               // Additional RRs
      0x03, 0x77, 0x77, 0x77, 0x04, 0x66, 0x6f, // Query record for
      0x6f, 0x33, 0x03, 0x63, 0x6f, 0x6d, 0x00, // www.foo3.com
      0x00, 0x05,                               // Query Type - CNAME
      0x00, 0x01,                               // Query Class - IN
  };

  const size_t count = sizeof(dns_request) / sizeof(dns_request[0]);
  const std::string query = Utils::buildQueryFromBytes(dns_request, count);

  sendQueryFromClient("10.0.0.1:1000", query);

  query_ctx_ = response_parser_->createQueryContext(udp_response_);
  ASSERT_TRUE(query_ctx_->parse_status_);
  ASSERT_EQ(DnsResponseCode::NotImplemented, response_parser_->getQueryResponseCode());

  ASSERT_EQ(0, config_->stats().a_record_queries_.value());
  ASSERT_EQ(0, config_->stats().downstream_rx_invalid_queries_.value());
=======
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
};

TEST_F(DnsFilterTest, TestConfig) {
  InSequence s;

  setup(config_yaml);
>>>>>>> master
}

} // namespace
} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
