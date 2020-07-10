#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/common/platform.h"
#include "envoy/network/address.h"
#include "envoy/network/dns.h"
#include "envoy/network/listener.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/empty_string.h"
#include "common/runtime/runtime_impl.h"
#include "common/stats/timespan_impl.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

constexpr uint16_t DNS_RECORD_CLASS_IN = 1;
constexpr uint16_t DNS_RECORD_TYPE_A = 1;
constexpr uint16_t DNS_RECORD_TYPE_NS = 2;
constexpr uint16_t DNS_RECORD_TYPE_AAAA = 28;
constexpr uint16_t DNS_RECORD_TYPE_SRV = 33;

constexpr uint16_t DNS_RESPONSE_CODE_NO_ERROR = 0;
constexpr uint16_t DNS_RESPONSE_CODE_FORMAT_ERROR = 1;
constexpr uint16_t DNS_RESPONSE_CODE_NAME_ERROR = 3;
constexpr uint16_t DNS_RESPONSE_CODE_NOT_IMPLEMENTED = 4;

/**
 * BaseDnsRecord contains the fields and functions common to both query and answer records.
 */
class BaseDnsRecord {
public:
  BaseDnsRecord(const std::string& rec_name, const uint16_t rec_type, const uint16_t rec_class)
      : name_(rec_name), type_(rec_type), class_(rec_class) {}
  virtual ~BaseDnsRecord() = default;
  bool serializeName(Buffer::OwnedImpl& output);
  virtual bool serialize(Buffer::OwnedImpl& output) PURE;

  const std::string name_;
  const uint16_t type_;
  const uint16_t class_;

protected:
  bool serializeSpecificName(Buffer::OwnedImpl& output, const std::string& name);
};

/**
 * DnsQueryRecord represents a query record parsed from a DNS request from a client. Each query
 * record contains the domain requested and the flags dictating the type of record that is sought.
 */
class DnsQueryRecord : public BaseDnsRecord {
public:
  DnsQueryRecord(const std::string& rec_name, const uint16_t rec_type, const uint16_t rec_class)
      : BaseDnsRecord(rec_name, rec_type, rec_class) {}
  bool serialize(Buffer::OwnedImpl& output) override;

  std::unique_ptr<Stats::HistogramCompletableTimespanImpl> query_time_ms_;
};

using DnsQueryRecordPtr = std::unique_ptr<DnsQueryRecord>;
using DnsQueryPtrVec = std::vector<DnsQueryRecordPtr>;
using AddressConstPtrVec = std::vector<Network::Address::InstanceConstSharedPtr>;

/**
 * DnsAnswerRecord represents a single answer record for a name that is to be serialized and sent to
 * a client. This class differs from the BaseDnsRecord and DnsQueryRecord because it contains
 * additional fields for the TTL and address.
 */
class DnsAnswerRecord : public BaseDnsRecord {
public:
  DnsAnswerRecord(const std::string& query_name, const uint16_t rec_type, const uint16_t rec_class,
                  const std::chrono::seconds ttl, Network::Address::InstanceConstSharedPtr ipaddr)
      : BaseDnsRecord(query_name, rec_type, rec_class), ttl_(ttl), ip_addr_(ipaddr) {}
  bool serialize(Buffer::OwnedImpl& output) override;

  const std::chrono::seconds ttl_;
  const Network::Address::InstanceConstSharedPtr ip_addr_;
};

using DnsAnswerRecordPtr = std::unique_ptr<DnsAnswerRecord>;
using DnsAnswerMap = std::unordered_multimap<std::string, DnsAnswerRecordPtr>;

/**
 * DnsSrvRecord represents a single answer record for a service which is to be serialized and
 * sent to a client. This class inherits core fields from DnsAnswerRecord and adds new fields
 * inherent to DNS service records
 */
class DnsSrvRecord : public DnsAnswerRecord {
public:
  DnsSrvRecord(const std::string& service_name, const std::string& proto,
               const std::chrono::seconds ttl, const uint16_t priority, const uint16_t weight,
               const uint16_t port, const std::string& target,
               const uint16_t rec_type = DNS_RECORD_TYPE_SRV,
               const uint16_t rec_class = DNS_RECORD_CLASS_IN)
      : DnsAnswerRecord(service_name, rec_type, rec_class, ttl, nullptr), proto_(proto),
        priority_(priority), weight_(weight), port_(port), target_(target) {}

  bool serialize(Buffer::OwnedImpl& output) override;

  static std::string buildServiceName(const std::string& name, const std::string& proto,
                                      const std::string& domain) {
    if (name.empty() || proto.empty() || domain.empty()) {
      return EMPTY_STRING;
    }

    std::string result{};
    if (name[0] != '_') {
      result += "_";
    }
    result += name + ".";
    if (proto[0] != '_') {
      result += "_";
    }
    result += proto + '.' + domain;
    return result;
  }

  static absl::string_view getServiceFromName(const absl::string_view name) {
    const size_t offset = name.find_first_of('.');
    if (offset != std::string::npos && offset < name.size()) {
      size_t start = 0;
      if (name[start] == '_') {
        return name.substr(++start, offset - 1);
      }
    }
    return EMPTY_STRING;
  }

  static absl::string_view getProtoFromName(const absl::string_view name) {
    size_t start = name.find_first_of('.');
    if (start != std::string::npos && ++start < name.size() - 1) {
      if (name[start] == '_') {
        const size_t offset = name.find_first_of('.', ++start);
        if (start != std::string::npos && offset < name.size()) {
          return name.substr(start, offset - start);
        }
      }
    }
    return EMPTY_STRING;
  }

  std::string proto_;
  uint16_t priority_;
  uint16_t weight_;
  uint16_t port_;
  std::string target_;
};

using DnsSrvRecordPtr = std::unique_ptr<DnsSrvRecord>;

// Store the server record with the full service name as the key to the service config. For
// each service there can be multiple configs for a given service name. The service can be
// weighted to distribute connections to multiple hosts, etc.
using DnsSrvRecordPtrVec = std::vector<DnsSrvRecordPtr>;

/**
 * @brief This struct is used to hold pointers to the counters that are relevant to the
 * parser. This is done to prevent dependency loops between the parser and filter headers
 */
struct DnsParserCounters {
  Stats::Counter& underflow_counter;
  Stats::Counter& record_name_overflow;
  Stats::Counter& query_parsing_failure;

  DnsParserCounters(Stats::Counter& underflow, Stats::Counter& record_name,
                    Stats::Counter& query_parsing)
      : underflow_counter(underflow), record_name_overflow(record_name),
        query_parsing_failure(query_parsing) {}
};

/**
 * DnsQueryContext contains all the data necessary for responding to a query from a given client.
 */
class DnsQueryContext {
public:
  DnsQueryContext(Network::Address::InstanceConstSharedPtr local,
                  Network::Address::InstanceConstSharedPtr peer, DnsParserCounters& counters,
                  uint64_t retry_count)
      : local_(std::move(local)), peer_(std::move(peer)), counters_(counters), parse_status_(false),
        response_code_(DNS_RESPONSE_CODE_NO_ERROR), retry_(retry_count) {}

  const Network::Address::InstanceConstSharedPtr local_;
  const Network::Address::InstanceConstSharedPtr peer_;
  DnsParserCounters& counters_;
  bool parse_status_;
  uint16_t response_code_;
  uint64_t retry_;
  uint16_t id_;
  Network::DnsResolver::ResolutionStatus resolution_status_;
  DnsQueryPtrVec queries_;
  DnsAnswerMap answers_;
  // DnsAnswerMap authority_;
  DnsAnswerMap additional_;
};

using DnsQueryContextPtr = std::unique_ptr<DnsQueryContext>;
using DnsFilterResolverCallback = std::function<void(
    DnsQueryContextPtr context, const DnsQueryRecord* current_query, AddressConstPtrVec& ipaddr)>;

/**
 * This class orchestrates parsing a DNS query and building the response to be sent to a client.
 */
class DnsMessageParser : public Logger::Loggable<Logger::Id::filter> {
public:
  enum class DnsQueryParseState {
    Init,
    Flags,      // 2 bytes
    Questions,  // 2 bytes
    Answers,    // 2 bytes
    Authority,  // 2 bytes
    Authority2, // 2 bytes
    Finish
  };

  // The flags have been verified with dig and this structure should not be modified. The flag
  // order here does not match the RFC, but takes byte ordering into account so that serialization
  // does not bitwise operations.
  PACKED_STRUCT(struct DnsHeaderFlags {
    unsigned rcode : 4;  // return code
    unsigned cd : 1;     // checking disabled
    unsigned ad : 1;     // authenticated data
    unsigned z : 1;      // z - bit (must be zero in queries per RFC1035)
    unsigned ra : 1;     // recursion available
    unsigned rd : 1;     // recursion desired
    unsigned tc : 1;     // truncated response
    unsigned aa : 1;     // authoritative answer
    unsigned opcode : 4; // operation code
    unsigned qr : 1;     // query or response
  });

  /**
   * Structure representing the DNS header as it appears in a packet
   * See https://www.ietf.org/rfc/rfc1035.txt for more details
   */
  PACKED_STRUCT(struct DnsHeader {
    uint16_t id;
    struct DnsHeaderFlags flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority_rrs;
    uint16_t additional_rrs;
  });

  DnsMessageParser(bool recurse, TimeSource& timesource, uint64_t retry_count,
                   Runtime::RandomGenerator& random, Stats::Histogram& latency_histogram)
      : recursion_available_(recurse), timesource_(timesource), retry_count_(retry_count),
        query_latency_histogram_(latency_histogram), rng_(random) {}

  /**
   * @brief Builds an Answer record for the active query. The active query transaction ID is at
   * the top of a queue. This ID is sufficient enough to determine the answer records associated
   * with the query
   */
  DnsAnswerRecordPtr getResponseForQuery();

  /**
   * @param buffer the buffer containing the constructed DNS response to be sent to a client
   */
  void buildResponseBuffer(DnsQueryContextPtr& query_context, Buffer::OwnedImpl& buffer);

  /**
   * @brief parse a single query record from a client request
   *
   * @param buffer a reference to the incoming request object received by the listener
   * @param offset the buffer offset at which parsing is to begin. This parameter is updated when
   * one record is parsed from the buffer and returned to the caller.
   * @return DnsQueryRecordPtr a pointer to a DnsQueryRecord object containing all query data
   * parsed from the buffer
   */
  DnsQueryRecordPtr parseDnsQueryRecord(const Buffer::InstancePtr& buffer, uint64_t& offset);

  struct DnsAnswerCtx {
    DnsAnswerCtx(const Buffer::InstancePtr& buffer, const std::string& record_name,
                 const uint16_t record_type, const uint16_t record_class,
                 const uint16_t available_bytes, const uint16_t data_length, const uint32_t ttl,
                 uint64_t& offset)
        : buffer_(buffer), record_name_(record_name), record_type_(record_type),
          record_class_(record_class), available_bytes_(available_bytes), data_length_(data_length),
          ttl_(ttl), offset_(offset) {}

    const Buffer::InstancePtr& buffer_;
    const std::string& record_name_;
    const uint16_t record_type_;
    const uint16_t record_class_;
    const uint16_t available_bytes_;
    const uint16_t data_length_;
    const uint32_t ttl_;
    uint64_t& offset_;
  };

  DnsAnswerRecordPtr parseDnsARecord(DnsAnswerCtx& context);

  DnsSrvRecordPtr parseDnsSrvRecord(DnsAnswerCtx& context);
  /**
   * @brief parse a single answer record from a client request
   *
   * @param buffer a reference to a buffer containing a DNS response
   * @param offset the buffer offset at which parsing is to begin. This parameter is updated when
   * one record is parsed from the buffer and returned to the caller.
   * @return DnsQueryRecordPtr a pointer to a DnsAnswerRecord object containing all answer data
   * parsed from the buffer
   */
  DnsAnswerRecordPtr parseDnsAnswerRecord(const Buffer::InstancePtr& buffer, uint64_t& offset);

#if 0
  void storeDnsAuthorityNSRecord(DnsQueryContextPtr& context, const absl::string_view name,
                                const uint16_t rec_type, const uint16_t rec_class,
                                const std::chrono::seconds ttl,
                                Network::Address::InstanceConstSharedPtr ipaddr);
#endif
  bool parseAnswerRecords(DnsAnswerMap& answers, const uint16_t answer_count,
                          const Buffer::InstancePtr& buffer, uint64_t& offset);

  void storeDnsAdditionalRecord(DnsQueryContextPtr& context, const absl::string_view name,
                                const uint16_t rec_type, const uint16_t rec_class,
                                const std::chrono::seconds ttl,
                                Network::Address::InstanceConstSharedPtr ipaddr);
  /**
   * @brief Constructs a DNS SRV Answer record for a given service and stores the object in a map
   * where the response is associated with query name
   *
   * @param context the query context for which we are generating a response
   * @param query_rec to which the answer is matched.
   * @param service the service that is returned in the answer record
   */
  void storeDnsSrvAnswerRecord(DnsQueryContextPtr& context, const DnsQueryRecord& query_rec,
                               const DnsSrvRecordPtr& service);
  /**
   * @brief Constructs a DNS Answer record for a given IP Address and stores the object in a map
   * where the response is associated with query name
   *
   * @param context the query context for which we are generating a response
   * @param query_rec to which the answer is matched.
   * @param ttl the TTL specifying how long the returned answer is cached
   * @param ipaddr the address that is returned in the answer record
   */
  void storeDnsAnswerRecord(DnsQueryContextPtr& context, const DnsQueryRecord& query_rec,
                            const std::chrono::seconds ttl,
                            Network::Address::InstanceConstSharedPtr ipaddr);

  /**
   * @return uint16_t the response code flag value from a parsed dns object
   */
  uint16_t getQueryResponseCode() { return static_cast<uint16_t>(header_.flags.rcode); }

  /**
   * @brief Parse the incoming query and create a context object for the filter
   *
   * @param client_request a structure containing addressing information and the buffer received
   * from a client
   */
  DnsQueryContextPtr createQueryContext(Network::UdpRecvData& client_request,
                                        DnsParserCounters& counters);
  /**
   * @param buffer a reference to the incoming request object received by the listener
   * @return bool true if all DNS records and flags were successfully parsed from the buffer
   */
  bool parseDnsObject(DnsQueryContextPtr& context, const Buffer::InstancePtr& buffer);

private:
  /**
   * @brief sets the response code returned to the client
   *
   * @param context the query context for which we are generating a response
   * @param queries specify the number of query records contained in the response
   * @param answers specify the number of answer records contained in the response
   */
  void setResponseCode(DnsQueryContextPtr& context, const uint16_t serialized_queries,
                       const uint16_t serialized_answers);

  /**
   * @brief sets the flags in the DNS header of the response sent to a client
   *
   * @param context the query context for which we are generating a response
   * @param queries specify the number of query records contained in the response
   * @param answers specify the number of answer records contained in the response
   */
  void setDnsResponseFlags(DnsQueryContextPtr& context, const uint16_t questions,
                           const uint16_t answers, const uint16_t authority_rrs,
                           const uint16_t additional_rrs);

  /**
   * @brief Extracts a DNS query name from a buffer
   *
   * @param buffer the buffer from which the name is extracted
   * @param available_bytes the size of the remaining bytes in the buffer on which we can operate
   * @param name_offset the offset from which parsing begins and ends. The updated value is
   * returned to the caller
   */
  const std::string parseDnsNameRecord(const Buffer::InstancePtr& buffer, uint64_t& available_bytes,
                                       uint64_t& name_offset);

  bool recursion_available_;
  TimeSource& timesource_;
  uint64_t retry_count_;
  Stats::Histogram& query_latency_histogram_;
  DnsHeader header_;
  DnsHeader response_header_;
  Runtime::RandomGenerator& rng_;
};

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
