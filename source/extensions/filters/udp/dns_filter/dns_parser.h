#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/network/address.h"
#include "envoy/network/listener.h"

#include "common/buffer/buffer_impl.h"
#include "common/stats/timespan_impl.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

// The flags have been verified with dig and this structure should not be modified. The flag order
// does not match the RFC, but takes byte ordering into account so that serialization does not need
// and-ing or shifting.
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

using dns_query_flags_t = struct dns_query_flags_s;

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

enum DnsRecordClass { IN = 1 };
enum DnsRecordType { A = 1, AAAA = 28 };
enum DnsResponseCode { NoError, FormatError, ServerFailure, NameError, NotImplemented };

/**
 * BaseDnsRecord contains the fields and functions common to both query and answer records.
 */
class BaseDnsRecord {
public:
  BaseDnsRecord(const std::string& rec_name, const uint16_t rec_type, const uint16_t rec_class)
      : name_(rec_name), type_(rec_type), class_(rec_class) {}

  virtual ~BaseDnsRecord() = default;
  void serializeName(Buffer::OwnedImpl& output);
  virtual void serialize(Buffer::OwnedImpl& output) PURE;

  const std::string name_;
  const uint16_t type_;
  const uint16_t class_;
};

/**
 * DnsQueryRecord represents a query record parsed from a DNS request from a client. Each query
 * record contains the domain requested and the flags dictating the type of record that is sought.
 */
class DnsQueryRecord : public BaseDnsRecord {

public:
  DnsQueryRecord(const std::string& rec_name, const uint16_t rec_type, const uint16_t rec_class)
      : BaseDnsRecord(rec_name, rec_type, rec_class) {}

  ~DnsQueryRecord() override = default;
  void serialize(Buffer::OwnedImpl& output) override;

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
                  const uint32_t ttl, Network::Address::InstanceConstSharedPtr ipaddr)
      : BaseDnsRecord(query_name, rec_type, rec_class), ttl_(ttl), ip_addr_(ipaddr) {}

  ~DnsAnswerRecord() override = default;
  void serialize(Buffer::OwnedImpl& output) override;

  const uint32_t ttl_;
  Network::Address::InstanceConstSharedPtr ip_addr_;
};

using DnsAnswerRecordPtr = std::unique_ptr<DnsAnswerRecord>;
using DnsAnswerMap = std::unordered_multimap<std::string, DnsAnswerRecordPtr>;

class DnsQueryContext {
public:
  DnsQueryContext(Network::Address::InstanceConstSharedPtr local,
                  Network::Address::InstanceConstSharedPtr peer)
      : local_(std::move(local)), peer_(std::move(peer)), status_(false), id_() {}
  ~DnsQueryContext() = default;

  Network::Address::InstanceConstSharedPtr local_;
  Network::Address::InstanceConstSharedPtr peer_;

  bool status_;
  uint16_t id_;
  DnsQueryPtrVec queries_;
  DnsAnswerMap answers_;
};

using DnsQueryContextPtr = std::unique_ptr<DnsQueryContext>;

using AnswerCallback = std::function<void(
    DnsQueryContextPtr context, const DnsQueryRecord* current_query, AddressConstPtrVec& ipaddr)>;

enum class DnsQueryParseState {
  Init = 0,
  Flags,      // 2 bytes
  Questions,  // 2 bytes
  Answers,    // 2 bytes
  Authority,  // 2 bytes
  Authority2, // 2 bytes
  Finish
};

/**
 * This class orchestrates parsing a DNS query and building the response to be sent to a client.
 */
class DnsMessageParser : public Logger::Loggable<Logger::Id::filter> {
public:
  DnsMessageParser(TimeSource& timesource, Stats::Histogram& latency_histogram)
      : timesource_(timesource), query_latency_histogram_(latency_histogram) {}
  ~DnsMessageParser() = default;

  // TODO: Do not include this in the PR
  void dumpBuffer(const std::string& title, const Buffer::InstancePtr& buffer,
                  const uint64_t offset = 0);

  // TODO: Do not include this in the PR
  void dumpFlags(const struct DnsHeader& query);

  /**
   * @brief Builds an Answer record for the active query. The active query transaction ID is at the
   * top of a queue. This ID is sufficient enough to determine the answer records associated with
   * the query
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
   * @return DnsQueryRecordPtr a pointer to a DnsQueryRecord object containing all query data parsed
   * from the buffer
   */
  DnsQueryRecordPtr parseDnsQueryRecord(const Buffer::InstancePtr& buffer, uint64_t* offset);

  /**
   * @brief parse a single answer record from a client request
   *
   * @param buffer a reference to a buffer containing a DNS response
   * @param offset the buffer offset at which parsing is to begin. This parameter is updated when
   * one record is parsed from the buffer and returned to the caller.
   * @return DnsQueryRecordPtr a pointer to a DnsAnswerRecord object containing all answer data
   * parsed from the buffer
   */
  DnsAnswerRecordPtr parseDnsAnswerRecord(const Buffer::InstancePtr& buffer, uint64_t* offset);

  /**
   * @brief Constructs a DNS Answer record for a given IP Address and stores the object in a map
   * where the response is associated with query name
   *
   * @param query_record to which the answer is matched.
   * @param ttl the TTL specifying how long the returned answer is cached
   * @param ipaddr the address that is returned in the answer record
   */
  void buildDnsAnswerRecord(DnsQueryContextPtr& context, const DnsQueryRecord& query_rec,
                            const uint32_t ttl, Network::Address::InstanceConstSharedPtr ipaddr);

  /**
   * @return a reference to a list of queries parsed from a client request
   */
  // const DnsQueryPtrVec& getActiveQueryRecords() { return queries_; }

  /**
   * @return the current query transaction ID being handled
   */
  // uint16_t getCurrentQueryId() { return active_transactions_.front(); }

  /**
   * @return a reference to a map associating the query name to the list of answers
   */
  // const DnsAnswerMap& getAnswerRecords() { return answers_; }

  /**
   * @return uint16_t the response code flag value from a parsed dns object
   */
  uint16_t getQueryResponseCode() { return static_cast<uint16_t>(incoming_.flags.rcode); }

  /**
   * @return uint16_t the number of answer records in the parsed dns object
   */
  uint16_t getAnswers() { return incoming_.answers; }

  /**
   * @return uint16_t the response code flag value from a generated dns object
   */
  uint16_t getAnswerResponseCode() { return static_cast<uint16_t>(generated_.flags.rcode); }

  // size_t getActiveTransactionCount() const { return active_transactions_.size(); }

  DnsQueryContextPtr createQueryContext(Network::UdpRecvData& client_request);
  /**
   * Reset the internal state of the class.
   */

private:
  /**
   * @param buffer a reference to the incoming request object received by the listener
   * @return bool true if all DNS records and flags were successfully parsed from the buffer
   */
  bool parseDnsObject(DnsQueryContextPtr& context, const Buffer::InstancePtr& buffer);

  /**
   * @brief sets the flags in the DNS header of the response sent to a client
   *
   * @param queries specify the number of query records contained in the response
   * @param answers specify the number of answer records contained in the response
   */
  void setDnsResponseFlags(const uint16_t questions, const uint16_t answers);

  /**
   * @brief Extracts a DNS query name from a buffer
   *
   * @param buffer the buffer from which the name is extracted
   * @param available_bytes the size of the remaining bytes in the buffer on which we can operate
   * @param name_offset the offset from which parsing begins and ends. The updated value is returned
   * to the caller
   */
  const std::string parseDnsNameRecord(const Buffer::InstancePtr& buffer, uint64_t* available_bytes,
                                       uint64_t* name_offset);

  TimeSource& timesource_;
  Stats::Histogram& query_latency_histogram_;

  struct DnsHeader incoming_;
  struct DnsHeader generated_;
};

using DnsMessageParserPtr = std::unique_ptr<DnsMessageParser>;

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
