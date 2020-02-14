#pragma once

#include "common/buffer/buffer_impl.h"
#include "envoy/buffer/buffer.h"
#include "envoy/network/listener.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

// The flags have been verified with dig and this
// structure should not be modified.  The flag order
// does not match the RFC, but takes byte ordering
// into account so that serialization/deserialization
// requires no and-ing or shifting.
typedef struct __attribute__((packed)) dns_query_flags_s {
  unsigned rcode : 4;  // return code
  unsigned cd : 1;     // checking disabled
  unsigned ad : 1;     // authenticated data
  unsigned z : 1;      // z - bit (must be zero in queries per RFC1035)
  unsigned ra : 1;     // recursion available
  unsigned rd : 1;     // recursion desired
  unsigned tc : 1;     // truncated response
  unsigned aa : 1;     // authoritiative answer
  unsigned opcode : 4; // operation code
  unsigned qr : 1;     // query or response
} dns_query_flags_t;

typedef struct __attribute__((packed)) dns_query_s {
  uint16_t id;
  union {
    uint16_t val;
    dns_query_flags_t flags;
  } f;
  uint16_t questions;
  uint16_t answers;
  uint16_t authority_rrs;
  uint16_t additional_rrs;
} dns_query_t;

enum class DnsResponseCode { NO_ERROR, FORMAT_ERROR, SERVER_FAILURE, NAME_ERROR, NOT_IMPLEMENTED };

class DnsObject {

public:
  DnsObject() {}
  dns_query_t query_;
  dns_query_t response_;

protected:
  void dumpBuffer(const std::string& title, const Buffer::InstancePtr& buffer,
                  const uint64_t offset = 0);
  void dumpFlags(const dns_query_t& queryObj);
};

// BaseDnsRecord class containing the domain name operated on, its class, and address type
// Since this is IP based the class is almost always 1 (INET), the type varies betweeen
// A and AAAA queries
class BaseDnsRecord {
public:
  BaseDnsRecord(const std::string& rec_name, const uint16_t rec_type, const uint16_t rec_class)
      : name_(rec_name), type_(rec_type), class_(rec_class) {}

  virtual ~BaseDnsRecord() {}

  const std::string name_;
  const uint16_t type_;
  const uint16_t class_;

  void serializeName();

protected:
  virtual Buffer::OwnedImpl& serialize() PURE;
  Buffer::OwnedImpl buffer_;
};

class DnsQueryRecord : public BaseDnsRecord {

public:
  DnsQueryRecord(const std::string& rec_name, const uint16_t rec_type, const uint16_t rec_class)
      : BaseDnsRecord(rec_name, rec_type, rec_class) {}

  virtual ~DnsQueryRecord() {}
  virtual Buffer::OwnedImpl& serialize();
};

using DnsQueryRecordPtr = std::unique_ptr<DnsQueryRecord>;
using DnsQueryList = std::list<DnsQueryRecordPtr>;

class DnsAnswerRecord : public BaseDnsRecord {
public:
  DnsAnswerRecord(const std::string& query_name, const uint16_t rec_type, const uint16_t rec_class,
                  const uint32_t ttl, const uint16_t data_length, const std::string& address)
      : BaseDnsRecord(query_name, rec_type, rec_class), ttl_(ttl), data_length_(data_length),
        address_(address) {}

  virtual ~DnsAnswerRecord() {}
  virtual Buffer::OwnedImpl& serialize();

  const uint32_t ttl_;
  const uint16_t data_length_;
  const std::string address_;
};

using DnsAnswerRecordPtr = std::unique_ptr<DnsAnswerRecord>;
using DnsAnswerList = std::list<DnsAnswerRecordPtr>;

enum class DnsQueryParseState {
  INIT = 0,
  TRANSACTION_ID, // 2 bytes
  FLAGS,          // 2 bytes
  QUESTIONS,      // 2 bytes
  ANSWERS,        // 2 bytes
  AUTHORITY,      // 2 bytes
  AUTHORITY2,     // 2 bytes
  FINISH
};

class DnsQueryParser : DnsObject, Logger::Loggable<Logger::Id::filter> {
public:
  DnsQueryParser() : queries(), answers() {}
  virtual ~DnsQueryParser() {}

  virtual bool parseQueryData(const Buffer::InstancePtr& buffer);
  virtual DnsQueryList& getQueries() { return queries; };

  virtual bool buildResponseBuffer(Buffer::OwnedImpl& buffer, DnsAnswerRecordPtr& answer_rec);

private:
  DnsQueryRecordPtr parseDnsQueryRecord(const Buffer::InstancePtr& buffer, uint64_t* offset);
  void setDnsResponseFlags();

  DnsQueryList queries;
  DnsAnswerList answers;
};

using DnsQueryParserPtr = std::unique_ptr<DnsQueryParser>;

class DnsResponseParser : DnsObject, Logger::Loggable<Logger::Id::filter> {

public:
  DnsResponseParser() {}
  virtual ~DnsResponseParser() {}

  virtual bool parseResponseData(const Buffer::InstancePtr& buffer);

private:
};

using DnsResponseParserPtr = std::unique_ptr<DnsResponseParser>;

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
