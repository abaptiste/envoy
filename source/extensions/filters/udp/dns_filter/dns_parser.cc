#include "extensions/filters/udp/dns_filter/dns_parser.h"

#include <iomanip>
#include <sstream>

#include "envoy/network/address.h"

#include "common/common/empty_string.h"
#include "common/network/address_impl.h"
#include "common/network/utility.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

// Don't push upstream
inline void DnsObject::dumpBuffer(const std::string& title, const Buffer::InstancePtr& buffer,
                                  const uint64_t offset) {

  // TODO: We should do no work if the log level is not applicable
  const uint64_t data_length = buffer->length();
  unsigned char buf[1024] = {};
  unsigned char c;

  char* p = reinterpret_cast<char*>(buf);

  for (uint64_t i = offset; i < data_length; i++) {
    if (i && ((i - offset) % 16 == 0)) {
      p += sprintf(p, "\n");
    }
    c = buffer->peekBEInt<unsigned char>(i);
    p += sprintf(p, "0x%02x ", c);
  }
  ENVOY_LOG_MISC(trace, "{}\n{}", title, buf);
}

// Don't push upstream
inline void DnsObject::dumpFlags(const DnsHeaderStruct& queryObj) {

  // TODO: We should do no work if the log level is not applicable
  std::stringstream ss{};

  ss << "Query ID: 0x" << std::hex << queryObj.id << "\n";
  ss << "Flags: " << queryObj.f.val << std::dec << "\n";
  ss << "- Query/Response:       " << queryObj.f.flags.qr << "\n";
  ss << "- Opcode:               " << queryObj.f.flags.opcode << "\n";
  ss << "- Authoritative Answer: " << queryObj.f.flags.aa << "\n";
  ss << "- Truncated:            " << queryObj.f.flags.tc << "\n";
  ss << "- Recursion Desired:    " << queryObj.f.flags.rd << "\n";
  ss << "- Recursion Available:  " << queryObj.f.flags.ra << "\n";
  ss << "- Z bit:                " << queryObj.f.flags.z << "\n";
  ss << "- Authenticated Data    " << queryObj.f.flags.ad << "\n";
  ss << "- Checking Disabled     " << queryObj.f.flags.cd << "\n";
  ss << "- Return Code           " << queryObj.f.flags.rcode << "\n";
  ss << "Questions               " << queryObj.questions << "\n";
  ss << "Answers                 " << queryObj.answers << "\n";
  ss << "Authority RRs           " << queryObj.authority_rrs << "\n";
  ss << "Additional RRs          " << queryObj.additional_rrs << "\n";

  const std::string message = ss.str();

  ENVOY_LOG_MISC(trace, "{}", message);
}

inline void BaseDnsRecord::serializeName() {

  // Iterate over a name e.g. "www.domain.com" once and produce a buffer containing each name
  // segment prefixed by its length

  static constexpr char SEPARATOR('.');

  size_t last = 0;
  size_t count = name_.find_first_of(SEPARATOR);
  auto iter = name_.begin();
  while (count != std::string::npos) {

    count -= last;
    buffer_.writeBEInt<uint8_t>(count);
    for (size_t i = 0; i < count; i++) {
      buffer_.writeByte(*iter);
      ++iter;
    }

    // periods are not serialized. Skip to the next character
    if (*iter == SEPARATOR) {
      ++iter;
    }

    // Move our last marker to the first position after where we stopped. Search for the next name
    // separator
    last += count;
    ++last;
    count = name_.find_first_of(SEPARATOR, last);
  }

  // Write the remaining segment prepended by its length
  count = name_.size() - last;
  buffer_.writeBEInt<uint8_t>(count);
  for (size_t i = 0; i < count; i++) {
    buffer_.writeByte(*iter);
    ++iter;
  }

  // Terminate the name record with a null byte
  buffer_.writeByte(0x00);
}

// Serialize a DNS Query Record
Buffer::OwnedImpl& DnsQueryRecord::serialize() {
  buffer_.drain(buffer_.length());

  serializeName();
  buffer_.writeBEInt<uint16_t>(type_);
  buffer_.writeBEInt<uint16_t>(class_);

  return buffer_;
}

// Serialize a DNS Answer Record
Buffer::OwnedImpl& DnsAnswerRecord::serialize() {
  buffer_.drain(buffer_.length());

  serializeName();
  buffer_.writeBEInt<uint16_t>(type_);
  buffer_.writeBEInt<uint16_t>(class_);
  buffer_.writeBEInt<uint32_t>(ttl_);

  ASSERT(ip_addr_ != nullptr);
  const auto ip_address = ip_addr_->ip();

  ASSERT(ip_address != nullptr);
  if (ip_address->ipv6() != nullptr) {
    // Store the 128bit address with 2 64 bit writes
    const absl::uint128 addr6 = ip_address->ipv6()->address();
    buffer_.writeBEInt<uint16_t>(sizeof(addr6));
    buffer_.writeLEInt<uint64_t>(absl::Uint128Low64(addr6));
    buffer_.writeLEInt<uint64_t>(absl::Uint128High64(addr6));
  } else if (ip_address->ipv4() != nullptr) {
    buffer_.writeBEInt<uint16_t>(4);
    buffer_.writeLEInt<uint32_t>(ip_address->ipv4()->address());
  }
  return buffer_;
}

bool DnsObject::parseDnsObject(const Buffer::InstancePtr& buffer) {

  auto available_bytes = buffer->length();

  // TODO: Remove before pushing upstream
  dumpBuffer(__func__, buffer);

  memset(&incoming_, 0x00, sizeof(incoming_));
  queries_.clear();
  answers_.clear();

  static constexpr uint64_t field_size = sizeof(uint16_t);
  uint64_t offset = 0;
  uint16_t data;

  DnsQueryParseState state_{DnsQueryParseState::INIT};

  while (state_ != DnsQueryParseState::FINISH) {

    // Ensure that we have enough data remaining in the buffer to parse the query
    if (available_bytes < field_size) {
      ENVOY_LOG_MISC(
          error,
          "Exhausted available bytes in the buffer. Insufficient data to parse query field.");
      return false;
    }

    // Each aggregate DNS header field is 2 bytes wide.
    data = buffer->peekBEInt<uint16_t>(offset);
    offset += field_size;
    available_bytes -= field_size;

    if (offset > buffer->length()) {
      ENVOY_LOG_MISC(error, "Buffer read offset [{}] is beyond buffer length [{}].", offset,
                     buffer->length());
      return false;
    }

    switch (state_) {
    case DnsQueryParseState::INIT:
      incoming_.id = data;
      state_ = DnsQueryParseState::FLAGS;
      break;

    case DnsQueryParseState::FLAGS:
      incoming_.f.val = data;
      state_ = DnsQueryParseState::QUESTIONS;
      break;

    case DnsQueryParseState::QUESTIONS:
      incoming_.questions = data;
      state_ = DnsQueryParseState::ANSWERS;
      break;

    case DnsQueryParseState::ANSWERS:
      incoming_.answers = data;
      state_ = DnsQueryParseState::AUTHORITY;
      break;

    case DnsQueryParseState::AUTHORITY:
      incoming_.authority_rrs = data;
      state_ = DnsQueryParseState::AUTHORITY2;
      break;

    case DnsQueryParseState::AUTHORITY2:
      incoming_.additional_rrs = data;
      state_ = DnsQueryParseState::FINISH;
      break;

    case DnsQueryParseState::FINISH:
      break;

    default:
      NOT_REACHED_GCOVR_EXCL_LINE;
    }
  }

  // Verify that we still have available data in the buffer to read answer and query records
  if (offset > buffer->length()) {
    ENVOY_LOG_MISC(error, "Buffer read offset[{}] is larget than buffer length [{}].", offset,
                   buffer->length());
    return false;
  }

  // TODO: Remove before pushing upstream
  dumpFlags(incoming_);

  // Most times we will have only one query here.
  for (auto index = 0; index < incoming_.questions; index++) {
    auto rec = parseDnsQueryRecord(buffer, &offset);
    if (rec == nullptr) {
      ENVOY_LOG_MISC(error, "Couldn't parse query record from buffer");
      return false;
    }
    queries_.push_back(std::move(rec));
  }

  // Parse all answer records and store them
  for (auto index = 0; index < incoming_.answers; index++) {
    auto rec = parseDnsAnswerRecord(buffer, &offset);
    if (rec == nullptr) {
      ENVOY_LOG_MISC(error, "Couldn't parse answer record from buffer");
      return false;
    }
    storeAnswerRecord(std::move(rec));
  }

  return true;
}

const std::string DnsObject::parseDnsNameRecord(const Buffer::InstancePtr& buffer,
                                                uint64_t* available_bytes, uint64_t* name_offset) {
  std::stringstream name_ss{};
  unsigned char c;

  do {
    // Read the name segment length or flag;
    c = buffer->peekBEInt<unsigned char>(*name_offset);
    *name_offset += sizeof(unsigned char);
    *available_bytes -= sizeof(unsigned char);

    if (c == 0xc0) {
      // This is a compressed response. Get the offset in the query record where the domain name
      // begins
      c = buffer->peekBEInt<unsigned char>(*name_offset);

      // We will restart the loop from this offset and read until we encounter a null byte
      // signifying the end of the name
      *name_offset = static_cast<uint64_t>(c);

      continue;

    } else if (c == 0x00) {
      // We've reached the end of the query.
      ENVOY_LOG_MISC(trace, "End of name: {}", c, *name_offset);
      break;
    }

    const uint64_t segment_length = static_cast<uint64_t>(c);

    // Verify that we have enough data to read the segment length
    if (segment_length > *available_bytes) {
      ENVOY_LOG_MISC(error,
                     "Insufficient data in buffer for name segment. "
                     "available bytes: {}  segment length: {}",
                     *available_bytes, segment_length);
      return EMPTY_STRING;
    }

    // Add the name separator if we have already accumulated name data
    if (name_ss.tellp()) {
      name_ss << '.';
    }

    *available_bytes -= segment_length;

    // The value read is a name segment length
    for (uint64_t index = 0; index < segment_length; index++) {
      c = buffer->peekBEInt<unsigned char>(*name_offset);
      *name_offset += sizeof(unsigned char);
      name_ss << c;
    }

  } while (c != 0x00);

  const std::string name = name_ss.str();

  return name;
}

DnsAnswerRecordPtr DnsObject::parseDnsAnswerRecord(const Buffer::InstancePtr& buffer,
                                                   uint64_t* offset) {

  uint64_t data_offset = *offset;
  uint64_t available_bytes = buffer->length() - data_offset;

  const std::string record_name = parseDnsNameRecord(buffer, &available_bytes, &data_offset);
  if (record_name.empty()) {
    ENVOY_LOG_MISC(error, "Unable to parse name record from buffer");
    return nullptr;
  }

  if (available_bytes < (sizeof(uint32_t) + 3 * sizeof(uint16_t))) {
    ENVOY_LOG_MISC(error,
                   "Insufficient data in buffer to read answer record data."
                   "Available bytes: {}",
                   available_bytes);
    return nullptr;
  }

  //  Parse the record type
  uint16_t record_type;
  record_type = buffer->peekBEInt<uint16_t>(data_offset);
  data_offset += sizeof(record_type);
  available_bytes -= sizeof(record_type);
  ASSERT(available_bytes);

  //  Parse the record class
  uint16_t record_class;
  record_class = buffer->peekBEInt<uint16_t>(data_offset);
  data_offset += sizeof(record_class);
  available_bytes -= sizeof(record_class);
  ASSERT(available_bytes);

  //  Parse the record TTL
  uint32_t ttl;
  ttl = buffer->peekBEInt<uint32_t>(data_offset);
  data_offset += sizeof(ttl);
  available_bytes -= sizeof(ttl);
  ASSERT(available_bytes);

  //  Parse the Data Length and address data record
  uint16_t data_length;
  data_length = buffer->peekBEInt<uint16_t>(data_offset);
  data_offset += sizeof(data_length);
  available_bytes -= sizeof(data_length);
  ASSERT(available_bytes);

  if (available_bytes < data_length) {
    ENVOY_LOG_MISC(error,
                   "Answer record data length: {} is more than the available bytes {} in buffer",
                   data_length, available_bytes);
    return nullptr;
  }

  // Build an address pointer from the string data.
  // We don't support anything other than A or AAAA records. If we add support for other record
  // types, we must account for them here
  Network::Address::InstanceConstSharedPtr ip_addr = nullptr;

  if (record_type == DnsRecordType::A) {
    sockaddr_in sa4;
    sa4.sin_addr.s_addr = buffer->peekLEInt<uint32_t>(data_offset);
    ip_addr = std::make_shared<Network::Address::Ipv4Instance>(&sa4);
  } else if (record_type == DnsRecordType::AAAA) {
    sockaddr_in6 sa6;
    uint8_t* address6_bytes = reinterpret_cast<uint8_t*>(&sa6.sin6_addr.s6_addr);
    static constexpr size_t count = sizeof(absl::uint128) / sizeof(uint8_t);
    for (size_t index = 0; index < count; index++) {
      *address6_bytes++ = buffer->peekLEInt<uint8_t>(data_offset++);
    }

    ip_addr = std::make_shared<Network::Address::Ipv6Instance>(sa6, true);
  }

  data_offset += data_length;

  ASSERT(ip_addr != nullptr);
  ENVOY_LOG_MISC(debug, "Parsed address [{}] from record type [{}]",
                 ip_addr->ip()->addressAsString(), record_type);

  *offset = data_offset;

  return std::make_unique<DnsAnswerRecord>(record_name, record_type, record_class, ttl,
                                           std::move(ip_addr));
}

DnsQueryRecordPtr DnsObject::parseDnsQueryRecord(const Buffer::InstancePtr& buffer,
                                                 uint64_t* offset) {
  uint64_t name_offset = *offset;
  uint64_t available_bytes = buffer->length() - name_offset;

  const std::string record_name = parseDnsNameRecord(buffer, &available_bytes, &name_offset);
  if (record_name.empty()) {
    ENVOY_LOG_MISC(error, "Unable to parse name record from buffer");
    return nullptr;
  }

  if (available_bytes < 2 * sizeof(uint16_t)) {
    ENVOY_LOG_MISC(error,
                   "Insufficient data in buffer to read query record type and class. "
                   "Available bytes: {}",
                   available_bytes);
    return nullptr;
  }

  // Read the record type (A or AAAA)
  uint16_t record_type;
  record_type = buffer->peekBEInt<uint16_t>(name_offset);
  name_offset += sizeof(record_type);

  // Read the record class.  This value is almost always 1 for internet address records
  uint16_t record_class;
  record_class = buffer->peekBEInt<uint16_t>(name_offset);
  name_offset += sizeof(record_class);

  // This is shared because we use the query from a list when building the response.
  // Using a shared pointer avoids duplicating this data in the asynchronous resolution path
  auto rec = std::make_shared<DnsQueryRecord>(record_name, record_type, record_class);

  // stop reading he buffer here since we aren't parsing additional records
  ENVOY_LOG_MISC(trace, "Extracted query record. Name: {} type: {} class: {}", rec->name_,
                 rec->type_, rec->class_);

  *offset = name_offset;

  return std::move(rec);
}

void DnsMessageParser::setDnsResponseFlags(uint16_t answers) {

  // Copy the transaction ID
  generated_.id = incoming_.id;

  // Signify that this is a response to a query
  generated_.f.flags.qr = 1;

  generated_.f.flags.opcode = incoming_.f.flags.opcode;

  generated_.f.flags.aa = 0;
  generated_.f.flags.tc = 0;

  // Copy Recursion flags
  generated_.f.flags.rd = incoming_.f.flags.rd;

  // TODO: This should be predicated on whether the user allows upstream lookups
  generated_.f.flags.ra = 0;

  // reserved flag is not set
  generated_.f.flags.z = 0;

  // Set the authenticated flags to zero
  generated_.f.flags.ad = 0;

  generated_.f.flags.cd = 0;

  generated_.answers = answers;

  // If the ID is empty, the query was not parsed correctly or
  // it may be an invalid buffer
  if (incoming_.id == 0) {
    generated_.f.flags.rcode = as_integer(DnsResponseCode::FORMAT_ERROR);
  } else {
    generated_.f.flags.rcode =
        as_integer(answers_.empty() ? DnsResponseCode::NAME_ERROR : DnsResponseCode::NO_ERROR);
  }

  // Set the number of questions we are responding to
  generated_.questions = incoming_.questions;

  // We will not include any additional records
  generated_.authority_rrs = 0;
  generated_.additional_rrs = 0;

  // TODO: Remove before pushing upstream
  dumpFlags(generated_);
}

void DnsObject::buildDnsAnswerRecord(const DnsQueryRecordPtr& query_rec, const uint32_t ttl,
                                     Network::Address::InstanceConstSharedPtr ipaddr) {

  // If the DNS resolution times out, this could be called with a NULL ip address
  if (ipaddr == nullptr) {
    return;
  }

  // Verify that we have an address matching the query record type
  switch (query_rec->type_) {
  case DnsRecordType::AAAA:
    if (ipaddr->ip()->ipv6() == nullptr) {
      ENVOY_LOG_MISC(error, "Unable to return IPV6 address for query");
      return;
    }
    break;

  case DnsRecordType::A:
    if (ipaddr->ip()->ipv4() == nullptr) {
      ENVOY_LOG_MISC(error, "Unable to return IPV4 address for query");
      return;
    }
    break;

  default:
    ENVOY_LOG_MISC(error, "record type [{}] not supported", query_rec->type_);
    return;
  }

  // The answer record could contain types other than IP's. We will support only IP addresses for
  // the moment
  auto answer_record = std::make_unique<DnsAnswerRecord>(query_rec->name_, query_rec->type_,
                                                         query_rec->class_, ttl, std::move(ipaddr));
  storeAnswerRecord(std::move(answer_record));
}

void DnsMessageParser::buildResponseBuffer(Buffer::OwnedImpl& buffer) {

  // Ensure that responses stay below the 512 byte byte limit. If we are to exceed this we must add
  // DNS extension fields
  //
  // Note:  There is Network::MAX_UDP_PACKET_SIZE, which is defined as 1500 bytes.  If we support
  // DNS extensions that support up to 4096 bytes, we will have to keep this 1500 byte limit in
  // mind.
  static constexpr uint64_t max_dns_response_size{512};

  // Each response must have DNS flags, which take 4 bytes. Account for them
  // immediately so that we can adjust the number of returned answers
  uint64_t total_buffer_size = 4;
  uint16_t serialized_answers = 0;

  Buffer::OwnedImpl query_buffer{};
  Buffer::OwnedImpl answer_buffer{};

  // There should be only one query here.
  for (const auto& query : queries_) {

    // Serialize the query
    query_buffer.add(query->serialize());
    total_buffer_size += query_buffer.length();

    // Find the answer record corresponding to this query
    const auto& answer_rec = answers_.find(query->name_);
    if (answer_rec == answers_.end()) {
      continue;
    }

    // Serialize each answer record and stop if we will exceed 512 bytes
    for (const auto& answer : answer_rec->second) {
      const auto& serialized_answer = answer->serialize();
      const uint64_t serialized_answer_length = serialized_answer.length();

      if ((total_buffer_size + serialized_answer_length) > max_dns_response_size) {
        break;
      }

      ++serialized_answers;
      total_buffer_size += serialized_answer_length;
      answer_buffer.add(serialized_answer);
    }

    answer_rec->second.clear();
    answers_.erase(answer_rec);
  }

  // Build the response and send it on the connection
  setDnsResponseFlags(serialized_answers);

  buffer.writeBEInt<uint16_t>(generated_.id);
  buffer.writeBEInt<uint16_t>(generated_.f.val);
  buffer.writeBEInt<uint16_t>(generated_.questions);
  buffer.writeBEInt<uint16_t>(generated_.answers);
  buffer.writeBEInt<uint16_t>(generated_.authority_rrs);
  buffer.writeBEInt<uint16_t>(generated_.additional_rrs);

  // write the queries and answers
  buffer.move(query_buffer);
  buffer.move(answer_buffer);
}

void DnsObject::storeAnswerRecord(DnsAnswerRecordPtr rec) {

  const std::string domain_name = rec->name_;

  const auto& answer_iter = answers_.find(domain_name);
  if (answer_iter == answers_.end()) {
    std::list<DnsAnswerRecordPtr> answer_list{};
    answer_list.push_back(std::move(rec));
    answers_.emplace(domain_name, std::move(answer_list));
  } else {
    answer_iter->second.push_back(std::move(rec));
  }
}

uint64_t DnsMessageParser::queriesUnanswered() {

  const auto queries = queries_.size();
  const auto answers = answers_.size();

  // The answers_ object is a map that pairs each query (if there are more than one) to the list of
  // answer records to be serialized and sent to the client
  ASSERT(queries >= answers);

  return queries - answers;
}

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
