#include <iomanip>
#include <sstream>

#include "envoy/network/address.h"
#include "common/network/utility.h"
#include "extensions/filters/udp/dns_filter/dns_parser.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

namespace {
template <typename Enumeration>
auto as_integer(Enumeration const value) -> typename std::underlying_type<Enumeration>::type {
  return static_cast<typename std::underlying_type<Enumeration>::type>(value);
}
} // namespace

inline void DnsObject::dumpBuffer(const std::string& title, const Buffer::InstancePtr& buffer,
                                  const uint64_t offset) {
  const uint64_t data_length = buffer->length();
  unsigned char buf[1024] = {};
  unsigned char c;
  char* p = nullptr;

  p = reinterpret_cast<char*>(buf);

  for (uint64_t i = offset; i < data_length; i++) {
    if (i && ((i - offset) % 16 == 0)) {
      p += sprintf(p, "\n");
    }
    c = buffer->peekBEInt<unsigned char>(i);
    p += sprintf(p, "0x%02x ", c);
  }
  ENVOY_LOG_MISC(trace, "{}\n{}", title, buf);
}

inline void DnsObject::dumpFlags(const DnsHostRecord& queryObj) {
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

  // This function iterates over a name eg. "www.foo1.com"
  // once and produces a buffer containing 3www4foo13com<nullbyte>

  size_t last = 0;
  size_t count = name_.find_first_of('.');

  auto iter = name_.begin();
  while (count != std::string::npos) {

    count -= last;
    buffer_.writeBEInt<uint8_t>(count);
    for (size_t i = 0; i < count; i++) {
      buffer_.writeByte(*iter);
      ++iter;
    }

    // periods are not serialized.  Skip to the next character
    if (*iter == '.') {
      ++iter;
    }

    // Move our last marker to the next character
    // after where we stopped.  Search for the next
    // name separator
    last += count;
    ++last;
    count = name_.find_first_of('.', last);
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

// TODO: How do we know that this worked?
Buffer::OwnedImpl& DnsQueryRecord::serialize() {
  // TODO: Reuse the existing serialized query.

  buffer_.drain(buffer_.length());

  serializeName();
  buffer_.writeBEInt<uint16_t>(type_);
  buffer_.writeBEInt<uint16_t>(class_);

  return buffer_;
}

Buffer::OwnedImpl& DnsAnswerRecord::serialize() {
  buffer_.drain(buffer_.length());

  serializeName();

  buffer_.writeBEInt<uint16_t>(type_);
  buffer_.writeBEInt<uint16_t>(class_);
  buffer_.writeBEInt<uint32_t>(ttl_);

  // Convert address and serialize
  auto address_ptr = Network::Utility::parseInternetAddress(address_, 0, false);
  auto ip_address = address_ptr->ip();

  if (ip_address->ipv6() != nullptr && data_length_ == 16) {
    buffer_.writeBEInt<uint16_t>(data_length_);
    buffer_.writeLEInt<uint32_t>(ip_address->ipv4()->address());
  } else if (ip_address->ipv4() != nullptr && data_length_ == 4) {
    buffer_.writeBEInt<uint16_t>(data_length_);
    buffer_.writeLEInt<uint32_t>(ip_address->ipv4()->address());
  }

  return buffer_;
}

bool DnsQueryParser::parseQueryData(const Buffer::InstancePtr& buffer) {

  ENVOY_LOG(debug, "In {} with {} bytes", __func__, buffer->length());

  dumpBuffer("Query", buffer);

  memset(&query_, 0x00, sizeof(query_));
  queries.clear();

  static const uint64_t field_size = sizeof(uint16_t);
  uint64_t offset = 0;
  uint16_t data;

  DnsQueryParseState state_{DnsQueryParseState::INIT};

  while (state_ != DnsQueryParseState::FINISH) {

    data = buffer->peekBEInt<uint16_t>(offset);
    offset += field_size;

    if (offset > buffer->length()) {
      ENVOY_LOG(error, "Exhausted available bytes in the buffer.  Unable to parse query");
      return false;
    }

    switch (state_) {
    case DnsQueryParseState::INIT:
      query_.id = data;
      state_ = DnsQueryParseState::FLAGS;
      break;

    case DnsQueryParseState::FLAGS:
      query_.f.val = data;
      state_ = DnsQueryParseState::QUESTIONS;
      break;

    case DnsQueryParseState::QUESTIONS:
      query_.questions = data;
      state_ = DnsQueryParseState::ANSWERS;
      break;

    case DnsQueryParseState::ANSWERS:
      query_.answers = data;
      state_ = DnsQueryParseState::AUTHORITY;
      break;

    case DnsQueryParseState::AUTHORITY:
      query_.authority_rrs = data;
      state_ = DnsQueryParseState::AUTHORITY2;
      break;

    case DnsQueryParseState::AUTHORITY2:
      query_.additional_rrs = data;
      state_ = DnsQueryParseState::FINISH;
      break;

    case DnsQueryParseState::FINISH:
      break;

    default:
      ENVOY_LOG(error, "Unknown DNS Query state: {}", as_integer(state_));
      return false;
    }
  }

  if (offset > buffer->length()) {
    return false;
  }

  // DEBUG
  dumpFlags(query_);

  // Most time we will have only one query here.
  // TODO: Validate this and handle the case where more than one query is present
  for (uint16_t index = 0; index < query_.questions; index++) {
    auto rec = parseDnsQueryRecord(buffer, &offset);
    queries.push_back(std::move(rec));
  }

  return true;
}

DnsQueryRecordPtr DnsQueryParser::parseDnsQueryRecord(const Buffer::InstancePtr& buffer,
                                                      uint64_t* offset) {
  std::stringstream name_ss{};
  uint64_t name_offset = *offset;
  uint64_t available_bytes = buffer->length() - name_offset;
  unsigned char c;

  do {
    // Read the name segment length or flag;
    c = buffer->peekBEInt<unsigned char>(name_offset);
    name_offset += sizeof(unsigned char);
    available_bytes -= sizeof(unsigned char);

    if (c == 0xc0) {
      // This is a compressed response.  Get the offset in the query record
      // of the response where the domain name begins
      c = buffer->peekBEInt<unsigned char>(name_offset);

      // We will restart the loop from this offset and read until we encounter
      // a null byte signifying the end of the name
      name_offset = static_cast<uint64_t>(c);

      continue;

    } else if (c == 0x00) {
      // We've reached the end of the query.
      ENVOY_LOG(debug, "End of name: {}", c, name_offset);
      break;
    }

    const uint64_t segment_length = static_cast<uint64_t>(c);

    // Verify that we have enough data to read the segment length
    if (available_bytes < segment_length) {
      ENVOY_LOG(error,
                "Insufficient data in buffer for name segment. "
                "available bytes: {}  segment: {}",
                available_bytes, segment_length);
      return nullptr;
    }

    // Add the name separator if we have already accumulated name data
    if (name_ss.tellp()) {
      name_ss << '.';
    }

    available_bytes -= segment_length;

    // The value read is a name segment length
    for (uint64_t index = 0; index < segment_length; index++) {
      c = buffer->peekBEInt<unsigned char>(name_offset);
      name_offset += sizeof(unsigned char);
      name_ss << c;
    }

  } while (c != 0x00);

  if (available_bytes < 2 * sizeof(uint16_t)) {
    ENVOY_LOG(error,
              "Insufficient data in buffer to read query record type and class. "
              "Available bytes: {}",
              available_bytes);
    return nullptr;
  }

  // Read the record type (A or AAAA)
  uint16_t record_type;
  record_type = buffer->peekBEInt<uint16_t>(name_offset);
  name_offset += sizeof(record_type);

  uint16_t record_class;
  record_class = buffer->peekBEInt<uint16_t>(name_offset);
  name_offset += sizeof(record_class);

  std::string record_name = name_ss.str();
  auto rec = std::make_unique<DnsQueryRecord>(record_name, record_type, record_class);

  // stop reading here since we aren't parsing additional records

  // We will have to figure out the size of any additional records present and update
  // *offset so it is at the start of the next query
  ENVOY_LOG_MISC(trace, "Extracted query record. Name: {} type: {} class: {}", rec->name_,
                 rec->type_, rec->class_);

  return rec;
}

void DnsQueryParser::setDnsResponseFlags() {

  // Copy the transaction ID
  response_.id = query_.id;

  // Signify that this is a response to a query
  response_.f.flags.qr = 1;

  response_.f.flags.opcode = query_.f.flags.opcode;

  response_.f.flags.aa = 0;
  response_.f.flags.tc = 0;

  // Copy Recursion flags
  response_.f.flags.rd = query_.f.flags.rd;

  // TODO: This should be predicated on whether the user allows upstream lookups
  response_.f.flags.ra = 0;

  // reserved flag is not set
  response_.f.flags.z = 0;

  // Set the authenticated flags to zero
  response_.f.flags.ad = 0;

  response_.f.flags.cd = 0;

  response_.answers = answers.size();
  response_.f.flags.rcode =
      as_integer(answers.empty() ? DnsResponseCode::NAME_ERROR : DnsResponseCode::NO_ERROR);

  // Set the number of questions we are responding to
  response_.questions = query_.questions;

  // We will not include any additionl records
  response_.authority_rrs = 0;
  response_.additional_rrs = 0;

  // DEBUG
  dumpFlags(response_);
}

// This is the sole function that aggregates all the data and builds
// the buffer sent back to the client
bool DnsQueryParser::buildResponseBuffer(Buffer::OwnedImpl& buffer_,
                                         DnsAnswerRecordPtr& answer_record) {

  answers.clear();
  if (answer_record != nullptr) {
    answers.push_back(std::move(answer_record));
  }

  // Build the response and send it on the connection
  ENVOY_LOG(debug, "In {} with address [{}]", __func__,
            answer_record != nullptr ? answer_record->address_ : "Nothing");

  // Clear any left over cruft
  buffer_.drain(buffer_.length());

  setDnsResponseFlags();

  buffer_.writeBEInt<uint16_t>(response_.id);
  buffer_.writeBEInt<uint16_t>(response_.f.val);
  buffer_.writeBEInt<uint16_t>(response_.questions);
  buffer_.writeBEInt<uint16_t>(response_.answers);
  buffer_.writeBEInt<uint16_t>(response_.authority_rrs);
  buffer_.writeBEInt<uint16_t>(response_.additional_rrs);

  // Copy the query that we are answering into to the response

  // TODO: Find a way to copy this from the original buffer so that we aren't
  // reserializing the data.  We do this for a couple reasons.  Pointer ownership
  // gets a bit hairy when trying to store an offset and a pointer to the original
  // buffer.   Secondly, if there are additional records in the original query
  // we aren't parsing those, so we don't know the complete length of the query.
  buffer_.add(queries.front()->serialize());

  // serialize the answer records and add to the buffer here
  for (const auto& answer_rec : answers) {
    buffer_.add(answer_rec->serialize());
  }

  return true;
}

bool DnsResponseParser::parseResponseData(const Buffer::InstancePtr& buffer) {
  const uint64_t data_length = buffer->length();
  ENVOY_LOG(debug, "In {} with {} bytes", __func__, data_length);

  dumpBuffer("Response", buffer);

  // Successfully able to parse the response
  return true;
}

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
