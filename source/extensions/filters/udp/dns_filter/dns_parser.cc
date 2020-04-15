#include "extensions/filters/udp/dns_filter/dns_parser.h"

#include <iomanip>
#include <sstream>

#include "envoy/network/address.h"

#include "common/common/empty_string.h"
#include "common/network/address_impl.h"
#include "common/network/utility.h"

#include "ares.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

// Don't push upstream
inline void DnsMessageParser::dumpBuffer(const std::string& title,
                                         const Buffer::InstancePtr& buffer, const uint64_t offset) {

  // TODO: We should do no work if the log level is not applicable
  std::stringstream buf;
  const uint64_t data_length = buffer->length();
  const unsigned char* linearize =
      static_cast<const unsigned char*>(buffer->linearize(static_cast<uint32_t>(data_length)));

  for (uint64_t i = offset; i < data_length ; i++) {
    if (i && ((i - offset) % 16 == 0)) {
      buf << "\n";
    }
    buf << std::setfill('0') << std::hex << static_cast<unsigned char>(linearize[i]) << " ";
  }
  ENVOY_LOG(trace, "Starting at {}\n{}\n{}", offset, title, buf.str());
}

// Don't push upstream
inline void DnsMessageParser::dumpFlags(const struct DnsHeader& query) {

  // TODO: We should do no work if the log level is not applicable
  std::stringstream ss{};

  ss << "Query ID: 0x" << std::hex << query.id << "\n";
  ss << "- Query/Response:       " << query.flags.qr << "\n";
  ss << "- Opcode:               " << query.flags.opcode << "\n";
  ss << "- Authoritative Answer: " << query.flags.aa << "\n";
  ss << "- Truncated:            " << query.flags.tc << "\n";
  ss << "- Recursion Desired:    " << query.flags.rd << "\n";
  ss << "- Recursion Available:  " << query.flags.ra << "\n";
  ss << "- Z bit:                " << query.flags.z << "\n";
  ss << "- Authenticated Data    " << query.flags.ad << "\n";
  ss << "- Checking Disabled     " << query.flags.cd << "\n";
  ss << "- Return Code           " << query.flags.rcode << "\n";
  ss << "Questions               " << query.questions << "\n";
  ss << "Answers                 " << query.answers << "\n";
  ss << "Authority RRs           " << query.authority_rrs << "\n";
  ss << "Additional RRs          " << query.additional_rrs << "\n";

  const std::string message = ss.str();

  ENVOY_LOG(trace, "{}", message);
}

inline void BaseDnsRecord::serializeName(Buffer::OwnedImpl& output) {

  // Iterate over a name e.g. "www.domain.com" once and produce a buffer containing each name
  // segment prefixed by its length

  static constexpr char SEPARATOR('.');

  size_t last = 0;
  size_t count = name_.find_first_of(SEPARATOR);
  auto iter = name_.begin();

  while (count != std::string::npos) {

    count -= last;
    output.writeBEInt<uint8_t>(count);
    for (size_t i = 0; i < count; i++) {
      output.writeByte(*iter);
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
  output.writeBEInt<uint8_t>(count);
  for (size_t i = 0; i < count; i++) {
    output.writeByte(*iter);
    ++iter;
  }

  // Terminate the name record with a null byte
  output.writeByte(0x00);
}

// Serialize a DNS Query Record
void DnsQueryRecord::serialize(Buffer::OwnedImpl& output) {

  serializeName(output);
  output.writeBEInt<uint16_t>(type_);
  output.writeBEInt<uint16_t>(class_);
}

// Serialize a DNS Answer Record
void DnsAnswerRecord::serialize(Buffer::OwnedImpl& output) {

  serializeName(output);
  output.writeBEInt<uint16_t>(type_);
  output.writeBEInt<uint16_t>(class_);
  output.writeBEInt<uint32_t>(ttl_);

  ASSERT(ip_addr_ != nullptr);
  const auto ip_address = ip_addr_->ip();

  ASSERT(ip_address != nullptr);
  if (ip_address->ipv6() != nullptr) {
    // Store the 128bit address with 2 64 bit writes
    const absl::uint128 addr6 = ip_address->ipv6()->address();
    output.writeBEInt<uint16_t>(sizeof(addr6));
    output.writeLEInt<uint64_t>(absl::Uint128Low64(addr6));
    output.writeLEInt<uint64_t>(absl::Uint128High64(addr6));
  } else if (ip_address->ipv4() != nullptr) {
    output.writeBEInt<uint16_t>(4);
    output.writeLEInt<uint32_t>(ip_address->ipv4()->address());
  }
}

DnsQueryContextPtr DnsMessageParser::createQueryContext(Network::UdpRecvData& client_request) {
  DnsQueryContextPtr query_context = std::make_unique<DnsQueryContext>(
      client_request.addresses_.local_, client_request.addresses_.peer_);

  query_context->parse_status_ = parseDnsObject(query_context, client_request.buffer_);

  if (!query_context->parse_status_) {
    query_context->response_code_ = DnsResponseCode::FormatError;
    ENVOY_LOG(error, "Unable to parse query buffer from '{}' into a DNS object",
              client_request.addresses_.peer_->ip()->addressAsString());
  }

  return query_context;
}

bool DnsMessageParser::parseDnsObject(DnsQueryContextPtr& context,
                                      const Buffer::InstancePtr& buffer) {

  auto available_bytes = buffer->length();

  // TODO: Remove before pushing upstream
  dumpBuffer(__func__, buffer);

  memset(&incoming_, 0x00, sizeof(incoming_));

  static constexpr uint64_t field_size = sizeof(uint16_t);
  uint64_t offset = 0;
  uint16_t data;

  DnsQueryParseState state_{DnsQueryParseState::Init};

  while (state_ != DnsQueryParseState::Finish) {

    // Each aggregate DNS header field is 2 bytes wide.
    data = buffer->peekBEInt<uint16_t>(offset);
    offset += field_size;
    available_bytes -= field_size;

    // Ensure that we have enough data remaining in the buffer to parse the query
    if (available_bytes < field_size) {
      ENVOY_LOG(error,
                "Exhausted available bytes in the buffer. Insufficient data to parse query field.");
      return false;
    }

    if (offset > buffer->length()) {
      ENVOY_LOG(error, "Buffer read offset [{}] is beyond buffer length [{}].", offset,
                buffer->length());
      return false;
    }

    switch (state_) {
    case DnsQueryParseState::Init:
      incoming_.id = data;
      state_ = DnsQueryParseState::Flags;
      break;

    case DnsQueryParseState::Flags:
      ::memcpy(static_cast<void*>(&incoming_.flags), &data, sizeof(uint16_t));
      state_ = DnsQueryParseState::Questions;
      break;

    case DnsQueryParseState::Questions:
      incoming_.questions = data;
      state_ = DnsQueryParseState::Answers;
      break;

    case DnsQueryParseState::Answers:
      incoming_.answers = data;
      state_ = DnsQueryParseState::Authority;
      break;

    case DnsQueryParseState::Authority:
      incoming_.authority_rrs = data;
      state_ = DnsQueryParseState::Authority2;
      break;

    case DnsQueryParseState::Authority2:
      incoming_.additional_rrs = data;
      state_ = DnsQueryParseState::Finish;
      break;

    case DnsQueryParseState::Finish:
      break;

    default:
      NOT_REACHED_GCOVR_EXCL_LINE;
    }
  }

  // Verify that we still have available data in the buffer to read answer and query records
  if (offset > buffer->length()) {
    ENVOY_LOG(error, "Buffer read offset[{}] is larget than buffer length [{}].", offset,
              buffer->length());
    return false;
  }

  context->id_ = static_cast<uint16_t>(incoming_.id);
  if (context->id_ == 0) {
    ENVOY_LOG(debug, "No ID in query");
    return false;
  }

  // TODO: Remove before pushing upstream
  dumpFlags(incoming_);

  if (incoming_.questions == 0) {
    ENVOY_LOG(trace, "No questions in DNS request");
    return false;
  }

  // Almost always, we will have only one query here. Per the RFC, QDCOUNT is usually 1
  context->queries_.reserve(incoming_.questions);
  for (auto index = 0; index < incoming_.questions; index++) {
    ENVOY_LOG(trace, "Parsing [{}/{}] questions", index, incoming_.questions);
    auto rec = parseDnsQueryRecord(buffer, &offset);
    if (rec == nullptr) {
      ENVOY_LOG(error, "Couldn't parse query record from buffer");
      return false;
    }
    context->queries_.push_back(std::move(rec));
  }

  // Parse all answer records and store them.
  for (auto index = 0; index < incoming_.answers; index++) {
    ENVOY_LOG(trace, "Parsing [{}/{}] answers", index, incoming_.answers);
    auto rec = parseDnsAnswerRecord(buffer, &offset);
    if (rec == nullptr) {
      ENVOY_LOG(error, "Couldn't parse answer record from buffer");
      return false;
    }
    std::string name = rec->name_;
    context->answers_.emplace(name, std::move(rec));
  }

  return true;
}

const std::string DnsMessageParser::parseDnsNameRecord(const Buffer::InstancePtr& buffer,
                                                       uint64_t* available_bytes,
                                                       uint64_t* name_offset) {
  void* buf = buffer->linearize(static_cast<uint32_t>(buffer->length()));
  const unsigned char* linearized_data = static_cast<unsigned char*>(buf);
  const unsigned char* record = linearized_data + *name_offset;
  long encoded_len;
  char* output;

  int result = ares_expand_name(record, linearized_data, buffer->length(), &output, &encoded_len);
  if (result != ARES_SUCCESS) {
    ENVOY_LOG(error, "Unable to expand name record from buffer. result [{}]", result);
    return EMPTY_STRING;
  }

  std::string name(output);
  ares_free_string(output);
  *name_offset += encoded_len;
  *available_bytes -= encoded_len;

  return name;
}

DnsAnswerRecordPtr DnsMessageParser::parseDnsAnswerRecord(const Buffer::InstancePtr& buffer,
                                                          uint64_t* offset) {
  dumpBuffer(__func__, buffer, *offset);

  uint64_t data_offset = *offset;
  uint64_t available_bytes = buffer->length() - data_offset;

  const std::string record_name = parseDnsNameRecord(buffer, &available_bytes, &data_offset);
  if (record_name.empty()) {
    ENVOY_LOG(error, "Unable to parse name record from buffer");
    return nullptr;
  }

  if (available_bytes < (sizeof(uint32_t) + 3 * sizeof(uint16_t))) {
    ENVOY_LOG(error,
              "Insufficient data in buffer to read answer record data."
              "Available bytes: {}",
              available_bytes);
    return nullptr;
  }

  // Parse the record type
  uint16_t record_type;
  record_type = buffer->peekBEInt<uint16_t>(data_offset);
  data_offset += sizeof(record_type);
  available_bytes -= sizeof(record_type);

  // Parse the record class
  uint16_t record_class;
  record_class = buffer->peekBEInt<uint16_t>(data_offset);
  data_offset += sizeof(record_class);
  available_bytes -= sizeof(record_class);

  // Parse the record TTL
  uint32_t ttl;
  ttl = buffer->peekBEInt<uint32_t>(data_offset);
  data_offset += sizeof(ttl);
  available_bytes -= sizeof(ttl);

  // Parse the Data Length and address data record
  uint16_t data_length;
  data_length = buffer->peekBEInt<uint16_t>(data_offset);
  data_offset += sizeof(data_length);
  available_bytes -= sizeof(data_length);

  // Verify that we are still have data in the buffer with the record address
  if (available_bytes < data_length) {
    ENVOY_LOG(error, "Answer record data length: {} is more than the available bytes {} in buffer",
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

    data_offset += data_length;

  } else if (record_type == DnsRecordType::AAAA) {
    sockaddr_in6 sa6;
    uint8_t* address6_bytes = reinterpret_cast<uint8_t*>(&sa6.sin6_addr.s6_addr);
    static constexpr size_t count = sizeof(absl::uint128) / sizeof(uint8_t);
    for (size_t index = 0; index < count; index++) {
      *address6_bytes++ = buffer->peekLEInt<uint8_t>(data_offset++);
    }

    ip_addr = std::make_shared<Network::Address::Ipv6Instance>(sa6, true);
  }

  ASSERT(ip_addr != nullptr);
  ENVOY_LOG(debug, "Parsed address [{}] from record type [{}]: offset {}",
            ip_addr->ip()->addressAsString(), record_type, data_offset);

  *offset = data_offset;

  return std::make_unique<DnsAnswerRecord>(/*static_cast<uint16_t>(incoming_.id), */ record_name,
                                           record_type, record_class, ttl, std::move(ip_addr));
}

DnsQueryRecordPtr DnsMessageParser::parseDnsQueryRecord(const Buffer::InstancePtr& buffer,
                                                        uint64_t* offset) {
  uint64_t name_offset = *offset;
  uint64_t available_bytes = buffer->length() - name_offset;

  if (available_bytes == 0) {
    ENVOY_LOG(error, "No available data in buffer to parse a query record");
    return nullptr;
  }

  const std::string record_name = parseDnsNameRecord(buffer, &available_bytes, &name_offset);
  if (record_name.empty()) {
    ENVOY_LOG(error, "Unable to parse name record from buffer");
    return nullptr;
  }

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

  // Read the record class. This value is almost always 1 for internet address records
  uint16_t record_class;
  record_class = buffer->peekBEInt<uint16_t>(name_offset);
  name_offset += sizeof(record_class);

  auto rec = std::make_unique<DnsQueryRecord>(/*static_cast<uint16_t>(incoming_.id), */ record_name,
                                              record_type, record_class);
  rec->query_time_ms_ = std::make_unique<Stats::HistogramCompletableTimespanImpl>(
      query_latency_histogram_, timesource_);

  // stop reading he buffer here since we aren't parsing additional records
  ENVOY_LOG(trace, "Extracted query record. Name: {} type: {} class: {}", rec->name_, rec->type_,
            rec->class_);

  *offset = name_offset;

  return rec;
}

void DnsMessageParser::setDnsResponseFlags(DnsQueryContextPtr& query_context,
                                           const uint16_t questions, const uint16_t answers) {

  // Copy the transaction ID
  generated_.id = incoming_.id;

  // Signify that this is a response to a query
  generated_.flags.qr = 1;

  generated_.flags.opcode = incoming_.flags.opcode;

  generated_.flags.aa = 0;
  generated_.flags.tc = 0;

  // Copy Recursion flags
  generated_.flags.rd = incoming_.flags.rd;

  // TODO: This should be predicated on whether the user enables external lookups
  generated_.flags.ra = 0;

  // reserved flag is not set
  generated_.flags.z = 0;

  // Set the authenticated flags to zero
  generated_.flags.ad = 0;

  generated_.flags.cd = 0;

  generated_.answers = answers;

  // The ID must be non-zero so that we can associate the response with the query
  generated_.flags.rcode = query_context->response_code_;

  // Set the number of questions we are responding to
  generated_.questions = questions;

  // We will not include any additional records
  generated_.authority_rrs = 0;
  generated_.additional_rrs = 0;

  // TODO: Remove before pushing upstream
  dumpFlags(generated_);
}

void DnsMessageParser::buildDnsAnswerRecord(DnsQueryContextPtr& context,
                                            const DnsQueryRecord& query_rec, const uint32_t ttl,
                                            Network::Address::InstanceConstSharedPtr ipaddr) {

  // Verify that we have an address matching the query record type
  switch (query_rec.type_) {
  case DnsRecordType::AAAA:
    if (ipaddr->ip()->ipv6() == nullptr) {
      ENVOY_LOG(error, "Unable to return IPV6 address for query");
      return;
    }
    break;

  case DnsRecordType::A:
    if (ipaddr->ip()->ipv4() == nullptr) {
      ENVOY_LOG(error, "Unable to return IPV4 address for query");
      return;
    }
    break;

  default:
    ENVOY_LOG(error, "record type [{}] not supported", query_rec.type_);
    return;
  }

  // The answer record could contain types other than IP's. We will support only IP addresses for
  // the moment
  auto answer_record = std::make_unique<DnsAnswerRecord>(
      /*query_rec.id_, */ query_rec.name_, query_rec.type_, query_rec.class_, ttl,
      std::move(ipaddr));

  context->answers_.emplace(query_rec.name_, std::move(answer_record));
}

void DnsMessageParser::setResponseCode(DnsQueryContextPtr& context,
                                       const uint16_t serialized_queries,
                                       const uint16_t serialized_answers) {

  // If the question is malformed, don't change the response
  if (context->response_code_ == DnsResponseCode::FormatError) {
    return;
  }

  // Check for unsupported request types
  for (const auto& query : context->queries_) {
    if (query->type_ != DnsRecordType::A && query->type_ != DnsRecordType::AAAA) {
      context->response_code_ = DnsResponseCode::NotImplemented;
      return;
    }
  }

  // Output validation
  if (serialized_queries == 0) {
    context->response_code_ = DnsResponseCode::FormatError;
    return;
  }

  if (serialized_answers == 0) {
    context->response_code_ = DnsResponseCode::NameError;
    return;
  }

  context->response_code_ = DnsResponseCode::NoError;
}

void DnsMessageParser::buildResponseBuffer(DnsQueryContextPtr& query_context,
                                           Buffer::OwnedImpl& buffer) {

  // Ensure that responses stay below the 512 byte byte limit. If we are to exceed this we must add
  // DNS extension fields
  //
  // Note:  There is Network::MAX_UDP_PACKET_SIZE, which is defined as 1500 bytes. If we support
  // DNS extensions that support up to 4096 bytes, we will have to keep this 1500 byte limit in
  // mind.
  static constexpr uint64_t max_dns_response_size{512};

  // Each response must have DNS flags, which take 4 bytes. Account for them immediately so that we
  // can adjust the number of returned answers to remain under the limit
  uint64_t total_buffer_size = 4;
  uint16_t serialized_answers = 0;
  uint16_t serialized_queries = 0;

  Buffer::OwnedImpl query_buffer{};
  Buffer::OwnedImpl answer_buffer{};

  ENVOY_LOG(debug, "Building response for query ID [{}]", query_context->id_);

  for (const auto& query : query_context->queries_) {

    // Serialize and remove the query from our list
    ++serialized_queries;
    query->serialize(query_buffer);
    total_buffer_size += query_buffer.length();

    for (const auto& answer : query_context->answers_) {

      if (answer.first != query->name_) {
        continue;
      }

      Buffer::OwnedImpl serialized_answer;
      answer.second->serialize(serialized_answer);
      const uint64_t serialized_answer_length = serialized_answer.length();

      if ((total_buffer_size + serialized_answer_length) > max_dns_response_size) {
        break;
      }

      ++serialized_answers;
      total_buffer_size += serialized_answer_length;
      answer_buffer.add(serialized_answer);
    }

    query->query_time_ms_->complete();
    ENVOY_LOG(debug, "Query delay: {}", query->query_time_ms_->elapsed().count());
  }

  // Build the response buffer for transmission to the client
  setResponseCode(query_context, serialized_queries, serialized_answers);
  setDnsResponseFlags(query_context, serialized_queries, serialized_answers);

  buffer.writeBEInt<uint16_t>(generated_.id);

  uint16_t flags;
  ::memcpy(&flags, static_cast<void*>(&generated_.flags), sizeof(uint16_t));
  buffer.writeBEInt<uint16_t>(flags);

  buffer.writeBEInt<uint16_t>(generated_.questions);
  buffer.writeBEInt<uint16_t>(generated_.answers);
  buffer.writeBEInt<uint16_t>(generated_.authority_rrs);
  buffer.writeBEInt<uint16_t>(generated_.additional_rrs);

  // write the queries and answers
  buffer.move(query_buffer);
  buffer.move(answer_buffer);
}

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
