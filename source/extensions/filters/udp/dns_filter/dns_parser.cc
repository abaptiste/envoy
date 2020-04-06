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
void DnsQueryRecord::serialize(Buffer::OwnedImpl& output) {
  buffer_.drain(buffer_.length());

  serializeName();
  buffer_.writeBEInt<uint16_t>(type_);
  buffer_.writeBEInt<uint16_t>(class_);

  output.move(buffer_);
}

// Serialize a DNS Answer Record
void DnsAnswerRecord::serialize(Buffer::OwnedImpl& output) {
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

  output.move(buffer_);
}

bool DnsMessageParser::parseDnsObject(const Buffer::InstancePtr& buffer) {

  auto available_bytes = buffer->length();

  memset(&incoming_, 0x00, sizeof(incoming_));

  static constexpr uint64_t field_size = sizeof(uint16_t);
  uint64_t offset = 0;
  uint16_t data;

  DnsQueryParseState state_{DnsQueryParseState::Init};

  while (state_ != DnsQueryParseState::Finish) {

    // Ensure that we have enough data remaining in the buffer to parse the query
    if (available_bytes < field_size) {
      ENVOY_LOG(error,
                "Exhausted available bytes in the buffer. Insufficient data to parse query field.");
      return false;
    }

    // Each aggregate DNS header field is 2 bytes wide.
    data = buffer->peekBEInt<uint16_t>(offset);
    offset += field_size;
    available_bytes -= field_size;

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

  // Each dns request has a Identification ID. This is used to match the request and replies.
  // We should not see a duplicate ID when handling DNS requests. The ID is removed from the
  // active transactions queue when we build a response for the identified query
  const uint16_t id = static_cast<uint16_t>(incoming_.id);
  if (std::find(active_transactions_.begin(), active_transactions_.end(), id) !=
      active_transactions_.end()) {
    ENVOY_LOG(error, "The filter has already encountered ID {} in a previous request", id);
    return false;
  }

  // Double check that this ID is not already being handled.
  if (queries_.find(id) != queries_.end()) {
    ENVOY_LOG(
        error,
        "There are queries matching ID {} from a previous request for which we have not responded",
        id);
    return false;
  }

  active_transactions_.push_back(id);

  // Almost always, we will have only one query here
  for (auto index = 0; index < incoming_.questions; index++) {
    ENVOY_LOG(trace, "Parsing [{}/{}] questions", index, incoming_.questions);
    auto rec = parseDnsQueryRecord(buffer, &offset);
    if (rec == nullptr) {
      ENVOY_LOG(error, "Couldn't parse query record from buffer");
      return false;
    }
    storeQueryRecord(std::move(rec));
  }

  // Parse all answer records and store them
  for (auto index = 0; index < incoming_.answers; index++) {
    ENVOY_LOG(trace, "Parsing [{}/{}] answers", index, incoming_.answers);
    auto rec = parseDnsAnswerRecord(buffer, &offset);
    if (rec == nullptr) {
      ENVOY_LOG(error, "Couldn't parse answer record from buffer");
      return false;
    }
    storeAnswerRecord(std::move(rec));
  }

  return true;
}

const std::string DnsMessageParser::parseDnsNameRecord(const Buffer::InstancePtr& buffer,
                                                       uint64_t* available_bytes,
                                                       uint64_t* name_offset) {
  std::stringstream name_ss{};
  unsigned char c;

  do {
    // Read the name segment length or flag;
    c = buffer->peekBEInt<unsigned char>(*name_offset);
    *name_offset += sizeof(unsigned char);
    *available_bytes -= sizeof(unsigned char);

    if (c == 0xc0) {
      // This is a compressed response. Get the offset in the query record where the domain name
      // begins. This is done to reduce the name duplication in DNS answer buffers.
      c = buffer->peekBEInt<unsigned char>(*name_offset);

      // We will restart the loop from this offset and read until we encounter a null byte
      // signifying the end of the name
      *name_offset = static_cast<uint64_t>(c);

      continue;

    } else if (c == 0x00) {
      // We've reached the end of the query.
      ENVOY_LOG(trace, "End of name: [{}] {}", name_ss.str(), *name_offset);
      break;
    }

    const uint64_t segment_length = static_cast<uint64_t>(c);

    // Verify that we have enough data to read the segment length
    if (segment_length > *available_bytes) {
      ENVOY_LOG(error,
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

DnsAnswerRecordPtr DnsMessageParser::parseDnsAnswerRecord(const Buffer::InstancePtr& buffer,
                                                          uint64_t* offset) {
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

  return std::make_unique<DnsAnswerRecord>(static_cast<uint16_t>(incoming_.id), record_name,
                                           record_type, record_class, ttl, std::move(ip_addr));
}

DnsQueryRecordPtr DnsMessageParser::parseDnsQueryRecord(const Buffer::InstancePtr& buffer,
                                                        uint64_t* offset) {
  uint64_t name_offset = *offset;
  uint64_t available_bytes = buffer->length() - name_offset;

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

  // This is shared because we use the query from a list when building the response.
  // Using a shared pointer avoids duplicating this data in the asynchronous resolution path
  auto rec = std::make_shared<DnsQueryRecord>(static_cast<uint16_t>(incoming_.id), record_name,
                                              record_type, record_class);

  // stop reading he buffer here since we aren't parsing additional records
  ENVOY_LOG(trace, "Extracted query record. Name: {} type: {} class: {}", rec->name_, rec->type_,
            rec->class_);

  *offset = name_offset;

  return rec;
}

void DnsMessageParser::setDnsResponseFlags(const uint16_t questions, const uint16_t answers) {

  // Copy the transaction ID
  generated_.id = incoming_.id;

  // Signify that this is a response to a query
  generated_.flags.qr = 1;

  generated_.flags.opcode = incoming_.flags.opcode;

  generated_.flags.aa = 0;
  generated_.flags.tc = 0;

  // Copy Recursion flags
  generated_.flags.rd = incoming_.flags.rd;

  // TODO(abaptiste): This should be predicated on whether the user enables external lookups
  generated_.flags.ra = 0;

  // reserved flag is not set
  generated_.flags.z = 0;

  // Set the authenticated flags to zero
  generated_.flags.ad = 0;

  generated_.flags.cd = 0;

  generated_.answers = answers;

  // The ID must be non-zero so that we can associate the response with the query
  if (incoming_.id == 0) {
    generated_.flags.rcode = DnsResponseCode::FormatError;
  } else {
    generated_.flags.rcode = answers == 0 ? DnsResponseCode::NameError : DnsResponseCode::NoError;
  }

  // Set the number of questions we are responding to
  generated_.questions = questions;

  // We will not include any additional records
  generated_.authority_rrs = 0;
  generated_.additional_rrs = 0;
}

void DnsMessageParser::buildDnsAnswerRecord(const DnsQueryRecord& query_rec, const uint32_t ttl,
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
      query_rec.id_, query_rec.name_, query_rec.type_, query_rec.class_, ttl, std::move(ipaddr));

  storeAnswerRecord(std::move(answer_record));
}

void DnsMessageParser::buildResponseBuffer(Buffer::OwnedImpl& buffer) {

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

  if (!active_transactions_.empty()) {

    // Determine and de-queue the ID of the query to which we are responding
    const uint16_t id = active_transactions_.front();
    active_transactions_.pop_front();

    // Get the queries associated with this ID
    const auto& query_iter = queries_.find(id);

    if (query_iter != queries_.end()) {
      for (const auto& query : query_iter->second) {

        // Serialize and remove the query from our list
        ++serialized_queries;
        query->serialize(query_buffer);
        total_buffer_size += query_buffer.length();

        // Find the answer record list corresponding to this query
        const auto& answer_list = answers_.find(query->name_);
        if (answer_list == answers_.end()) {
          continue;
        }

        // Serialize each answer record and stop before we exceed 512 bytes
        auto& answers = answer_list->second;
        auto answer = answers.begin();
        while (answer != answers.end()) {

          // It is possible that we may have different transactions looking for the same domain ID.
          // Only serialize answers with the same transaction ID
          if ((*answer)->id_ == id) {
            Buffer::OwnedImpl serialized_answer;
            (*answer)->serialize(serialized_answer);
            const uint64_t serialized_answer_length = serialized_answer.length();

            if ((total_buffer_size + serialized_answer_length) > max_dns_response_size) {
              break;
            }

            ++serialized_answers;
            total_buffer_size += serialized_answer_length;
            answer_buffer.add(serialized_answer);
            answer = answers.erase(answer);
            continue;
          }
          ++answer;
        }

        // If all answers for this domain matched the current ID, the answer_list will now be empty
        // and can be purged.
        if (answer_list->second.empty()) {
          answers_.erase(answer_list);
        }
      }
    }
  }

  // Build the response buffer for transmission to the client
  setDnsResponseFlags(serialized_queries, serialized_answers);

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

void DnsMessageParser::storeQueryRecord(DnsQueryRecordPtr rec) {

  const uint16_t id = rec->id_;
  const auto& query_iter = queries_.find(id);

  if (query_iter == queries_.end()) {
    std::list<DnsQueryRecordPtr> query_list{};
    query_list.push_back(std::move(rec));
    queries_.emplace(id, std::move(query_list));
  } else {
    // There should really be only one record here, but allow adding others since the
    // protocol allows it.
    query_iter->second.push_back(std::move(rec));
  }
}

void DnsMessageParser::storeAnswerRecord(DnsAnswerRecordPtr rec) {

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

uint64_t DnsMessageParser::queriesUnanswered(const uint16_t id) {

  const auto querylist = queries_.find(id);

  // This shouldn't be the case since this function is called before serialization. We should have
  // a query matching the ID, and from the query we can determine whether there are answers for it.
  ASSERT(querylist != queries_.end());

  for (const auto& query : querylist->second) {
    const auto& answers = answers_.find(query->name_);

    // There are no answers corresponding to this query's name.
    if (answers == answers_.end()) {
      break;
    }

    // We found an answer record matching the query ID
    for (const auto& answer : answers->second) {
      if (answer->id_ == id) {
        return false;
      }
    }
  }

  // proceed with another method of resolution
  return true;
}

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
