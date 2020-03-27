#include "dns_filter_test_utils.h"

#include "extensions/filters/udp/dns_filter/dns_filter.h"

#include "test/test_common/utility.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {
namespace Utils {

std::string buildQueryForDomain(const std::string& name, uint16_t rec_type, uint16_t rec_class) {

  DnsMessageStruct query{};

  // Generate a random query ID
  query.id = 1234; // Util::generateRandom64() & 0xFFFF;

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

} // namespace Utils
} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
