#pragma once

#include <cstdint>
#include <string>

#include "envoy/common/platform.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/byte_order.h"
#include "common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace DnsFilter {

/**
 * Helper for extracting DNS record from a buffer.
 *
 * If at any point a peek is tried beyond max_len, an EnvoyException
 * will be thrown. This is important to protect Envoy against malformed
 * requests (e.g.: when the declared and actual length don't match).
 *
 * Note: DNS Data is in network byte order (big-endian).
 */
class BufferHelper : public Logger::Loggable<Logger::Id::filter> {
public:
  BufferHelper(uint32_t max_len) : max_len_(max_len) {}

  uint16_t peekUint16(Buffer::Instance& buffer, uint64_t& offset);
  int32_t peekInt32(Buffer::Instance& buffer, uint64_t& offset);
  int64_t peekInt64(Buffer::Instance& buffer, uint64_t& offset);
  std::string peekString(Buffer::Instance& buffer, uint64_t& offset);
  bool peekBool(Buffer::Instance& buffer, uint64_t& offset);
  void skip(uint32_t len, uint64_t& offset);
  void reset() { current_ = 0; }

private:
  void ensureMaxLen(uint32_t size);

  const uint32_t max_len_;
  uint32_t current_{};
};

} // namespace DnsFilter
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
