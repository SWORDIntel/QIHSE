#include "enrichment/bgp_update_decoder.h"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tgmap::enrichment {
namespace {

constexpr std::size_t kHeaderLength = 19U;
constexpr std::size_t kMaximumMessageLength = 4096U;
constexpr std::uint8_t kUpdateType = 2U;
constexpr std::uint8_t kExtendedLengthFlag = 0x10U;
constexpr std::uint8_t kAsPathAttribute = 2U;
constexpr std::uint8_t kAs4PathAttribute = 17U;
constexpr std::uint8_t kMpReachNlriAttribute = 14U;
constexpr std::uint8_t kMpUnreachNlriAttribute = 15U;
constexpr std::uint8_t kAsSequence = 2U;
constexpr std::uint16_t kIpv6Afi = 2U;
constexpr std::uint8_t kUnicastSafi = 1U;

std::uint16_t read_u16(std::span<const std::uint8_t> bytes, std::size_t* offset,
                       std::string_view field) {
  if (*offset > bytes.size() || bytes.size() - *offset < 2U) {
    throw std::invalid_argument("BGP UPDATE is truncated in " + std::string(field));
  }
  const auto value = static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[*offset]) << 8U) |
      static_cast<std::uint16_t>(bytes[*offset + 1U]));
  *offset += 2U;
  return value;
}

std::uint32_t read_asn(std::span<const std::uint8_t> bytes, std::size_t* offset,
                       std::size_t width) {
  if (*offset > bytes.size() || bytes.size() - *offset < width) {
    throw std::invalid_argument("BGP UPDATE AS path is truncated");
  }
  std::uint32_t result = 0U;
  for (std::size_t index = 0U; index < width; ++index) {
    result = static_cast<std::uint32_t>((result << 8U) | bytes[*offset + index]);
  }
  *offset += width;
  if (result == 0U) {
    throw std::invalid_argument("BGP UPDATE AS path contains ASN zero");
  }
  return result;
}

std::vector<std::string> parse_ipv4_prefixes(std::span<const std::uint8_t> bytes) {
  std::vector<std::string> prefixes;
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    const auto prefix_length = bytes[offset++];
    if (prefix_length > 32U) {
      throw std::invalid_argument("BGP UPDATE contains a non-IPv4 NLRI prefix length");
    }
    const auto octets = static_cast<std::size_t>((prefix_length + 7U) / 8U);
    if (bytes.size() - offset < octets) {
      throw std::invalid_argument("BGP UPDATE NLRI is truncated");
    }
    std::array<std::uint8_t, 4U> address{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), octets, address.begin());
    offset += octets;
    std::array<char, INET_ADDRSTRLEN> rendered{};
    if (inet_ntop(AF_INET, address.data(), rendered.data(), rendered.size()) == nullptr) {
      throw std::invalid_argument("BGP UPDATE could not render IPv4 NLRI");
    }
    prefixes.emplace_back(std::string(rendered.data()) + "/" + std::to_string(prefix_length));
  }
  return prefixes;
}

std::vector<std::string> parse_ipv6_prefixes(std::span<const std::uint8_t> bytes) {
  std::vector<std::string> prefixes;
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    const auto prefix_length = bytes[offset++];
    if (prefix_length > 128U) {
      throw std::invalid_argument("BGP UPDATE contains a non-IPv6 MP NLRI prefix length");
    }
    const auto octets = static_cast<std::size_t>((prefix_length + 7U) / 8U);
    if (bytes.size() - offset < octets) {
      throw std::invalid_argument("BGP UPDATE IPv6 MP NLRI is truncated");
    }
    std::array<std::uint8_t, 16U> address{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), octets, address.begin());
    offset += octets;
    std::array<char, INET6_ADDRSTRLEN> rendered{};
    if (inet_ntop(AF_INET6, address.data(), rendered.data(), rendered.size()) == nullptr) {
      throw std::invalid_argument("BGP UPDATE could not render IPv6 MP NLRI");
    }
    prefixes.emplace_back(std::string(rendered.data()) + "/" + std::to_string(prefix_length));
  }
  return prefixes;
}

void require_ipv6_unicast_family(const std::span<const std::uint8_t> payload,
                                 const std::string_view attribute_name) {
  std::size_t offset = 0U;
  const auto afi = read_u16(payload, &offset, std::string(attribute_name) + " AFI");
  if (afi != kIpv6Afi || offset >= payload.size() || payload[offset++] != kUnicastSafi) {
    throw std::invalid_argument("BGP UPDATE " + std::string(attribute_name) +
                                " is not IPv6 unicast");
  }
}

std::vector<std::string> parse_mp_reach_ipv6(const std::span<const std::uint8_t> payload) {
  require_ipv6_unicast_family(payload, "MP_REACH_NLRI");
  std::size_t offset = 3U;
  if (offset >= payload.size()) {
    throw std::invalid_argument("BGP UPDATE MP_REACH_NLRI is truncated before next-hop length");
  }
  const auto next_hop_length = static_cast<std::size_t>(payload[offset++]);
  if (next_hop_length != 16U && next_hop_length != 32U) {
    throw std::invalid_argument("BGP UPDATE MP_REACH_NLRI has an invalid IPv6 next-hop length");
  }
  if (payload.size() - offset < next_hop_length + 1U) {
    throw std::invalid_argument("BGP UPDATE MP_REACH_NLRI next hop is truncated");
  }
  offset += next_hop_length;
  if (payload[offset++] != 0U) {
    throw std::invalid_argument("BGP UPDATE MP_REACH_NLRI reserved field is nonzero");
  }
  return parse_ipv6_prefixes(payload.subspan(offset));
}

std::vector<std::string> parse_mp_unreach_ipv6(const std::span<const std::uint8_t> payload) {
  require_ipv6_unicast_family(payload, "MP_UNREACH_NLRI");
  return parse_ipv6_prefixes(payload.subspan(3U));
}

struct ParsedAsPath final {
  std::vector<std::uint32_t> members;
  std::optional<std::uint32_t> origin;
};

ParsedAsPath parse_as_path(std::span<const std::uint8_t> bytes, std::size_t asn_width) {
  ParsedAsPath result;
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    if (bytes.size() - offset < 2U) {
      throw std::invalid_argument("BGP UPDATE AS path segment is truncated");
    }
    const auto segment_type = bytes[offset++];
    const auto count = static_cast<std::size_t>(bytes[offset++]);
    if ((segment_type != 1U && segment_type != kAsSequence) || count == 0U ||
        count > (bytes.size() - offset) / asn_width) {
      throw std::invalid_argument("BGP UPDATE AS path segment is invalid");
    }
    std::optional<std::uint32_t> final_member;
    for (std::size_t index = 0U; index < count; ++index) {
      const auto asn = read_asn(bytes, &offset, asn_width);
      result.members.push_back(asn);
      final_member = asn;
    }
    result.origin = segment_type == kAsSequence ? final_member : std::nullopt;
  }
  return result;
}

}  // namespace

DecodedBgpUpdate decode_bgp_update(const std::span<const std::uint8_t> message) {
  if (message.size() < kHeaderLength || message.size() > kMaximumMessageLength) {
    throw std::invalid_argument("BGP UPDATE length is outside the permitted range");
  }
  if (!std::all_of(message.begin(), message.begin() + 16, [](const std::uint8_t value) {
        return value == 0xffU;
      })) {
    throw std::invalid_argument("BGP UPDATE marker is invalid");
  }
  std::size_t offset = 16U;
  if (read_u16(message, &offset, "header length") != message.size() ||
      message[offset++] != kUpdateType) {
    throw std::invalid_argument("BGP message is not one complete UPDATE");
  }
  const auto withdrawn_length = static_cast<std::size_t>(read_u16(message, &offset, "withdrawn length"));
  if (message.size() - offset < withdrawn_length) {
    throw std::invalid_argument("BGP UPDATE withdrawn-routes field is truncated");
  }
  const auto withdrawn = parse_ipv4_prefixes(message.subspan(offset, withdrawn_length));
  offset += withdrawn_length;
  const auto attributes_length = static_cast<std::size_t>(read_u16(message, &offset, "attribute length"));
  if (message.size() - offset < attributes_length) {
    throw std::invalid_argument("BGP UPDATE path-attributes field is truncated");
  }
  const auto attributes_end = offset + attributes_length;
  std::optional<ParsedAsPath> as_path;
  std::optional<ParsedAsPath> as4_path;
  std::optional<std::vector<std::string>> announced_ipv6;
  std::optional<std::vector<std::string>> withdrawn_ipv6;
  while (offset < attributes_end) {
    if (attributes_end - offset < 3U) {
      throw std::invalid_argument("BGP UPDATE path attribute is truncated");
    }
    const auto flags = message[offset++];
    const auto type = message[offset++];
    const auto length = (flags & kExtendedLengthFlag) != 0U
                            ? static_cast<std::size_t>(read_u16(message, &offset, "attribute length"))
                            : static_cast<std::size_t>(message[offset++]);
    if (attributes_end - offset < length) {
      throw std::invalid_argument("BGP UPDATE path attribute payload is truncated");
    }
    const auto payload = message.subspan(offset, length);
    offset += length;
    if (type == kAsPathAttribute) as_path = parse_as_path(payload, 2U);
    if (type == kAs4PathAttribute) as4_path = parse_as_path(payload, 4U);
    if (type == kMpReachNlriAttribute) {
      if (announced_ipv6.has_value()) {
        throw std::invalid_argument("BGP UPDATE contains duplicate MP_REACH_NLRI");
      }
      announced_ipv6 = parse_mp_reach_ipv6(payload);
    }
    if (type == kMpUnreachNlriAttribute) {
      if (withdrawn_ipv6.has_value()) {
        throw std::invalid_argument("BGP UPDATE contains duplicate MP_UNREACH_NLRI");
      }
      withdrawn_ipv6 = parse_mp_unreach_ipv6(payload);
    }
  }
  if (offset != attributes_end) {
    throw std::invalid_argument("BGP UPDATE path attributes are malformed");
  }
  DecodedBgpUpdate result{.announced_prefixes = parse_ipv4_prefixes(message.subspan(offset)),
                          .withdrawn_prefixes = std::move(withdrawn),
                          .announced_ipv6_prefixes = announced_ipv6.value_or(std::vector<std::string>{}),
                          .withdrawn_ipv6_prefixes = withdrawn_ipv6.value_or(std::vector<std::string>{}),
                          .as_path = as4_path.has_value() ? as4_path->members
                                                           : (as_path.has_value() ? as_path->members
                                                                                  : std::vector<std::uint32_t>{}),
                          .origin_asn = as4_path.has_value() ? as4_path->origin
                                                              : (as_path.has_value() ? as_path->origin
                                                                                     : std::nullopt)};
  if ((!result.announced_prefixes.empty() || !result.announced_ipv6_prefixes.empty()) &&
      !result.origin_asn.has_value()) {
    throw std::invalid_argument("BGP UPDATE announcement has no unambiguous AS origin");
  }
  return result;
}

}  // namespace tgmap::enrichment
