#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace tgmap::enrichment {

// Represents the read-only IPv4-unicast and IPv6-unicast information present in one validated BGP UPDATE.
// It is intentionally separate from Fact because a withdrawal does not carry an origin ASN.
struct DecodedBgpUpdate final {
  std::vector<std::string> announced_prefixes;
  std::vector<std::string> withdrawn_prefixes;
  std::vector<std::string> announced_ipv6_prefixes;
  std::vector<std::string> withdrawn_ipv6_prefixes;
  std::vector<std::uint32_t> as_path;
  std::optional<std::uint32_t> origin_asn;
};

// Decodes one complete BGP UPDATE message held in caller-owned memory. The decoder accepts only
// the RFC framing, IPv4-unicast NLRI, and IPv6-unicast MP_REACH_NLRI/MP_UNREACH_NLRI needed for offline
// RIB/update import. It never
// opens a socket, starts a peer, sends data, or changes routing state.
[[nodiscard]] DecodedBgpUpdate decode_bgp_update(std::span<const std::uint8_t> message);

}  // namespace tgmap::enrichment
