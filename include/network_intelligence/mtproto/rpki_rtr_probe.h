#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace tgmap::mtproto {

// ── RPKI ROA (Route Origin Authorization) ─────────────────────────────────────

// A single ROA entry from the RTR cache.
// A ROA authorizes `origin_asn` to announce `prefix` with a maximum prefix length
// of `max_length` (which may be longer than `prefix_length` to allow for sub-prefixes).
struct RoaEntry final {
  std::uint32_t origin_asn = 0U;       // AS number authorized to originate
  std::string prefix;                   // e.g. "149.154.160.0/20"
  std::uint8_t prefix_length = 0U;      // CIDR prefix length
  std::uint8_t max_length = 0U;         // Maximum prefix length covered by this ROA
  std::string address_family;           // "ipv4" or "ipv6"

  void validate() const;
};

// RPKI validation state for a prefix+origin pair.
enum class RpkiValidationState {
  Valid,       // Prefix covered by a ROA, origin AS matches
  Invalid,     // Prefix covered by a ROA, origin AS does NOT match
  NotFound,    // No ROA covers this prefix
};

// ── RTR Protocol types (RFC 6810) ─────────────────────────────────────────────

// RTR PDU types.
enum class RtrPduType : std::uint8_t {
  SerialNotify  = 0,
  SerialQuery   = 1,
  ResetQuery    = 2,
  CacheResponse = 3,
  Ipv4Prefix    = 4,
  Ipv6Prefix    = 5,
  EndOfData     = 6,
  CacheReset    = 8,
  ErrorReport   = 10,
};

// ── RTR Client ────────────────────────────────────────────────────────────────

struct RtrClientOptions final {
  std::string host = "127.0.0.1";
  std::uint16_t port = 8282U;  // Default RTR port
  std::chrono::milliseconds connect_timeout{5000};
  std::chrono::milliseconds read_timeout{10000};
  // RTR protocol version (0 = RFC 6810, 1 = draft-ietf-sidr-rpki-rtr-rfc6810-bis)
  std::uint8_t version = 1U;

  void validate() const;
};

// Injectable RTR source — abstracts the RTR protocol for unit testing.
class RtrSource {
 public:
  virtual ~RtrSource() = default;

  // Fetch the full ROA cache from the RTR server.
  // Returns the ROA entries and the current serial number.
  [[nodiscard]] virtual std::vector<RoaEntry> fetch_roas(
      const RtrClientOptions& options) = 0;
};

// Real RTR client that connects to an RTR server via TCP and implements
// the RTR protocol (RFC 6810) to retrieve the ROA cache.
class RtrTcpClient final : public RtrSource {
 public:
  [[nodiscard]] std::vector<RoaEntry> fetch_roas(
      const RtrClientOptions& options) override;
};

// ── ROA cache with validation ─────────────────────────────────────────────────

// In-memory ROA cache with prefix-based validation.
class RoaCache final {
 public:
  // Load ROAs into the cache, replacing any existing entries.
  void load(const std::vector<RoaEntry>& roas);

  // Validate a prefix+origin ASN pair against the ROA cache.
  [[nodiscard]] RpkiValidationState validate(
      const std::string& prefix, std::uint8_t prefix_length,
      std::uint32_t origin_asn) const;

  // Validate an IP address against the ROA cache by finding the
  // longest matching prefix and checking the origin ASN.
  [[nodiscard]] RpkiValidationState validate_ip(
      const std::string& ip, std::uint32_t origin_asn) const;

  [[nodiscard]] std::size_t size() const noexcept { return roas_.size(); }
  [[nodiscard]] bool empty() const noexcept { return roas_.empty(); }
  [[nodiscard]] const std::vector<RoaEntry>& entries() const noexcept { return roas_; }

 private:
  std::vector<RoaEntry> roas_;
};

// ── Pure validation function (fully testable, no network) ─────────────────────

// Validate a prefix+origin ASN against a list of ROAs.
// This is the core classification function — pure, deterministic, offline-testable.
[[nodiscard]] RpkiValidationState validate_against_roas(
    const std::vector<RoaEntry>& roas,
    const std::string& prefix, std::uint8_t prefix_length,
    std::uint32_t origin_asn);

// ── Helpers ───────────────────────────────────────────────────────────────────

[[nodiscard]] std::string to_string(RpkiValidationState state);

// Check if an IP address falls within a prefix.
[[nodiscard]] bool ip_in_prefix(
    const std::string& ip, const std::string& prefix,
    std::uint8_t prefix_length);

// Parse a CIDR prefix string into prefix + length.
[[nodiscard]] std::pair<std::string, std::uint8_t> parse_prefix(const std::string& cidr);

// ── RPKI RTR probe result ─────────────────────────────────────────────────────

struct RpkiRtrProbeResult final {
  std::string schema = "tgmap.rpki-rtr-probe.v1";
  std::string endpoint_identity;
  std::string ip;
  std::string prefix;           // Longest covering prefix from BGP probe
  std::uint8_t prefix_length = 0U;
  std::uint32_t origin_asn = 0U;
  std::string validation_state; // "valid", "invalid", "not_found"
  std::size_t roa_cache_size = 0U;
  std::string rtr_server;
  std::chrono::milliseconds elapsed{};

  void validate() const;
};

// Probe RPKI validation state for an endpoint using a local RTR cache.
// The RTR source is injected for testability.
[[nodiscard]] RpkiRtrProbeResult probe_rpki_rtr(
    const std::string& endpoint_identity,
    const std::string& ip,
    const std::string& prefix,
    std::uint8_t prefix_length,
    std::uint32_t origin_asn,
    RtrSource& source,
    const RtrClientOptions& options = {});

// Serialize to JSON.
[[nodiscard]] std::string rpki_rtr_probe_json(const RpkiRtrProbeResult& result);

}  // namespace tgmap::mtproto
