#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tgmap::mtproto {

// ── RDAP lookup result ────────────────────────────────────────────────────────

// Registration data for an IP address from RDAP (RFC 7483).
struct RdapRecord final {
  bool lookup_ok = false;
  std::string detail;
  // Network/rCIDR range from RDAP.
  std::string network_cidr;
  std::string network_start;
  std::string network_end;
  std::string network_type;     // "allocated", "assigned", "reserved"
  std::string network_name;
  // Registration entity (RIR/LIR).
  std::string registry;
  std::string registrar;        // Handle of the registering entity.
  // Country code (ISO 3166-1 alpha-2).
  std::optional<std::string> country;
  // Registration and last-changed dates.
  std::optional<std::string> registration_date;
  std::optional<std::string> last_changed_date;
  std::chrono::milliseconds lookup_elapsed{};

  void validate() const;
};

// Injectable RDAP source — abstracts the HTTPS lookup for unit testing.
class RdapSource {
 public:
  virtual ~RdapSource() = default;
  [[nodiscard]] virtual RdapRecord lookup(const std::string& ip,
                                           std::chrono::milliseconds timeout) = 0;
};

// Real RDAP source that queries RDAP servers via HTTPS.
class HttpRdapSource final : public RdapSource {
 public:
  [[nodiscard]] RdapRecord lookup(const std::string& ip,
                                   std::chrono::milliseconds timeout) override;
};

// ── RDAP probe result ─────────────────────────────────────────────────────────

struct RdapProbeResult final {
  std::string schema = "tgmap.rdap-probe.v1";
  std::string endpoint_identity;
  std::string ip;
  // Registration fields (echoed from RdapRecord).
  std::string network_cidr;
  std::string network_type;
  std::string network_name;
  std::string registry;
  std::optional<std::string> country;
  std::optional<std::string> registration_date;
  std::string lookup_status;    // "success" or "error"
  std::string detail;
  std::chrono::milliseconds elapsed{};

  void validate() const;
};

// Probe RDAP registration data for an endpoint's IP.
[[nodiscard]] RdapProbeResult probe_rdap(
    const std::string& endpoint_identity,
    const std::string& ip,
    RdapSource& source,
    std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

// Serialize to JSON.
[[nodiscard]] std::string rdap_probe_json(const RdapProbeResult& result);

}  // namespace tgmap::mtproto
