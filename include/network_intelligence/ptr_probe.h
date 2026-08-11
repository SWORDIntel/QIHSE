#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tgmap::mtproto {

// ── PTR reverse DNS record ────────────────────────────────────────────────────

struct PtrRecord final {
  bool lookup_ok = false;
  std::string detail;
  // The resolved PTR hostname(s). May be empty if no PTR exists.
  std::vector<std::string> hostnames;
  // The query name used (e.g. "50.167.154.149.in-addr.arpa").
  std::string query_name;
  // "resolved" — one or more PTR records returned
  // "nxdomain" — no PTR record exists
  // "timeout"  — DNS query timed out
  // "failed"   — other DNS error
  std::string outcome;
  std::chrono::milliseconds lookup_elapsed{};

  void validate() const;
};

// Injectable PTR source — abstracts DNS resolution for unit testing.
class PtrSource {
 public:
  virtual ~PtrSource() = default;
  [[nodiscard]] virtual PtrRecord lookup(const std::string& ip,
                                          std::chrono::milliseconds timeout) = 0;
};

// Real PTR source using getnameinfo / resolver.
class SystemPtrSource final : public PtrSource {
 public:
  [[nodiscard]] PtrRecord lookup(const std::string& ip,
                                  std::chrono::milliseconds timeout) override;
};

// ── PTR probe result ──────────────────────────────────────────────────────────

struct PtrProbeResult final {
  std::string schema = "tgmap.ptr-probe.v1";
  std::string endpoint_identity;
  std::string ip;
  std::vector<std::string> hostnames;
  std::string query_name;
  std::string outcome;         // "resolved", "nxdomain", "timeout", "failed"
  std::string detail;
  std::chrono::milliseconds elapsed{};

  void validate() const;
};

// Probe PTR reverse DNS for an endpoint's IP.
[[nodiscard]] PtrProbeResult probe_ptr(
    const std::string& endpoint_identity,
    const std::string& ip,
    PtrSource& source,
    std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

// Batch probe PTR for multiple IPs.
[[nodiscard]] std::vector<PtrProbeResult> probe_ptr_batch(
    const std::vector<std::pair<std::string, std::string>>& endpoint_ip_pairs,
    PtrSource& source,
    std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

// Serialize to JSON.
[[nodiscard]] std::string ptr_probe_json(const PtrProbeResult& result);

// Construct the reverse DNS query name for an IP address.
// IPv4: "50.167.154.149.in-addr.arpa"
// IPv6: nibble-reversed ".ip6.arpa"
[[nodiscard]] std::string reverse_dns_query_name(const std::string& ip);

}  // namespace tgmap::mtproto
