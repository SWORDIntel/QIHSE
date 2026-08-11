#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tgmap::mtproto {

// ── Route-views / RIPE RIS lookup record ──────────────────────────────────────

// Result of looking up one IP address against a public routing-data source
// (Routeviews, RIPE RIS / RIPEstat). The record is the only input the
// hijack-classification logic needs, so the source is injectable and the
// classification is fully offline-testable.
struct RouteViewRecord final {
  // True when the lookup completed and returned a usable answer.
  bool lookup_ok = false;
  // Human-readable status / error detail from the source.
  std::string detail;
  // Origin ASNs observed announcing a route covering the IP (numeric, e.g. 62041).
  std::vector<std::uint32_t> origin_asns;
  // Prefixes covering the IP that were observed in the global routing table.
  std::vector<std::string> announced_prefixes;
  // RPKI validation state of the covering announcement, when the source provides it.
  std::optional<bool> rpki_valid;
  // Wall time spent inside the source lookup.
  std::chrono::milliseconds lookup_elapsed_ms{};

  // Full AS paths from each collector that observed the route. Each inner
  // vector is one AS path, ordered from the collector's AS (first) to the
  // origin AS (last). When the source does not provide path data this is
  // empty and path analysis is skipped.
  std::vector<std::vector<std::uint32_t>> as_paths;

  void validate() const;
};

// Abstract source of public routing-table observations. Implementations perform
// real network lookups (RIPEstat HTTPS, Routeviews RIB import, ...). Tests
// inject a fake implementation.
class RouteViewSource {
 public:
  virtual ~RouteViewSource() = default;
  [[nodiscard]] virtual RouteViewRecord lookup(const std::string& ip,
                                               std::chrono::milliseconds timeout) = 0;
};

// Real source backed by the RIPEstat Data API (aggregates Routeviews + RIPE RIS).
// Performs an HTTPS GET to stat.ripe.net and parses the JSON response. It never
// sends traffic towards the probed Telegram endpoint.
class RipeStatRouteViewSource final : public RouteViewSource {
 public:
  [[nodiscard]] RouteViewRecord lookup(const std::string& ip,
                                       std::chrono::milliseconds timeout) override;
};

// ── Options ───────────────────────────────────────────────────────────────────

struct BgpRouteProbeOptions final {
  std::chrono::milliseconds timeout{5000};
  // ASNs expected to announce the endpoint's prefix (e.g. Telegram's
  // AS62041 / AS44939). An observed origin ASN outside this set is flagged.
  std::vector<std::uint32_t> expected_asns;
};

// ── Result ────────────────────────────────────────────────────────────────────

struct BgpRouteProbeResult final {
  std::string schema = "tgmap.bgp-route.v1";
  std::string endpoint_identity;
  std::string environment;
  std::string ip;

  bool is_hijacked = false;
  // "none", "origin_mismatch", "bgp_leak", "anycast_hijack", "lookup_failed"
  std::string hijack_type;

  // Origin ASNs observed for the covering announcement.
  std::vector<std::uint32_t> observed_asns;
  // Expected ASNs supplied via options (echoed for the audit trail).
  std::vector<std::uint32_t> expected_asns;
  // Observed ASNs not present in expected_asns, formatted as "AS<n>".
  std::vector<std::string> anomalous_asns;
  // Prefixes covering the IP from the public routing table.
  std::vector<std::string> announced_prefixes;
  // RPKI validation state of the covering announcement, when known.
  std::optional<bool> rpki_valid;

  // RTT margin between the route-views lookup and a baseline expectation.
  // For a healthy announcement this is the lookup wall time; for a hijack it
  // is the extra latency attributable to the anomalous path.
  std::chrono::milliseconds rtt_margin{};

  std::string lookup_detail;

  // ── AS-path analysis (B1-3) ────────────────────────────────────────────────
  // Full AS paths from each collector, ordered collector→origin.
  std::vector<std::vector<std::uint32_t>> as_paths;
  // [0.0, 1.0] — 1.0 means all collector paths agree perfectly; lower values
  // indicate path asymmetry or valley-free violations.  Set to 1.0 when no
  // path data is available (no evidence of inconsistency).
  double path_consistency_score = 1.0;
  // True when at least one path contains a valley-free violation (a customer
  // AS appearing as a transit provider for a later AS in the path).
  bool has_valley_free_violation = false;
  // True when different collectors observe different origin ASNs for the same
  // prefix (selective hijack or traffic engineering).
  bool has_origin_asymmetry = false;

  void validate() const;
};

// Classify a route-views record against the expected ASN set. Pure function —
// no network access, fully deterministic, offline-testable.
[[nodiscard]] BgpRouteProbeResult classify_bgp_route(const std::string& endpoint_identity,
                                                     const std::string& ip,
                                                     const std::string& environment,
                                                     const RouteViewRecord& record,
                                                     const BgpRouteProbeOptions& options);

// Compute path consistency, valley-free violations, and origin asymmetry from
// a set of collector AS paths. Pure function — no network access.
// Returns {consistency_score, has_valley_free_violation, has_origin_asymmetry}.
struct PathAnalysisResult final {
  double consistency_score = 1.0;
  bool has_valley_free_violation = false;
  bool has_origin_asymmetry = false;
};
[[nodiscard]] PathAnalysisResult analyze_as_paths(
    const std::vector<std::vector<std::uint32_t>>& as_paths);

// Probe one endpoint's BGP/routing state by looking up its IP against a public
// routing-data source and classifying the announcement against the expected
// Telegram ASNs. The source is injected so the classification is testable.
[[nodiscard]] BgpRouteProbeResult probe_bgp_route(const std::string& endpoint_identity,
                                                  const std::string& ip,
                                                  const std::string& environment,
                                                  RouteViewSource& source,
                                                  const BgpRouteProbeOptions& options = {});

}  // namespace tgmap::mtproto
