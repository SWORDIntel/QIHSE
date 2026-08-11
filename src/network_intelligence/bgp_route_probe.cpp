#include "mtproto/bgp_route_probe.h"

#include <nlohmann/json.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstring>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>

namespace tgmap::mtproto {

namespace {

struct SslCtxDeleter { void operator()(SSL_CTX* p) const { SSL_CTX_free(p); } };
struct SslDeleter    { void operator()(SSL* p)     const { SSL_free(p);     } };
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using SslPtr    = std::unique_ptr<SSL, SslDeleter>;

bool would_block(int err) {
  return err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE;
}

// Wait for the socket to become ready for the requested SSL direction. Returns
// false on timeout/error, true when the direction is ready.
bool ssl_wait(int fd, int ssl_err, std::chrono::milliseconds timeout) {
  if (!would_block(ssl_err)) return false;
  struct pollfd pfd{};
  pfd.fd = fd;
  pfd.events = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0) return false;
    const int rc = ::poll(&pfd, 1, static_cast<int>(remaining.count()));
    if (rc > 0) return true;
    if (rc == 0) return false;
    if (errno != EINTR) return false;
  }
}

// Establish a TCP connection to host:port with a deadline. Returns a file
// descriptor or throws on failure.
int connect_with_timeout(const std::string& host, const std::string& port,
                         std::chrono::milliseconds timeout) {
  struct addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo* res_raw = nullptr;
  const int gai_rc = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &res_raw);
  if (gai_rc != 0 || res_raw == nullptr) {
    if (res_raw) ::freeaddrinfo(res_raw);
    throw std::runtime_error(std::string("getaddrinfo failed: ") + ::gai_strerror(gai_rc));
  }
  struct addrinfo_deleter { void operator()(addrinfo* p) const { ::freeaddrinfo(p); } };
  std::unique_ptr<addrinfo, addrinfo_deleter> res(res_raw);

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (struct addrinfo* ai = res.get(); ai != nullptr; ai = ai->ai_next) {
    const int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) (void)::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0) { ::close(fd); continue; }

    int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc == 0) return fd;
    if (errno == EINPROGRESS) {
      struct pollfd pfd{};
      pfd.fd = fd;
      pfd.events = POLLOUT;
      const int prc = ::poll(&pfd, 1, static_cast<int>(remaining.count()));
      if (prc > 0) {
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 && soerr == 0) {
          return fd;
        }
      }
    }
    ::close(fd);
  }
  throw std::runtime_error("connect timed out");
}

// Perform a single HTTPS GET and return the response body. Mirrors the OpenSSL
// pattern used by tls_fingerprint but is a generic client GET.
std::string https_get(const std::string& host, const std::string& path,
                      std::chrono::milliseconds timeout) {
  SslCtxPtr ctx(::SSL_CTX_new(::TLS_client_method()));
  if (!ctx) throw std::runtime_error("SSL_CTX_new failed");
  ::SSL_CTX_set_default_verify_paths(ctx.get());

  const int fd = connect_with_timeout(host, "443", timeout);
  struct fd_closer { int f; ~fd_closer() { if (f >= 0) ::close(f); } } closer{fd};

  SslPtr ssl(::SSL_new(ctx.get()));
  if (!ssl) throw std::runtime_error("SSL_new failed");
  ::SSL_set_tlsext_host_name(ssl.get(), host.c_str());
  ::SSL_set_fd(ssl.get(), fd);

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    const int rc = ::SSL_connect(ssl.get());
    if (rc == 1) break;
    const int err = ::SSL_get_error(ssl.get(), rc);
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0 || !ssl_wait(fd, err, remaining)) {
      throw std::runtime_error("TLS handshake failed/timed out");
    }
  }

  std::ostringstream req;
  req << "GET " << path << " HTTP/1.1\r\n"
      << "Host: " << host << "\r\n"
      << "User-Agent: TGMap-bgp-probe/1.0\r\n"
      << "Accept: application/json\r\n"
      << "Connection: close\r\n\r\n";
  const std::string request = req.str();
  for (std::size_t sent = 0; sent < request.size();) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0) throw std::runtime_error("write timed out");
    const int w = ::SSL_write(ssl.get(), request.data() + sent,
                              static_cast<int>(request.size() - sent));
    if (w > 0) { sent += static_cast<std::size_t>(w); continue; }
    const int err = ::SSL_get_error(ssl.get(), w);
    if (!ssl_wait(fd, err, remaining)) throw std::runtime_error("SSL_write failed");
  }

  std::string body;
  std::array<char, 4096> chunk{};
  bool saw_headers = false;
  std::string buffer;
  for (;;) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0) throw std::runtime_error("read timed out");
    const int r = ::SSL_read(ssl.get(), chunk.data(), static_cast<int>(chunk.size()));
    if (r > 0) {
      buffer.append(chunk.data(), static_cast<std::size_t>(r));
      if (!saw_headers) {
        const auto hdr_end = buffer.find("\r\n\r\n");
        if (hdr_end != std::string::npos) {
          saw_headers = true;
          body = buffer.substr(hdr_end + 4);
        }
      } else {
        body.append(chunk.data(), static_cast<std::size_t>(r));
      }
      continue;
    }
    const int err = ::SSL_get_error(ssl.get(), r);
    if (err == SSL_ERROR_ZERO_RETURN) break;
    if (would_block(err)) {
      if (!ssl_wait(fd, err, remaining)) break;
      continue;
    }
    break;  // connection closed or error — return what we have
  }
  return body;
}

// Parse the RIPEstat bgp-state response to extract AS paths from collectors.
// The bgp-state endpoint returns routes observed by RIPE RIS collectors,
// each with an AS path.
std::vector<std::vector<std::uint32_t>> parse_ripestat_bgp_state_paths(const std::string& body) {
  std::vector<std::vector<std::uint32_t>> paths;
  if (body.empty()) return paths;
  try {
    const auto doc = nlohmann::json::parse(body);
    const auto* data = doc.contains("data") ? &doc["data"] : nullptr;
    if (!data || !data->is_object()) return paths;
    if (!data->contains("routes") || !(*data)["routes"].is_array()) return paths;
    for (const auto& route : (*data)["routes"]) {
      if (!route.contains("path") || !route["path"].is_array()) continue;
      std::vector<std::uint32_t> path;
      for (const auto& asn : route["path"]) {
        if (asn.is_number()) {
          path.push_back(asn.get<std::uint32_t>());
        } else if (asn.is_string()) {
          std::string s = asn.get<std::string>();
          if (!s.empty() && s[0] == 'A') s.erase(0, 1);
          try { path.push_back(static_cast<std::uint32_t>(std::stoul(s))); }
          catch (...) {}
        }
      }
      if (!path.empty()) paths.push_back(std::move(path));
    }
  } catch (const std::exception&) {
    // Path parsing is best-effort; failures don't affect the core lookup.
  }
  return paths;
}

// Parse the RIPEstat network-info response body into a RouteViewRecord.
RouteViewRecord parse_ripestat_network_info(const std::string& body,
                                            std::chrono::milliseconds elapsed) {
  RouteViewRecord rec;
  rec.lookup_elapsed_ms = elapsed;
  if (body.empty()) {
    rec.detail = "empty response body";
    return rec;
  }
  try {
    const auto doc = nlohmann::json::parse(body);
    const auto* data = doc.contains("data") ? &doc["data"] : nullptr;
    if (!data || !data->is_object()) {
      rec.detail = "response missing data object";
      return rec;
    }
    if (data->contains("asns") && (*data)["asns"].is_array()) {
      for (const auto& a : (*data)["asns"]) {
        if (a.is_string()) {
          std::string s = a.get<std::string>();
          if (!s.empty() && s[0] == 'A') s.erase(0, 1);  // strip "AS" prefix
          try { rec.origin_asns.push_back(static_cast<std::uint32_t>(std::stoul(s))); }
          catch (...) {}
        } else if (a.is_number()) {
          rec.origin_asns.push_back(a.get<std::uint32_t>());
        }
      }
    }
    if (data->contains("prefixes") && (*data)["prefixes"].is_array()) {
      for (const auto& p : (*data)["prefixes"]) {
        if (p.is_string()) rec.announced_prefixes.push_back(p.get<std::string>());
      }
    }
    rec.lookup_ok = true;
    rec.detail = "ok";
  } catch (const std::exception& ex) {
    rec.detail = std::string("json parse failed: ") + ex.what();
  }
  return rec;
}

std::string asn_label(std::uint32_t asn) {
  return "AS" + std::to_string(asn);
}

// ── AS-path analysis (B1-3) ───────────────────────────────────────────────────

// Detect a valley-free violation in a single AS path.
//
// In a valley-free path, once the path transitions from a customer to a
// provider (going "up" the hierarchy), it must not transition back to a
// customer (going "down"). Without AS relationship data we use a heuristic:
// if the same AS appears more than once in the path (a loop), or if the path
// has a pattern that goes up-then-down-then-up (which would require an AS to
// be both a customer and a provider of different neighbours), we flag it.
//
// The simplest reliable heuristic without relationship data: check for AS
// loops (same AS appearing at non-adjacent positions) and for paths that
// reverse direction more than once. A clean valley-free path has at most one
// "peak" (the highest-tier transit AS).
bool has_path_valley_violation(const std::vector<std::uint32_t>& path) {
  if (path.size() < 3U) return false;
  // Check for AS loops (same AS at non-adjacent positions).
  for (std::size_t i = 0U; i < path.size(); ++i) {
    for (std::size_t j = i + 2U; j < path.size(); ++j) {
      if (path[i] == path[j]) return true;
    }
  }
  // Without relationship data we cannot definitively detect valley-free
  // violations from path topology alone.  The loop check above catches the
  // most common manifestation (an AS appearing as both transit and origin
  // in the same path).  Relationship-aware detection is a future increment.
  return false;
}

// Compute the longest common suffix (origin-side) between two AS paths.
// This measures how much of the path near the origin is stable across
// collectors — the stable portion is the "core" routing path.
std::size_t longest_common_suffix(const std::vector<std::uint32_t>& a,
                                   const std::vector<std::uint32_t>& b) {
  std::size_t common = 0U;
  auto ia = a.rbegin();
  auto ib = b.rbegin();
  while (ia != a.rend() && ib != b.rend() && *ia == *ib) {
    ++common;
    ++ia;
    ++ib;
  }
  return common;
}

}  // namespace

PathAnalysisResult analyze_as_paths(
    const std::vector<std::vector<std::uint32_t>>& as_paths) {
  PathAnalysisResult result;
  // No path data → perfect consistency by default (no evidence of problems).
  if (as_paths.empty()) {
    result.consistency_score = 1.0;
    return result;
  }
  // Single path → check for valley violations only.
  if (as_paths.size() == 1U) {
    result.consistency_score = 1.0;
    result.has_valley_free_violation = has_path_valley_violation(as_paths[0]);
    if (result.has_valley_free_violation) {
      result.consistency_score = 0.5;
    }
    return result;
  }

  // ── Origin asymmetry ──────────────────────────────────────────────────────
  // Different collectors seeing different origin ASNs for the same prefix.
  std::set<std::uint32_t> origins;
  for (const auto& path : as_paths) {
    if (!path.empty()) origins.insert(path.back());
  }
  result.has_origin_asymmetry = (origins.size() > 1U);

  // ── Valley-free violations ────────────────────────────────────────────────
  for (const auto& path : as_paths) {
    if (has_path_valley_violation(path)) {
      result.has_valley_free_violation = true;
      break;
    }
  }

  // ── Path consistency score ────────────────────────────────────────────────
  // Compute pairwise longest-common-suffix between all paths, normalised by
  // the shorter path length. The score is the average of all pairwise
  // agreement ratios. Perfect agreement (all paths identical) → 1.0.
  double total_agreement = 0.0;
  std::size_t pair_count = 0U;
  for (std::size_t i = 0U; i < as_paths.size(); ++i) {
    for (std::size_t j = i + 1U; j < as_paths.size(); ++j) {
      const auto& a = as_paths[i];
      const auto& b = as_paths[j];
      const std::size_t lcs = longest_common_suffix(a, b);
      const std::size_t shorter = std::min(a.size(), b.size());
      const double agreement = (shorter == 0U) ? 0.0
          : static_cast<double>(lcs) / static_cast<double>(shorter);
      total_agreement += agreement;
      ++pair_count;
    }
  }
  double score = (pair_count == 0U) ? 1.0 : total_agreement / static_cast<double>(pair_count);

  // Penalise for valley-free violations and origin asymmetry.
  if (result.has_valley_free_violation) score *= 0.7;
  if (result.has_origin_asymmetry)      score *= 0.5;

  // Clamp to [0.0, 1.0].
  result.consistency_score = std::max(0.0, std::min(1.0, score));
  return result;
}

// ── End AS-path analysis ──────────────────────────────────────────────────────

void RouteViewRecord::validate() const {
  if (!lookup_ok && !origin_asns.empty()) {
    throw std::invalid_argument("RouteViewRecord: origin_asns set but lookup_ok false");
  }
}

void BgpRouteProbeResult::validate() const {
  if (schema != "tgmap.bgp-route.v1") {
    throw std::invalid_argument("BgpRouteProbeResult schema is invalid");
  }
  if (endpoint_identity.empty()) {
    throw std::invalid_argument("BgpRouteProbeResult endpoint_identity must be set");
  }
  if (hijack_type != "none" && hijack_type != "origin_mismatch" &&
      hijack_type != "bgp_leak" && hijack_type != "anycast_hijack" &&
      hijack_type != "lookup_failed") {
    throw std::invalid_argument("BgpRouteProbeResult hijack_type is invalid: " + hijack_type);
  }
}

BgpRouteProbeResult classify_bgp_route(const std::string& endpoint_identity,
                                       const std::string& ip,
                                       const std::string& environment,
                                       const RouteViewRecord& record,
                                       const BgpRouteProbeOptions& options) {
  if (endpoint_identity.empty() || ip.empty()) {
    throw std::invalid_argument("classify_bgp_route requires non-empty identity and ip");
  }

  BgpRouteProbeResult result;
  result.endpoint_identity = endpoint_identity;
  result.environment = environment;
  result.ip = ip;
  result.expected_asns = options.expected_asns;
  result.observed_asns = record.origin_asns;
  result.announced_prefixes = record.announced_prefixes;
  result.rpki_valid = record.rpki_valid;
  result.lookup_detail = record.detail;
  result.rtt_margin = record.lookup_elapsed_ms;

  // ── AS-path analysis (B1-3) ──────────────────────────────────────────────
  result.as_paths = record.as_paths;
  if (!record.as_paths.empty()) {
    const auto path_analysis = analyze_as_paths(record.as_paths);
    result.path_consistency_score = path_analysis.consistency_score;
    result.has_valley_free_violation = path_analysis.has_valley_free_violation;
    result.has_origin_asymmetry = path_analysis.has_origin_asymmetry;
  }

  if (!record.lookup_ok) {
    result.is_hijacked = false;  // unknown, not a confirmed hijack
    result.hijack_type = "lookup_failed";
    result.validate();
    return result;
  }

  // Collect observed ASNs that are not in the expected set.
  std::vector<std::uint32_t> expected = options.expected_asns;
  std::sort(expected.begin(), expected.end());
  for (const auto asn : record.origin_asns) {
    if (!std::binary_search(expected.begin(), expected.end(), asn)) {
      result.anomalous_asns.push_back(asn_label(asn));
    }
  }

  if (result.anomalous_asns.empty()) {
    result.is_hijacked = false;
    result.hijack_type = "none";
    result.validate();
    return result;
  }

  // Anomalous origin ASNs observed. Classify the kind of routing anomaly.
  // - origin_mismatch: a single unexpected origin announces the prefix (classic
  //   prefix hijack or a misorigination).
  // - bgp_leak: expected ASNs are still present alongside unexpected ones (a
  //   route leak where the legitimate route coexists with a leaked one).
  // - anycast_hijack: no expected ASN is present at all and the announcement
  //   looks like a wholesale takeover of the prefix.
  const bool any_expected_present = [&] {
    for (const auto asn : record.origin_asns) {
      if (std::binary_search(expected.begin(), expected.end(), asn)) return true;
    }
    return false;
  }();

  if (any_expected_present) {
    result.hijack_type = "bgp_leak";
  } else if (record.origin_asns.size() == 1U) {
    result.hijack_type = "origin_mismatch";
  } else {
    result.hijack_type = "anycast_hijack";
  }
  result.is_hijacked = true;

  // RPKI invalid strengthens confidence but does not change the type.
  if (record.rpki_valid && !*record.rpki_valid) {
    result.lookup_detail += "; rpki_invalid";
  }

  result.validate();
  return result;
}

RouteViewRecord RipeStatRouteViewSource::lookup(const std::string& ip,
                                                std::chrono::milliseconds timeout) {
  if (ip.empty()) {
    RouteViewRecord rec;
    rec.detail = "empty ip";
    return rec;
  }
  const auto start = std::chrono::steady_clock::now();
  RouteViewRecord rec;
  try {
    const std::string host = "stat.ripe.net";
    // Phase 1: network-info for origin ASNs and prefixes.
    const std::string path = "/data/network-info/data.json?resource=" + ip;
    const std::string body = https_get(host, path, timeout);
    rec = parse_ripestat_network_info(body, std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start));

    // Phase 2: bgp-state for full AS paths from RIPE RIS collectors.
    // Best-effort — failures here don't invalidate the core lookup.
    try {
      const std::string bgp_path = "/data/bgp-state/data.json?resource=" + ip;
      const std::string bgp_body = https_get(host, bgp_path, timeout);
      rec.as_paths = parse_ripestat_bgp_state_paths(bgp_body);
    } catch (const std::exception&) {
      // bgp-state lookup failed; path analysis will be skipped.
    }
  } catch (const std::exception& ex) {
    rec.detail = std::string("ripestat lookup failed: ") + ex.what();
    rec.lookup_elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
  }
  return rec;
}

BgpRouteProbeResult probe_bgp_route(const std::string& endpoint_identity,
                                    const std::string& ip,
                                    const std::string& environment,
                                    RouteViewSource& source,
                                    const BgpRouteProbeOptions& options) {
  if (endpoint_identity.empty() || ip.empty()) {
    throw std::invalid_argument("probe_bgp_route requires non-empty identity and ip");
  }
  const auto record = source.lookup(ip, options.timeout);
  return classify_bgp_route(endpoint_identity, ip, environment, record, options);
}

}  // namespace tgmap::mtproto
