#include "mtproto/ptr_probe.h"

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/types.h>

namespace tgmap::mtproto {

// ── Validation ────────────────────────────────────────────────────────────────

void PtrRecord::validate() const {
  if (lookup_ok && outcome == "resolved" && hostnames.empty()) {
    throw std::logic_error("PtrRecord: resolved but no hostnames");
  }
}

void PtrProbeResult::validate() const {
  if (schema.empty()) throw std::logic_error("PtrProbeResult: empty schema");
  if (endpoint_identity.empty()) throw std::logic_error("PtrProbeResult: empty endpoint_identity");
  if (outcome.empty()) throw std::logic_error("PtrProbeResult: empty outcome");
}

// ── Reverse DNS query name construction ───────────────────────────────────────

std::string reverse_dns_query_name(const std::string& ip) {
  // Try IPv4 first.
  struct in_addr addr4{};
  if (::inet_pton(AF_INET, ip.c_str(), &addr4) == 1) {
    const auto bytes = reinterpret_cast<const std::uint8_t*>(&addr4.s_addr);
    // Reverse byte order for in-addr.arpa.
    return std::to_string(bytes[3]) + "." +
           std::to_string(bytes[2]) + "." +
           std::to_string(bytes[1]) + "." +
           std::to_string(bytes[0]) + ".in-addr.arpa";
  }

  // Try IPv6.
  struct in6_addr addr6{};
  if (::inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
    std::string result;
    result.reserve(80);
    // Reverse nibble order for ip6.arpa.
    for (int i = 15; i >= 0; --i) {
      const auto byte = addr6.s6_addr[i];
      const auto low = byte & 0x0F;
      const auto high = (byte >> 4) & 0x0F;
      result += "0123456789abcdef"[low];
      result += ".";
      result += "0123456789abcdef"[high];
      result += ".";
    }
    result += "ip6.arpa";
    return result;
  }

  throw std::invalid_argument("reverse_dns_query_name: invalid IP address: " + ip);
}

// ── PTR probe ─────────────────────────────────────────────────────────────────

PtrProbeResult probe_ptr(
    const std::string& endpoint_identity,
    const std::string& ip,
    PtrSource& source,
    std::chrono::milliseconds timeout) {
  if (endpoint_identity.empty()) {
    throw std::invalid_argument("probe_ptr: endpoint_identity is required");
  }
  if (ip.empty()) {
    throw std::invalid_argument("probe_ptr: ip is required");
  }

  const auto start = std::chrono::steady_clock::now();

  PtrProbeResult result;
  result.endpoint_identity = endpoint_identity;
  result.ip = ip;

  try {
    const auto record = source.lookup(ip, timeout);
    record.validate();

    result.hostnames = record.hostnames;
    result.query_name = record.query_name;
    result.outcome = record.outcome;
    result.detail = record.detail;
  } catch (const std::exception& ex) {
    result.outcome = "failed";
    result.detail = ex.what();
  }

  result.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start);

  result.validate();
  return result;
}

std::vector<PtrProbeResult> probe_ptr_batch(
    const std::vector<std::pair<std::string, std::string>>& endpoint_ip_pairs,
    PtrSource& source,
    std::chrono::milliseconds timeout) {
  std::vector<PtrProbeResult> results;
  results.reserve(endpoint_ip_pairs.size());
  for (const auto& [identity, ip] : endpoint_ip_pairs) {
    results.push_back(probe_ptr(identity, ip, source, timeout));
  }
  return results;
}

// ── JSON serialization ────────────────────────────────────────────────────────

std::string ptr_probe_json(const PtrProbeResult& result) {
  result.validate();

  std::string json = "{\"schema\":\"" + result.schema + "\"";
  json += ",\"endpoint_identity\":\"" + result.endpoint_identity + "\"";
  json += ",\"ip\":\"" + result.ip + "\"";
  json += ",\"query_name\":\"" + result.query_name + "\"";
  json += ",\"outcome\":\"" + result.outcome + "\"";
  if (!result.detail.empty()) {
    json += ",\"detail\":\"" + result.detail + "\"";
  }

  // Hostnames array.
  json += ",\"hostnames\":[";
  for (std::size_t i = 0U; i < result.hostnames.size(); ++i) {
    if (i > 0U) json += ",";
    json += "\"" + result.hostnames[i] + "\"";
  }
  json += "]";

  json += ",\"elapsed_ms\":" + std::to_string(result.elapsed.count());
  json += "}";
  return json;
}

// ── SystemPtrSource ───────────────────────────────────────────────────────────

PtrRecord SystemPtrSource::lookup(const std::string& ip,
                                    std::chrono::milliseconds /*timeout*/) {
  PtrRecord record;
  record.query_name = reverse_dns_query_name(ip);

  // Determine address family.
  struct in_addr addr4{};
  struct in6_addr addr6{};
  struct sockaddr_storage sa{};
  socklen_t sa_len = 0;

  if (::inet_pton(AF_INET, ip.c_str(), &addr4) == 1) {
    auto* sin = reinterpret_cast<struct sockaddr_in*>(&sa);
    sin->sin_family = AF_INET;
    sin->sin_addr = addr4;
    sin->sin_port = 0;
    sa_len = sizeof(struct sockaddr_in);
  } else if (::inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
    auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(&sa);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr = addr6;
    sin6->sin6_port = 0;
    sin6->sin6_flowinfo = 0;
    sin6->sin6_scope_id = 0;
    sa_len = sizeof(struct sockaddr_in6);
  } else {
    record.outcome = "failed";
    record.detail = "invalid IP address";
    return record;
  }

  char host[NI_MAXHOST];
  const int flags = NI_NAMEREQD;  // Require a hostname, otherwise report as no PTR.
  const int ret = ::getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sa_len,
                                 host, sizeof(host), nullptr, 0, flags);

  if (ret == 0) {
    record.lookup_ok = true;
    record.outcome = "resolved";
    record.hostnames.push_back(std::string(host));
  } else if (ret == EAI_NONAME) {
    record.lookup_ok = true;
    record.outcome = "nxdomain";
    record.detail = "no PTR record";
  } else {
    record.lookup_ok = false;
    record.outcome = "failed";
    record.detail = std::string("getnameinfo: ") + ::gai_strerror(ret);
  }

  return record;
}

}  // namespace tgmap::mtproto
