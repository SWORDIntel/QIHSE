#include "mtproto/rdap_probe.h"

#include <chrono>
#include <stdexcept>

namespace tgmap::mtproto {

// ── Validation ────────────────────────────────────────────────────────────────

void RdapRecord::validate() const {
  if (lookup_ok && network_cidr.empty()) {
    throw std::logic_error("RdapRecord: successful lookup with empty network_cidr");
  }
}

void RdapProbeResult::validate() const {
  if (schema.empty()) throw std::logic_error("RdapProbeResult: empty schema");
  if (endpoint_identity.empty()) throw std::logic_error("RdapProbeResult: empty endpoint_identity");
  if (lookup_status.empty()) throw std::logic_error("RdapProbeResult: empty lookup_status");
}

// ── RDAP probe ────────────────────────────────────────────────────────────────

RdapProbeResult probe_rdap(
    const std::string& endpoint_identity,
    const std::string& ip,
    RdapSource& source,
    std::chrono::milliseconds timeout) {
  if (endpoint_identity.empty()) {
    throw std::invalid_argument("probe_rdap: endpoint_identity is required");
  }
  if (ip.empty()) {
    throw std::invalid_argument("probe_rdap: ip is required");
  }

  const auto start = std::chrono::steady_clock::now();

  RdapProbeResult result;
  result.endpoint_identity = endpoint_identity;
  result.ip = ip;

  try {
    const auto record = source.lookup(ip, timeout);
    record.validate();

    result.network_cidr = record.network_cidr;
    result.network_type = record.network_type;
    result.network_name = record.network_name;
    result.registry = record.registry;
    result.country = record.country;
    result.registration_date = record.registration_date;
    result.lookup_status = record.lookup_ok ? "success" : "error";
    result.detail = record.detail;
  } catch (const std::exception& ex) {
    result.lookup_status = "error";
    result.detail = ex.what();
  }

  result.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start);

  result.validate();
  return result;
}

// ── JSON serialization ────────────────────────────────────────────────────────

std::string rdap_probe_json(const RdapProbeResult& result) {
  result.validate();

  std::string json = "{\"schema\":\"" + result.schema + "\"";
  json += ",\"endpoint_identity\":\"" + result.endpoint_identity + "\"";
  json += ",\"ip\":\"" + result.ip + "\"";
  json += ",\"network_cidr\":\"" + result.network_cidr + "\"";
  json += ",\"network_type\":\"" + result.network_type + "\"";
  json += ",\"network_name\":\"" + result.network_name + "\"";
  json += ",\"registry\":\"" + result.registry + "\"";
  if (result.country.has_value()) {
    json += ",\"country\":\"" + *result.country + "\"";
  }
  if (result.registration_date.has_value()) {
    json += ",\"registration_date\":\"" + *result.registration_date + "\"";
  }
  json += ",\"lookup_status\":\"" + result.lookup_status + "\"";
  if (!result.detail.empty()) {
    json += ",\"detail\":\"" + result.detail + "\"";
  }
  json += ",\"elapsed_ms\":" + std::to_string(result.elapsed.count());
  json += "}";
  return json;
}

// ── HttpRdapSource ────────────────────────────────────────────────────────────
// The real implementation would use libcurl or similar to query RDAP servers.
// For now, we provide a stub that returns a not-implemented error. The injectable
// RdapSource interface allows tests to use a fake source, and the real HTTPS
// implementation can be added when libcurl is integrated into the build.

RdapRecord HttpRdapSource::lookup(const std::string& /*ip*/,
                                   std::chrono::milliseconds /*timeout*/) {
  RdapRecord record;
  record.lookup_ok = false;
  record.detail = "HttpRdapSource not yet implemented — use injectable RdapSource for testing";
  return record;
}

}  // namespace tgmap::mtproto
