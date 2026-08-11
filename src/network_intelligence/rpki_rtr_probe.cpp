#include "mtproto/rpki_rtr_probe.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace tgmap::mtproto {

// ── Validation ────────────────────────────────────────────────────────────────

void RoaEntry::validate() const {
  if (origin_asn == 0U) throw std::logic_error("RoaEntry: origin_asn must be > 0");
  if (prefix.empty()) throw std::logic_error("RoaEntry: prefix is empty");
  if (prefix_length == 0U || prefix_length > 128U) {
    throw std::logic_error("RoaEntry: prefix_length must be in [1, 128]");
  }
  if (max_length < prefix_length) {
    throw std::logic_error("RoaEntry: max_length must be >= prefix_length");
  }
  if (address_family != "ipv4" && address_family != "ipv6") {
    throw std::logic_error("RoaEntry: address_family must be ipv4 or ipv6");
  }
}

void RtrClientOptions::validate() const {
  if (host.empty()) throw std::invalid_argument("RtrClientOptions: host is required");
  if (port == 0U) throw std::invalid_argument("RtrClientOptions: port must be > 0");
  if (connect_timeout.count() < 100) {
    throw std::invalid_argument("RtrClientOptions: connect_timeout must be >= 100ms");
  }
  if (read_timeout.count() < 100) {
    throw std::invalid_argument("RtrClientOptions: read_timeout must be >= 100ms");
  }
}

void RpkiRtrProbeResult::validate() const {
  if (schema.empty()) throw std::logic_error("RpkiRtrProbeResult: empty schema");
  if (endpoint_identity.empty()) throw std::logic_error("RpkiRtrProbeResult: empty endpoint_identity");
  if (validation_state.empty()) throw std::logic_error("RpkiRtrProbeResult: empty validation_state");
}

// ── String conversion ─────────────────────────────────────────────────────────

std::string to_string(RpkiValidationState state) {
  switch (state) {
    case RpkiValidationState::Valid:    return "valid";
    case RpkiValidationState::Invalid:  return "invalid";
    case RpkiValidationState::NotFound: return "not_found";
  }
  return "unknown";
}

// ── IP/prefix helpers ─────────────────────────────────────────────────────────

namespace {

bool parse_ipv4(const std::string& s, std::uint32_t& out) {
  struct in_addr addr{};
  if (::inet_pton(AF_INET, s.c_str(), &addr) != 1) return false;
  out = ntohl(addr.s_addr);
  return true;
}

bool parse_ipv6(const std::string& s, std::array<std::uint8_t, 16>& out) {
  struct in6_addr addr{};
  if (::inet_pton(AF_INET6, s.c_str(), &addr) != 1) return false;
  std::memcpy(out.data(), addr.s6_addr, 16);
  return true;
}

bool ipv4_in_prefix(std::uint32_t ip, std::uint32_t network, std::uint8_t prefix_len) {
  if (prefix_len == 0U) return true;
  if (prefix_len > 32U) return false;
  const std::uint32_t mask = prefix_len == 0U ? 0U : ~((1U << (32U - prefix_len)) - 1U);
  return (ip & mask) == (network & mask);
}

bool ipv6_in_prefix(const std::array<std::uint8_t, 16>& ip,
                     const std::array<std::uint8_t, 16>& network,
                     std::uint8_t prefix_len) {
  if (prefix_len == 0U) return true;
  if (prefix_len > 128U) return false;
  const auto full_bytes = prefix_len / 8U;
  const auto remaining_bits = prefix_len % 8U;
  for (std::uint8_t i = 0U; i < full_bytes; ++i) {
    if (ip[i] != network[i]) return false;
  }
  if (remaining_bits > 0U && full_bytes < 16U) {
    const std::uint8_t mask = static_cast<std::uint8_t>(0xFFU << (8U - remaining_bits));
    if ((ip[full_bytes] & mask) != (network[full_bytes] & mask)) return false;
  }
  return true;
}

}  // namespace

bool ip_in_prefix(const std::string& ip, const std::string& prefix_str,
                   std::uint8_t prefix_length) {
  // Try IPv4 first.
  std::uint32_t ip4 = 0U, net4 = 0U;
  if (parse_ipv4(ip, ip4) && parse_ipv4(prefix_str, net4)) {
    return ipv4_in_prefix(ip4, net4, prefix_length);
  }

  // Try IPv6.
  std::array<std::uint8_t, 16> ip6{}, net6{};
  if (parse_ipv6(ip, ip6) && parse_ipv6(prefix_str, net6)) {
    return ipv6_in_prefix(ip6, net6, prefix_length);
  }

  return false;
}

std::pair<std::string, std::uint8_t> parse_prefix(const std::string& cidr) {
  const auto slash = cidr.find('/');
  if (slash == std::string::npos) {
    throw std::invalid_argument("parse_prefix: missing '/' in CIDR: " + cidr);
  }
  const auto prefix = cidr.substr(0, slash);
  const auto length = static_cast<std::uint8_t>(std::stoul(cidr.substr(slash + 1)));
  return {prefix, length};
}

// ── Pure validation function ──────────────────────────────────────────────────

RpkiValidationState validate_against_roas(
    const std::vector<RoaEntry>& roas,
    const std::string& prefix, std::uint8_t prefix_length,
    std::uint32_t origin_asn) {
  bool prefix_covered = false;

  for (const auto& roa : roas) {
    // Check if the ROA covers this prefix.
    // A ROA covers a prefix if the ROA's prefix matches and the prefix length
    // is <= the ROA's max_length.
    if (roa.prefix_length > prefix_length) continue;

    // Check that the network portions match.
    if (!ip_in_prefix(prefix, roa.prefix, roa.prefix_length)) continue;

    // The ROA's prefix must be at least as specific as the query prefix.
    // Actually, we need to check if the query prefix is covered by the ROA:
    // the ROA prefix must be less specific (shorter) or equal, and the
    // query prefix length must be <= ROA max_length.
    if (prefix_length > roa.max_length) continue;

    prefix_covered = true;

    if (roa.origin_asn == origin_asn) {
      return RpkiValidationState::Valid;
    }
  }

  if (prefix_covered) {
    return RpkiValidationState::Invalid;
  }
  return RpkiValidationState::NotFound;
}

// ── ROA cache ─────────────────────────────────────────────────────────────────

void RoaCache::load(const std::vector<RoaEntry>& roas) {
  roas_ = roas;
}

RpkiValidationState RoaCache::validate(
    const std::string& prefix, std::uint8_t prefix_length,
    std::uint32_t origin_asn) const {
  return validate_against_roas(roas_, prefix, prefix_length, origin_asn);
}

RpkiValidationState RoaCache::validate_ip(
    const std::string& ip, std::uint32_t origin_asn) const {
  // Try each ROA to see if any covers this IP.
  bool prefix_covered = false;

  for (const auto& roa : roas_) {
    if (!ip_in_prefix(ip, roa.prefix, roa.prefix_length)) continue;

    prefix_covered = true;

    if (roa.origin_asn == origin_asn) {
      return RpkiValidationState::Valid;
    }
  }

  if (prefix_covered) {
    return RpkiValidationState::Invalid;
  }
  return RpkiValidationState::NotFound;
}

// ── RTR TCP client (RFC 6810) ─────────────────────────────────────────────────

namespace {

[[noreturn]] void throw_system_error(const std::string& operation) {
  throw std::runtime_error(operation + ": " + std::strerror(errno));
}

bool wait_for_readable(int fd, std::chrono::milliseconds timeout) {
  struct pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLIN;
  const auto ms = static_cast<int>(timeout.count());
  return ::poll(&pfd, 1, ms) > 0 && (pfd.revents & POLLIN) != 0;
}

bool wait_for_writable(int fd, std::chrono::milliseconds timeout) {
  struct pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLOUT;
  const auto ms = static_cast<int>(timeout.count());
  return ::poll(&pfd, 1, ms) > 0 && (pfd.revents & POLLOUT) != 0;
}

bool read_exact(int fd, void* buffer, std::size_t length, std::chrono::milliseconds timeout) {
  auto* buf = static_cast<std::uint8_t*>(buffer);
  std::size_t offset = 0U;
  while (offset < length) {
    if (!wait_for_readable(fd, timeout)) return false;
    const ssize_t n = ::read(fd, buf + offset, length - offset);
    if (n <= 0) {
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
      return false;
    }
    offset += static_cast<std::size_t>(n);
  }
  return true;
}

bool write_exact(int fd, const void* buffer, std::size_t length, std::chrono::milliseconds timeout) {
  const auto* buf = static_cast<const std::uint8_t*>(buffer);
  std::size_t offset = 0U;
  while (offset < length) {
    if (!wait_for_writable(fd, timeout)) return false;
    const ssize_t n = ::write(fd, buf + offset, length - offset);
    if (n <= 0) {
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
      return false;
    }
    offset += static_cast<std::size_t>(n);
  }
  return true;
}

// RTR PDU header (8 bytes): version(1) + pdu_type(1) + session_id(2) + length(4)
struct RtrHeader {
  std::uint8_t version;
  std::uint8_t pdu_type;
  std::uint16_t session_id;
  std::uint32_t length;
};

RtrHeader read_header(int fd, std::chrono::milliseconds timeout) {
  std::array<std::uint8_t, 8> raw{};
  if (!read_exact(fd, raw.data(), 8, timeout)) {
    throw std::runtime_error("RTR: failed to read PDU header");
  }
  RtrHeader h{};
  h.version = raw[0];
  h.pdu_type = raw[1];
  h.session_id = static_cast<std::uint16_t>((raw[2] << 8) | raw[3]);
  h.length = (static_cast<std::uint32_t>(raw[4]) << 24) |
             (static_cast<std::uint32_t>(raw[5]) << 16) |
             (static_cast<std::uint32_t>(raw[6]) << 8) |
             static_cast<std::uint32_t>(raw[7]);
  return h;
}

// Send a Reset Query PDU to request the full ROA cache.
bool send_reset_query(int fd, std::uint8_t version, std::chrono::milliseconds timeout) {
  // Reset Query: version(1) + pdu_type=2(1) + session_id=0(2) + length=8(4)
  std::array<std::uint8_t, 8> pdu{};
  pdu[0] = version;
  pdu[1] = static_cast<std::uint8_t>(RtrPduType::ResetQuery);
  pdu[2] = 0; pdu[3] = 0;
  pdu[4] = 0; pdu[5] = 0; pdu[6] = 0; pdu[7] = 8;
  return write_exact(fd, pdu.data(), 8, timeout);
}

// Parse an IPv4 Prefix PDU (12 bytes after header).
RoaEntry parse_ipv4_prefix_pdu(const std::uint8_t* data) {
  RoaEntry roa;
  roa.address_family = "ipv4";
  // PDU layout: flags(1) + prefix_length(1) + max_length(1) + reserved(1) +
  //             prefix(4) + asn(4)
  // flags bit 0: 0 = add, 1 = withdraw
  const std::uint8_t prefix_length = data[1];
  const std::uint8_t max_length = data[2];
  std::uint32_t prefix_val = (static_cast<std::uint32_t>(data[4]) << 24) |
                              (static_cast<std::uint32_t>(data[5]) << 16) |
                              (static_cast<std::uint32_t>(data[6]) << 8) |
                              static_cast<std::uint32_t>(data[7]);
  std::uint32_t asn = (static_cast<std::uint32_t>(data[8]) << 24) |
                       (static_cast<std::uint32_t>(data[9]) << 16) |
                       (static_cast<std::uint32_t>(data[10]) << 8) |
                       static_cast<std::uint32_t>(data[11]);

  struct in_addr addr{};
  addr.s_addr = htonl(prefix_val);
  char buf[INET_ADDRSTRLEN];
  ::inet_ntop(AF_INET, &addr, buf, sizeof(buf));
  roa.prefix = std::string(buf) + "/" + std::to_string(prefix_length);
  roa.prefix_length = prefix_length;
  roa.max_length = max_length;
  roa.origin_asn = asn;
  return roa;
}

// Parse an IPv6 Prefix PDU (24 bytes after header).
RoaEntry parse_ipv6_prefix_pdu(const std::uint8_t* data) {
  RoaEntry roa;
  roa.address_family = "ipv6";
  const std::uint8_t prefix_length = data[1];
  const std::uint8_t max_length = data[2];
  struct in6_addr addr{};
  std::memcpy(addr.s6_addr, data + 4, 16);
  std::uint32_t asn = (static_cast<std::uint32_t>(data[20]) << 24) |
                       (static_cast<std::uint32_t>(data[21]) << 16) |
                       (static_cast<std::uint32_t>(data[22]) << 8) |
                       static_cast<std::uint32_t>(data[23]);

  char buf[INET6_ADDRSTRLEN];
  ::inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
  roa.prefix = std::string(buf) + "/" + std::to_string(prefix_length);
  roa.prefix_length = prefix_length;
  roa.max_length = max_length;
  roa.origin_asn = asn;
  return roa;
}

}  // namespace

std::vector<RoaEntry> RtrTcpClient::fetch_roas(const RtrClientOptions& options) {
  options.validate();

  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) throw_system_error("socket");

  // Set non-blocking for timeout-aware connect.
  int flags = ::fcntl(fd, F_GETFL, 0);
  ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(options.port);
  if (::inet_pton(AF_INET, options.host.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    throw std::invalid_argument("RTR: invalid host address: " + options.host);
  }

  int result = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
  if (result < 0 && errno != EINPROGRESS) {
    ::close(fd);
    throw_system_error("connect");
  }
  if (result < 0) {
    if (!wait_for_writable(fd, options.connect_timeout)) {
      ::close(fd);
      throw std::runtime_error("RTR: connect timed out");
    }
    int error = 0;
    socklen_t err_len = sizeof(error);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &err_len) < 0 || error != 0) {
      ::close(fd);
      throw std::runtime_error("RTR: connect failed");
    }
  }

  // Restore blocking mode.
  ::fcntl(fd, F_SETFL, flags);

  // Send Reset Query.
  if (!send_reset_query(fd, options.version, options.connect_timeout)) {
    ::close(fd);
    throw std::runtime_error("RTR: failed to send Reset Query");
  }

  std::vector<RoaEntry> roas;

  // Read PDUs until EndOfData or error.
  while (true) {
    RtrHeader hdr = read_header(fd, options.read_timeout);

    if (hdr.pdu_type == static_cast<std::uint8_t>(RtrPduType::EndOfData)) {
      // EndOfData: read remaining bytes (serial_number(4) + refresh_interval(4) +
      //            retry_interval(4) + expire_interval(4) = 16 bytes after header)
      std::array<std::uint8_t, 16> data{};
      if (!read_exact(fd, data.data(), 16, options.read_timeout)) {
        ::close(fd);
        throw std::runtime_error("RTR: failed to read EndOfData body");
      }
      break;
    }

    if (hdr.pdu_type == static_cast<std::uint8_t>(RtrPduType::CacheResponse)) {
      // CacheResponse: no additional data beyond the 8-byte header.
      continue;
    }

    if (hdr.pdu_type == static_cast<std::uint8_t>(RtrPduType::Ipv4Prefix)) {
      // IPv4 Prefix PDU: 12 bytes after header.
      std::array<std::uint8_t, 12> data{};
      if (!read_exact(fd, data.data(), 12, options.read_timeout)) {
        ::close(fd);
        throw std::runtime_error("RTR: failed to read IPv4 Prefix PDU");
      }
      // Only add (flags bit 0 = 0), skip withdraw (flags bit 0 = 1).
      if ((data[0] & 1U) == 0U) {
        roas.push_back(parse_ipv4_prefix_pdu(data.data()));
      }
      continue;
    }

    if (hdr.pdu_type == static_cast<std::uint8_t>(RtrPduType::Ipv6Prefix)) {
      // IPv6 Prefix PDU: 24 bytes after header.
      std::array<std::uint8_t, 24> data{};
      if (!read_exact(fd, data.data(), 24, options.read_timeout)) {
        ::close(fd);
        throw std::runtime_error("RTR: failed to read IPv6 Prefix PDU");
      }
      if ((data[0] & 1U) == 0U) {
        roas.push_back(parse_ipv6_prefix_pdu(data.data()));
      }
      continue;
    }

    if (hdr.pdu_type == static_cast<std::uint8_t>(RtrPduType::ErrorReport)) {
      ::close(fd);
      throw std::runtime_error("RTR: server returned ErrorReport PDU");
    }

    // Unknown PDU type — skip the remaining bytes.
    if (hdr.length > 8U) {
      std::vector<std::uint8_t> skip(hdr.length - 8U);
      if (!read_exact(fd, skip.data(), skip.size(), options.read_timeout)) {
        ::close(fd);
        throw std::runtime_error("RTR: failed to skip unknown PDU");
      }
    }
  }

  ::close(fd);
  return roas;
}

// ── RPKI RTR probe ────────────────────────────────────────────────────────────

RpkiRtrProbeResult probe_rpki_rtr(
    const std::string& endpoint_identity,
    const std::string& ip,
    const std::string& prefix,
    std::uint8_t prefix_length,
    std::uint32_t origin_asn,
    RtrSource& source,
    const RtrClientOptions& options) {
  options.validate();

  const auto start = std::chrono::steady_clock::now();

  RpkiRtrProbeResult result;
  result.endpoint_identity = endpoint_identity;
  result.ip = ip;
  result.prefix = prefix;
  result.prefix_length = prefix_length;
  result.origin_asn = origin_asn;
  result.rtr_server = options.host + ":" + std::to_string(options.port);

  const auto roas = source.fetch_roas(options);
  result.roa_cache_size = roas.size();

  // Parse the prefix to get the network address.
  auto [net_addr, net_len] = parse_prefix(prefix);
  (void)net_addr;

  const auto state = validate_against_roas(roas, net_addr, prefix_length, origin_asn);
  result.validation_state = to_string(state);

  result.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start);

  result.validate();
  return result;
}

// ── JSON serialization ────────────────────────────────────────────────────────

std::string rpki_rtr_probe_json(const RpkiRtrProbeResult& result) {
  result.validate();

  std::string json = "{\"schema\":\"" + result.schema + "\"";
  json += ",\"endpoint_identity\":\"" + result.endpoint_identity + "\"";
  json += ",\"ip\":\"" + result.ip + "\"";
  json += ",\"prefix\":\"" + result.prefix + "\"";
  json += ",\"prefix_length\":" + std::to_string(result.prefix_length);
  json += ",\"origin_asn\":" + std::to_string(result.origin_asn);
  json += ",\"validation_state\":\"" + result.validation_state + "\"";
  json += ",\"roa_cache_size\":" + std::to_string(result.roa_cache_size);
  json += ",\"rtr_server\":\"" + result.rtr_server + "\"";
  json += ",\"elapsed_ms\":" + std::to_string(result.elapsed.count());
  json += "}";
  return json;
}

}  // namespace tgmap::mtproto
