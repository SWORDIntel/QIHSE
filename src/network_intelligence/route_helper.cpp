#include "mtproto/route_helper.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <thread>

namespace tgmap::mtproto {

// ── Validation ────────────────────────────────────────────────────────────────

void RouteHelperRequest::validate() const {
  if (schema.empty()) throw std::logic_error("RouteHelperRequest: empty schema");
  if (endpoint_identity.empty() && ip.empty()) {
    throw std::logic_error("RouteHelperRequest: needs endpoint_identity or ip");
  }
  if (timeout.count() < 100) {
    throw std::invalid_argument("RouteHelperRequest: timeout must be >= 100ms");
  }
}

void RouteHelperResponse::validate() const {
  if (schema.empty()) throw std::logic_error("RouteHelperResponse: empty schema");
  if (status.empty()) throw std::logic_error("RouteHelperResponse: empty status");
}

void RouteHelperOptions::validate() const {
  if (socket_path.empty()) {
    throw std::invalid_argument("RouteHelperOptions: socket_path is required");
  }
  if (socket_path.string().size() >= sizeof(sockaddr_un::sun_path)) {
    throw std::invalid_argument("RouteHelperOptions: socket_path too long");
  }
  if (accept_timeout.count() < 100) {
    throw std::invalid_argument("RouteHelperOptions: accept_timeout must be >= 100ms");
  }
  if (io_timeout.count() < 100) {
    throw std::invalid_argument("RouteHelperOptions: io_timeout must be >= 100ms");
  }
}

// ── String conversion ─────────────────────────────────────────────────────────

std::string to_string(RouteHelperQueryType type) {
  switch (type) {
    case RouteHelperQueryType::BgpLookup:    return "bgp_lookup";
    case RouteHelperQueryType::TtlProbe:     return "ttl_probe";
    case RouteHelperQueryType::DnsDiscover:  return "dns_discover";
    case RouteHelperQueryType::TcpPreflight: return "tcp_preflight";
  }
  return "unknown";
}

RouteHelperQueryType route_helper_query_type_from_string(const std::string& value) {
  if (value == "bgp_lookup")    return RouteHelperQueryType::BgpLookup;
  if (value == "ttl_probe")     return RouteHelperQueryType::TtlProbe;
  if (value == "dns_discover")  return RouteHelperQueryType::DnsDiscover;
  if (value == "tcp_preflight") return RouteHelperQueryType::TcpPreflight;
  throw std::invalid_argument("unknown route helper query type: " + value);
}

// ── JSON serialization (manual, no nlohmann dependency) ───────────────────────

namespace {

std::string escape_json_string(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      case '\t': out += "\\t";  break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          out += "\\u00";
          out += "0123456789abcdef"[static_cast<unsigned char>(c) >> 4];
          out += "0123456789abcdef"[static_cast<unsigned char>(c) & 0x0F];
        } else {
          out += c;
        }
    }
  }
  return out;
}

// Simple JSON field extractor (for known string fields).
// Handles basic escape sequences: \", \\, \n, \r, \t
std::string extract_json_string(const std::string& json, const std::string& key) {
  const std::string pattern = "\"" + key + "\":\"";
  const auto pos = json.find(pattern);
  if (pos == std::string::npos) return "";
  const auto start = pos + pattern.size();
  std::string result;
  result.reserve(json.size() - start);
  for (std::size_t i = start; i < json.size(); ++i) {
    if (json[i] == '"') break;
    if (json[i] == '\\' && i + 1 < json.size()) {
      const char next = json[i + 1];
      switch (next) {
        case '"':  result += '"';  i++; break;
        case '\\': result += '\\'; i++; break;
        case 'n':  result += '\n'; i++; break;
        case 'r':  result += '\r'; i++; break;
        case 't':  result += '\t'; i++; break;
        default:   result += json[i]; break;
      }
    } else {
      result += json[i];
    }
  }
  return result;
}

// Simple JSON field extractor for integer fields.
long long extract_json_int(const std::string& json, const std::string& key) {
  const std::string pattern = "\"" + key + "\":";
  const auto pos = json.find(pattern);
  if (pos == std::string::npos) return 0;
  const auto start = pos + pattern.size();
  long long value = 0;
  bool negative = false;
  std::size_t i = start;
  if (i < json.size() && json[i] == '-') { negative = true; i++; }
  while (i < json.size() && json[i] >= '0' && json[i] <= '9') {
    value = value * 10 + (json[i] - '0');
    i++;
  }
  return negative ? -value : value;
}

}  // namespace

std::string RouteHelperRequest::to_json() const {
  std::string json = "{\"schema\":\"" + escape_json_string(schema) + "\"";
  json += ",\"query_type\":\"" + to_string(query_type) + "\"";
  json += ",\"endpoint_identity\":\"" + escape_json_string(endpoint_identity) + "\"";
  json += ",\"ip\":\"" + escape_json_string(ip) + "\"";
  json += ",\"port\":" + std::to_string(port);
  json += ",\"dc_id\":" + std::to_string(dc_id);
  json += ",\"ipv6\":" + std::string(ipv6 ? "true" : "false");
  json += ",\"timeout_ms\":" + std::to_string(timeout.count());
  json += ",\"expected_asns\":\"" + escape_json_string(expected_asns) + "\"";
  json += ",\"config_path\":\"" + escape_json_string(config_path) + "\"";
  json += "}";
  return json;
}

RouteHelperRequest RouteHelperRequest::from_json(const std::string& json) {
  RouteHelperRequest req;
  req.schema = extract_json_string(json, "schema");
  req.query_type = route_helper_query_type_from_string(extract_json_string(json, "query_type"));
  req.endpoint_identity = extract_json_string(json, "endpoint_identity");
  req.ip = extract_json_string(json, "ip");
  req.port = static_cast<std::uint16_t>(extract_json_int(json, "port"));
  req.dc_id = static_cast<std::int32_t>(extract_json_int(json, "dc_id"));
  req.ipv6 = json.find("\"ipv6\":true") != std::string::npos;
  req.timeout = std::chrono::milliseconds(extract_json_int(json, "timeout_ms"));
  req.expected_asns = extract_json_string(json, "expected_asns");
  req.config_path = extract_json_string(json, "config_path");
  return req;
}

std::string RouteHelperResponse::to_json() const {
  std::string json = "{\"schema\":\"" + escape_json_string(schema) + "\"";
  json += ",\"request_schema\":\"" + escape_json_string(request_schema) + "\"";
  json += ",\"query_type\":\"" + to_string(query_type) + "\"";
  json += ",\"endpoint_identity\":\"" + escape_json_string(endpoint_identity) + "\"";
  json += ",\"status\":\"" + escape_json_string(status) + "\"";
  json += ",\"detail\":\"" + escape_json_string(detail) + "\"";
  json += ",\"result_json\":\"" + escape_json_string(result_json) + "\"";
  json += ",\"elapsed_ms\":" + std::to_string(elapsed.count());
  json += "}";
  return json;
}

RouteHelperResponse RouteHelperResponse::from_json(const std::string& json) {
  RouteHelperResponse resp;
  resp.schema = extract_json_string(json, "schema");
  resp.request_schema = extract_json_string(json, "request_schema");
  resp.query_type = route_helper_query_type_from_string(extract_json_string(json, "query_type"));
  resp.endpoint_identity = extract_json_string(json, "endpoint_identity");
  resp.status = extract_json_string(json, "status");
  resp.detail = extract_json_string(json, "detail");
  resp.result_json = extract_json_string(json, "result_json");
  resp.elapsed = std::chrono::milliseconds(extract_json_int(json, "elapsed_ms"));
  return resp;
}

// ── Frame protocol ────────────────────────────────────────────────────────────

std::string encode_frame(const std::string& json_payload) {
  const auto size = static_cast<std::uint32_t>(json_payload.size());
  std::string frame;
  frame.reserve(4 + json_payload.size());
  frame.push_back(static_cast<char>((size >> 24) & 0xFF));
  frame.push_back(static_cast<char>((size >> 16) & 0xFF));
  frame.push_back(static_cast<char>((size >> 8) & 0xFF));
  frame.push_back(static_cast<char>(size & 0xFF));
  frame += json_payload;
  return frame;
}

std::optional<std::string> decode_frame(std::string& buffer) {
  if (buffer.size() < 4U) return std::nullopt;
  const auto size = (static_cast<std::uint32_t>(static_cast<unsigned char>(buffer[0])) << 24) |
                    (static_cast<std::uint32_t>(static_cast<unsigned char>(buffer[1])) << 16) |
                    (static_cast<std::uint32_t>(static_cast<unsigned char>(buffer[2])) << 8) |
                    static_cast<std::uint32_t>(static_cast<unsigned char>(buffer[3]));
  if (size > 1024U * 1024U) {
    throw std::runtime_error("route helper frame exceeds 1MB limit");
  }
  if (buffer.size() < 4U + size) return std::nullopt;
  std::string payload = buffer.substr(4U, size);
  buffer.erase(0, 4U + size);
  return payload;
}

// ── Route Helper Server ───────────────────────────────────────────────────────

namespace {

[[noreturn]] void throw_system_error(const std::string& operation) {
  throw std::runtime_error(operation + ": " + std::strerror(errno));
}

bool set_nonblocking(int fd) {
  const int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0;
}

bool wait_for_readable(int fd, std::chrono::milliseconds timeout) {
  struct pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLIN;
  const auto ms = static_cast<int>(timeout.count());
  const int result = ::poll(&pfd, 1, ms);
  return result > 0 && (pfd.revents & POLLIN) != 0;
}

bool read_all(int fd, std::string& payload_out, std::chrono::milliseconds timeout) {
  std::string buffer;
  while (true) {
    auto payload = decode_frame(buffer);
    if (payload.has_value()) {
      payload_out = std::move(*payload);
      return true;
    }
    if (!wait_for_readable(fd, timeout)) return false;
    std::array<char, 4096> chunk{};
    const ssize_t n = ::read(fd, chunk.data(), chunk.size());
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
      return false;
    }
    if (n == 0) return false;
    buffer.append(chunk.data(), static_cast<std::size_t>(n));
  }
}

bool write_all(int fd, const std::string& data, std::chrono::milliseconds timeout) {
  std::size_t offset = 0U;
  while (offset < data.size()) {
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    const auto ms = static_cast<int>(timeout.count());
    const int result = ::poll(&pfd, 1, ms);
    if (result <= 0) return false;
    const ssize_t n = ::write(fd, data.data() + offset, data.size() - offset);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
      return false;
    }
    offset += static_cast<std::size_t>(n);
  }
  return true;
}

}  // namespace

RouteHelperServer::RouteHelperServer(RouteHelperOptions options, RouteHelperHandler& handler)
    : options_(std::move(options)), handler_(handler) {
  options_.validate();

  // Remove stale socket file.
  ::unlink(options_.socket_path.c_str());

  listener_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (listener_fd_ < 0) throw_system_error("socket");

  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, options_.socket_path.c_str(), sizeof(addr.sun_path) - 1);

  if (::bind(listener_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
    ::close(listener_fd_);
    listener_fd_ = -1;
    throw_system_error("bind");
  }

  if (::chmod(options_.socket_path.c_str(), 0600) < 0) {
    ::close(listener_fd_);
    listener_fd_ = -1;
    throw_system_error("chmod");
  }

  if (::listen(listener_fd_, options_.backlog) < 0) {
    ::close(listener_fd_);
    listener_fd_ = -1;
    throw_system_error("listen");
  }
}

RouteHelperServer::~RouteHelperServer() { close_listener(); }

void RouteHelperServer::close_listener() noexcept {
  if (listener_fd_ >= 0) {
    ::close(listener_fd_);
    listener_fd_ = -1;
  }
  if (!options_.socket_path.empty()) {
    ::unlink(options_.socket_path.c_str());
  }
}

int RouteHelperServer::accept_connection() {
  if (!wait_for_readable(listener_fd_, options_.accept_timeout)) {
    return -1;  // timeout
  }

  struct sockaddr_un client_addr{};
  socklen_t client_len = sizeof(client_addr);
  int client_fd = ::accept(listener_fd_, reinterpret_cast<struct sockaddr*>(&client_addr),
                            &client_len);
  if (client_fd < 0) return -1;

  // Optional: verify same UID.
  if (options_.require_same_uid) {
    struct ucred cred{};
    socklen_t cred_len = sizeof(cred);
    if (::getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
      ::close(client_fd);
      return -1;
    }
    if (cred.uid != ::getuid()) {
      ::close(client_fd);
      return -1;
    }
  }

  set_nonblocking(client_fd);
  return client_fd;
}

bool RouteHelperServer::process_request(int client_fd) {
  std::string payload;
  if (!read_all(client_fd, payload, options_.io_timeout)) {
    ::close(client_fd);
    return false;
  }

  RouteHelperRequest request;
  RouteHelperResponse response;
  try {
    request = RouteHelperRequest::from_json(payload);
    request.validate();
    response = handler_.handle(request);
  } catch (const std::exception& ex) {
    response.status = "error";
    response.detail = ex.what();
    response.schema = "tgmap.route-helper-response.v1";
  }

  response.validate();
  const auto frame = encode_frame(response.to_json());
  const bool ok = write_all(client_fd, frame, options_.io_timeout);
  ::close(client_fd);
  return ok;
}

void RouteHelperServer::run() {
  while (true) {
    if (options_.max_requests > 0U && requests_processed_ >= options_.max_requests) {
      break;
    }

    const int client_fd = accept_connection();
    if (client_fd < 0) continue;

    (void)process_request(client_fd);
    requests_processed_++;
  }
}

const std::filesystem::path& RouteHelperServer::socket_path() const noexcept {
  return options_.socket_path;
}

// ── Route Helper Client ───────────────────────────────────────────────────────

RouteHelperClient::RouteHelperClient(std::filesystem::path socket_path)
    : socket_path_(std::move(socket_path)) {
  if (socket_path_.empty()) {
    throw std::invalid_argument("RouteHelperClient: socket_path is required");
  }
}

RouteHelperClient::~RouteHelperClient() = default;

RouteHelperResponse RouteHelperClient::send(const RouteHelperRequest& request,
                                             std::chrono::milliseconds timeout) {
  request.validate();

  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) throw_system_error("socket");

  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

  // Set non-blocking for timeout-aware connect.
  set_nonblocking(fd);

  int result = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
  if (result < 0 && errno != EINPROGRESS) {
    ::close(fd);
    throw_system_error("connect");
  }

  if (result < 0) {
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    const auto ms = static_cast<int>(timeout.count());
    if (::poll(&pfd, 1, ms) <= 0) {
      ::close(fd);
      throw std::runtime_error("route helper connect timed out");
    }
    int error = 0;
    socklen_t err_len = sizeof(error);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &err_len) < 0 || error != 0) {
      ::close(fd);
      throw std::runtime_error("route helper connect failed");
    }
  }

  // Send request.
  const auto frame = encode_frame(request.to_json());
  if (!write_all(fd, frame, timeout)) {
    ::close(fd);
    throw std::runtime_error("route helper send failed");
  }

  // Receive response.
  std::string payload;
  if (!read_all(fd, payload, timeout)) {
    ::close(fd);
    throw std::runtime_error("route helper receive failed");
  }

  ::close(fd);

  auto response = RouteHelperResponse::from_json(payload);
  response.validate();
  return response;
}

}  // namespace tgmap::mtproto
