#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace tgmap::mtproto {

// ── Protocol ──────────────────────────────────────────────────────────────────

// Query types supported by the route helper.
enum class RouteHelperQueryType {
  // BGP route lookup via RIPEstat (no traffic to target).
  BgpLookup,
  // TTL binary-search probe (requires raw socket / CAP_NET_RAW).
  TtlProbe,
  // DNS discovery for Telegram endpoints.
  DnsDiscover,
  // TCP preflight reachability check.
  TcpPreflight,
};

// A request from the main process to the route helper.
struct RouteHelperRequest final {
  std::string schema = "tgmap.route-helper-request.v1";
  RouteHelperQueryType query_type = RouteHelperQueryType::BgpLookup;
  std::string endpoint_identity;
  std::string ip;
  std::uint16_t port = 0U;
  std::int32_t dc_id = 0;
  bool ipv6 = false;
  // Timeout for the operation (milliseconds).
  std::chrono::milliseconds timeout{5000};
  // Optional: expected ASNs for BGP lookup (comma-separated).
  std::string expected_asns;
  // Optional: config snapshot path for DNS discovery.
  std::string config_path;

  void validate() const;
  [[nodiscard]] std::string to_json() const;
  [[nodiscard]] static RouteHelperRequest from_json(const std::string& json);
};

// A response from the route helper to the main process.
struct RouteHelperResponse final {
  std::string schema = "tgmap.route-helper-response.v1";
  std::string request_schema;  // Echo of the request schema for correlation.
  RouteHelperQueryType query_type = RouteHelperQueryType::BgpLookup;
  std::string endpoint_identity;
  // "success" or "error"
  std::string status;
  std::string detail;
  // The result payload as a JSON string (query-type specific).
  std::string result_json;
  // Wall-clock time spent processing.
  std::chrono::milliseconds elapsed{};

  void validate() const;
  [[nodiscard]] std::string to_json() const;
  [[nodiscard]] static RouteHelperResponse from_json(const std::string& json);
};

// ── String conversion ─────────────────────────────────────────────────────────

[[nodiscard]] std::string to_string(RouteHelperQueryType type);
[[nodiscard]] RouteHelperQueryType route_helper_query_type_from_string(const std::string& value);

// ── Frame protocol ────────────────────────────────────────────────────────────

// Frame format: 4-byte big-endian length prefix + JSON payload.
// This matches the existing UnixIngress frame pattern.

// Serialize a frame: returns length-prefixed bytes.
[[nodiscard]] std::string encode_frame(const std::string& json_payload);

// Deserialize a frame: extracts the JSON payload from a length-prefixed buffer.
// Returns nullopt if the buffer is incomplete. Consumes bytes from the buffer.
// On success, removes the consumed bytes from the front of the buffer.
[[nodiscard]] std::optional<std::string> decode_frame(std::string& buffer);

// ── Route Helper Server ───────────────────────────────────────────────────────

struct RouteHelperOptions final {
  std::filesystem::path socket_path;
  std::chrono::milliseconds accept_timeout{5000};
  std::chrono::milliseconds io_timeout{30000};
  int backlog = 8;
  bool require_same_uid = true;
  // Maximum number of requests before the helper exits (0 = unlimited).
  std::uint64_t max_requests = 0U;

  void validate() const;
};

// Injectable request handler — abstracts the actual probe execution.
// Real implementation runs the probes; unit tests inject a fake.
class RouteHelperHandler {
 public:
  virtual ~RouteHelperHandler() = default;

  // Process a request and return a response.
  [[nodiscard]] virtual RouteHelperResponse handle(const RouteHelperRequest& request) = 0;
};

// The route helper server — listens on a Unix-domain socket and processes
// requests using the injected handler.
class RouteHelperServer final {
 public:
  RouteHelperServer(RouteHelperOptions options, RouteHelperHandler& handler);
  ~RouteHelperServer();

  RouteHelperServer(const RouteHelperServer&) = delete;
  RouteHelperServer& operator=(const RouteHelperServer&) = delete;
  RouteHelperServer(RouteHelperServer&&) = delete;
  RouteHelperServer& operator=(RouteHelperServer&&) = delete;

  // Run the server loop. Returns when max_requests is reached or the socket
  // is closed. Each accepted request is processed by the handler.
  void run();

  [[nodiscard]] const std::filesystem::path& socket_path() const noexcept;

 private:
  void close_listener() noexcept;
  [[nodiscard]] int accept_connection();
  [[nodiscard]] bool process_request(int client_fd);

  RouteHelperOptions options_;
  RouteHelperHandler& handler_;
  int listener_fd_ = -1;
  std::uint64_t requests_processed_ = 0U;
};

// ── Route Helper Client ───────────────────────────────────────────────────────

// Client for connecting to a running route helper and sending requests.
class RouteHelperClient final {
 public:
  explicit RouteHelperClient(std::filesystem::path socket_path);
  ~RouteHelperClient();

  RouteHelperClient(const RouteHelperClient&) = delete;
  RouteHelperClient& operator=(const RouteHelperClient&) = delete;
  RouteHelperClient(RouteHelperClient&&) = delete;
  RouteHelperClient& operator=(RouteHelperClient&&) = delete;

  // Send a request and receive a response. Throws on connection or protocol errors.
  [[nodiscard]] RouteHelperResponse send(const RouteHelperRequest& request,
                                          std::chrono::milliseconds timeout);

 private:
  std::filesystem::path socket_path_;
};

}  // namespace tgmap::mtproto
