using System.Diagnostics;
using Microsoft.AspNetCore.SignalR;
using Qihse.Studio.Server.Hubs;
using Qihse.Studio.Server.Models;

namespace Qihse.Studio.Server.Services;

public class ClusterMeshService : BackgroundService
{
    private readonly IHubContext<TelemetryHub> _hubContext;
    private readonly ILogger<ClusterMeshService> _logger;
    private readonly List<QihseNodeConfig> _configuredNodes;
    private readonly Dictionary<string, QihseRespClient> _clients = new();
    private TelemetryFrame _latestFrame;
    private readonly object _stateLock = new();
    private long _totalOperations = 0;
    private readonly Random _rand = new();

    public TelemetryFrame LatestFrame
    {
        get
        {
            lock (_stateLock) return _latestFrame;
        }
    }

    private readonly string _clusterPassword;

    public record QihseNodeConfig(string Id, string Host, int Port, string Architecture, List<string> Capabilities, string ShardSlots);

    public ClusterMeshService(IHubContext<TelemetryHub> hubContext, ILogger<ClusterMeshService> logger, IConfiguration config)
    {
        _hubContext = hubContext;
        _logger = logger;

        _clusterPassword = Environment.GetEnvironmentVariable("QIHSE_CLUSTER_PASSWORD")
            ?? config.GetValue<string>("Cluster:Password")
            ?? string.Empty;

        _configuredNodes = new List<QihseNodeConfig>
        {
            new("node-0", "127.0.0.1", 7100, "Ivy Bridge-EP (Xeon E5-2470 v2)", 
                new List<string> { "AVX", "F16C", "AES-NI", "PCLMUL (Hardware CRC16)", "POPCNT", "FSGSBASE", "CX16" }, "0-4549"),
            new("node-5", "192.168.1.90", 7115, "Broadwell-EP (Dual Xeon E5-2690 v4)", 
                new List<string> { "AVX2", "FMA3", "BMI1", "BMI2", "MOVBE", "TSX (RTM)", "RDSEED", "ADX", "PCLMUL (6.0 GiB/s)", "LZCNT" }, "4550-10922"),
            new("node-1", "192.168.1.250", 7101, "Zen 2 (AMD EPYC 7662 64C/128T)", 
                new List<string> { "AVX2", "SHA-NI", "CLZERO", "CLWB", "RDPID", "ADX", "RDSEED", "64 Cores" }, "10923-16383"),
            new("node-sec", "192.168.1.92", 7100, "Zen 4 (Ryzen 9 7950X @ 4.5GHz)", 
                new List<string> { "AVX-512F", "AVX-512 VNNI", "AVX-512 VPOPCNTDQ (8x)", "SHA-NI (2.0 GB/s)", "VPCLMULQDQ (>20 GiB/s)", "VAES", "CLZERO", "CLWB", "RDPID" }, "Standby Vector Shard")
        };

        foreach (var n in _configuredNodes)
        {
            _clients[n.Id] = new QihseRespClient(n.Host, n.Port, _clusterPassword);
        }

        _latestFrame = BuildInitialFrame();
    }

    private TelemetryFrame BuildInitialFrame()
    {
        var nodes = _configuredNodes.Select(n => new QihseNode(
            n.Id, n.Host, n.Port, "unknown", "unavailable", n.Architecture, n.Capabilities, n.ShardSlots, 0, 0, 0
        )).ToList();

        return new TelemetryFrame(
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            0,
            0,
            0,
            0,
            0,
            _totalOperations,
            nodes,
            16384,
            "UNAVAILABLE"
        );
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("QIHSE ClusterMeshService started polling telemetry.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var sw = Stopwatch.StartNew();
                var activeNodeStates = new List<QihseNode>();

                foreach (var cfg in _configuredNodes)
                {
                    var client = _clients[cfg.Id];
                    double ping = 0;
                    string status = "unavailable";

                    if (string.IsNullOrEmpty(_clusterPassword))
                    {
                        status = "unconfigured";
                    }
                    else try
                    {
                        var pingSw = Stopwatch.StartNew();
                        var resp = await client.SendCommandAsync(new[] { "PING" }, stoppingToken);
                        pingSw.Stop();

                        if (resp == "PONG")
                        {
                            ping = pingSw.Elapsed.TotalMilliseconds;
                            status = "online";
                        }
                        else
                        {
                            ping = 0;
                            status = "unavailable";
                        }
                    }
                    catch
                    {
                        ping = 0;
                        status = "unavailable";
                    }

                    // PING does not measure QPS or memory; unknown metrics remain zero.
                    double nodeQps = 0;
                    long mem = 0;

                    activeNodeStates.Add(new QihseNode(
                        cfg.Id, cfg.Host, cfg.Port, "master", status, cfg.Architecture, cfg.Capabilities, cfg.ShardSlots, ping, mem, nodeQps
                    ));
                }

                double totalQps = activeNodeStates.Sum(n => n.Qps);
                _totalOperations += (long)(totalQps * 0.1);

                double p50 = 0, p95 = 0, p99 = 0; // no measured latency series

                var frame = new TelemetryFrame(
                    DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    totalQps,
                    p50,
                    p95,
                    p99,
                    0,
                    _totalOperations,
                    activeNodeStates,
                    0,
                    activeNodeStates.All(n => n.Status == "online") ? "REACHABLE_METRICS_UNAVAILABLE" : "DEGRADED"
                );

                lock (_stateLock)
                {
                    _latestFrame = frame;
                }

                // Push to SignalR clients
                await _hubContext.Clients.Group("TelemetrySubscribers")
                    .SendAsync("ReceiveTelemetry", frame, stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error during cluster telemetry broadcast");
            }

            // No automatic trust of endpoints supplied in CLUSTER NODES replies.

            // 10 Hz update frequency (100 ms interval)
            await Task.Delay(100, stoppingToken);
        }
    }

    private async Task AutoDiscoverClusterMeshAsync(CancellationToken ct)
    {
        try
        {
            var seedClient = _clients.Values.FirstOrDefault(c => c.IsConnected) 
                             ?? _clients.Values.FirstOrDefault();
            if (seedClient == null) return;

            var rawNodes = await seedClient.SendCommandAsync(new[] { "CLUSTER", "NODES" }, ct);
            if (string.IsNullOrEmpty(rawNodes) || rawNodes.StartsWith("-")) return;

            var lines = rawNodes.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                var parts = line.Trim().Split(' ');
                if (parts.Length < 8) continue;

                var endpoint = parts[1].Split('@')[0];
                var hostPort = endpoint.Split(':');
                if (hostPort.Length < 2) continue;
                var host = hostPort[0];
                if (!int.TryParse(hostPort[1], out int port)) continue;

                string id = host switch
                {
                    "192.168.1.91" or "127.0.0.1" => "node-0",
                    "192.168.1.90" => "node-5",
                    "192.168.1.250" => "node-1",
                    "192.168.1.92" => "node-sec",
                    _ => $"node-{host.Replace('.', '-')}"
                };

                string slots = parts.Length > 8 ? string.Join(" ", parts.Skip(8)) : "unassigned";

                lock (_stateLock)
                {
                    var existing = _configuredNodes.FirstOrDefault(n => n.Id == id);
                    if (existing != null)
                    {
                        var idx = _configuredNodes.IndexOf(existing);
                        _configuredNodes[idx] = existing with { Host = host, Port = port, ShardSlots = slots };
                    }
                    if (!_clients.ContainsKey(id))
                    {
                        _clients[id] = new QihseRespClient(host, port, _clusterPassword);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Cluster mesh auto-discovery probe notice");
        }
    }

    public override void Dispose()
    {
        foreach (var c in _clients.Values) c.Dispose();
        base.Dispose();
    }
}
