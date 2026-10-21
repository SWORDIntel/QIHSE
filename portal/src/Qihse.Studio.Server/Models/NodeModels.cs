using System.Text.Json.Serialization;

namespace Qihse.Studio.Server.Models;

public record QihseNode(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("cluster")] string Cluster,
    [property: JsonPropertyName("clusterType")] string ClusterType,
    [property: JsonPropertyName("host")] string Host,
    [property: JsonPropertyName("port")] int Port,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("architecture")] string Architecture,
    [property: JsonPropertyName("isaCapabilities")] List<string> IsaCapabilities,
    [property: JsonPropertyName("shardSlots")] string ShardSlots,
    [property: JsonPropertyName("pingMs")] double PingMs,
    [property: JsonPropertyName("memoryBytes")] long MemoryBytes,
    [property: JsonPropertyName("qps")] double Qps,
    [property: JsonPropertyName("networkTier")] string NetworkTier
);

public record TelemetryFrame(
    [property: JsonPropertyName("timestamp")] long Timestamp,
    [property: JsonPropertyName("qps")] double Qps,
    [property: JsonPropertyName("latencyP50Us")] double LatencyP50Us,
    [property: JsonPropertyName("latencyP95Us")] double LatencyP95Us,
    [property: JsonPropertyName("latencyP99Us")] double LatencyP99Us,
    [property: JsonPropertyName("activeVectors")] long ActiveVectors,
    [property: JsonPropertyName("totalOperations")] long TotalOperations,
    [property: JsonPropertyName("nodes")] List<QihseNode> Nodes,
    [property: JsonPropertyName("activeSlots")] int ActiveSlots,
    [property: JsonPropertyName("clusterState")] string ClusterState
);

public record SlotRange(
    [property: JsonPropertyName("start")] int Start,
    [property: JsonPropertyName("end")] int End,
    [property: JsonPropertyName("masterNodeId")] string MasterNodeId
);

public record VectorSearchRequest(
    [property: JsonPropertyName("query")] float[]? Query,
    [property: JsonPropertyName("dimensions")] int Dimensions = 128,
    [property: JsonPropertyName("topK")] int TopK = 10,
    [property: JsonPropertyName("metric")] string Metric = "cosine",
    [property: JsonPropertyName("precision")] string Precision = "fp32" // fp32, fp16, int8
);

public record VectorSearchResult(
    [property: JsonPropertyName("id")] long Id,
    [property: JsonPropertyName("distance")] double Distance,
    [property: JsonPropertyName("latencyUs")] double LatencyUs,
    [property: JsonPropertyName("precisionUsed")] string PrecisionUsed,
    [property: JsonPropertyName("hardwareAccelerated")] bool HardwareAccelerated,
    [property: JsonPropertyName("acceleratorUsed")] string AcceleratorUsed
);
