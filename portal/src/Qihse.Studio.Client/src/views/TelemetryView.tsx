import { Cpu, Zap, Clock, HardDrive, BarChart3, ShieldCheck } from 'lucide-react';
import type { TelemetryFrame, QihseNode } from '../types';

interface TelemetryViewProps {
  telemetry: TelemetryFrame | null;
}

export const TelemetryView: React.FC<TelemetryViewProps> = ({ telemetry }) => {
  if (!telemetry) {
    return (
      <div className="py-20 text-center text-slate-500 animate-pulse">
        Connecting to ASP.NET Core SignalR hub...
      </div>
    );
  }

  const lanNodes = telemetry.nodes.filter((n) => n.clusterType === 'lan');
  const remoteNodes = telemetry.nodes.filter((n) => n.clusterType === 'remote');

  const renderNodeCard = (node: QihseNode) => (
    <div
      key={node.id}
      className="p-4 rounded border border-slate-800 bg-[#0d1017] hover:border-slate-700 transition-all flex flex-col justify-between overflow-hidden"
    >
      <div>
        {/* Row 1: Name, Role, Status Badges (Left) vs Throughput & Latency (Right) */}
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 min-w-0">
            <span className="font-bold text-cyan-300 text-base shrink-0">{node.name}</span>
            <span
              className={`text-[10px] px-1.5 py-0.5 rounded border shrink-0 ${
                node.clusterType === 'remote'
                  ? 'bg-purple-950/80 border-purple-800 text-purple-300'
                  : 'bg-emerald-950/80 border-emerald-800 text-emerald-400'
              }`}
            >
              {node.role.toUpperCase()}
            </span>
            <span
              className={`text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 ${
                node.status === 'online'
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                  : 'bg-slate-800 text-slate-500'
              }`}
            >
              {node.status.toUpperCase()}
            </span>
          </div>

          <div className="text-right shrink-0">
            <div className="text-xs font-mono text-cyan-400 font-bold">
              {Math.round(node.qps).toLocaleString()} ops/s
            </div>
            <div className="text-[10px] text-slate-400">
              RTT: {node.pingMs > 0 ? `${node.pingMs.toFixed(1)} ms` : '—'}
            </div>
          </div>
        </div>

        {/* Row 2: Node ID and Endpoint Badges */}
        <div className="flex flex-wrap items-center gap-1.5 mt-2">
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
            {node.id}
          </span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400 font-mono break-all">
            {node.host}:{node.port}
          </span>
        </div>

        {/* Architecture & Network Tier */}
        <div className="text-xs text-slate-300 mt-2 font-medium">{node.architecture}</div>
        <div className="text-[11px] text-slate-500 mt-0.5 truncate">{node.networkTier}</div>
      </div>

      <div>
        {/* Shard Slots & Memory */}
        <div className="flex items-center justify-between text-[11px] text-slate-400 mt-3 pt-2 border-t border-slate-800/60 font-mono">
          <span>Partition: {node.shardSlots}</span>
          <span>RAM: {(node.memoryBytes / (1024 * 1024 * 1024)).toFixed(1)} GB</span>
        </div>

        {/* Active ISA Capability Badges */}
        <div className="mt-3 flex flex-wrap gap-1.5">
          {node.isaCapabilities.map((cap) => (
            <span
              key={cap}
              className={`text-[10px] px-2 py-0.5 rounded font-mono border ${
                cap.includes('AVX-512') || cap.includes('VNNI') || cap.includes('VPOPCNTDQ') || cap.includes('PQC')
                  ? 'bg-purple-950/60 border-purple-700 text-purple-300 shadow-[0_0_8px_rgba(168,85,247,0.15)]'
                  : cap.includes('SHA-NI') || cap.includes('VPCLMUL') || cap.includes('ML-KEM')
                  ? 'bg-amber-950/60 border-amber-700 text-amber-300'
                  : cap.includes('AVX2') || cap.includes('FMA') || cap.includes('WireGuard')
                  ? 'bg-cyan-950/60 border-cyan-700 text-cyan-300'
                  : cap.includes('TSX')
                  ? 'bg-rose-950/60 border-rose-700 text-rose-300'
                  : 'bg-slate-800/80 border-slate-700 text-slate-300'
              }`}
            >
              {cap}
            </span>
          ))}
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Top Level Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* QPS */}
        <div className="p-4 rounded-lg bg-[#12151d] border border-slate-800 relative overflow-hidden group">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-500 to-transparent" />
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>CLUSTER THROUGHPUT</span>
            <Zap size={14} className="text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100">
            {Math.round(telemetry.qps).toLocaleString()}{' '}
            <span className="text-xs font-normal text-cyan-400">ops/s</span>
          </div>
          <div className="text-[11px] text-emerald-400 mt-2 flex items-center gap-1">
            <span>↑ High-throughput RESP pipeline active</span>
          </div>
        </div>

        {/* P50 Latency */}
        <div className="p-4 rounded-lg bg-[#12151d] border border-slate-800 relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-emerald-500 to-transparent" />
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>P50 MEDIAN LATENCY</span>
            <Clock size={14} className="text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100">
            {telemetry.latencyP50Us.toFixed(1)}{' '}
            <span className="text-xs font-normal text-emerald-400">µs</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-2">
            P95: <span className="text-slate-200">{telemetry.latencyP95Us.toFixed(1)} µs</span> · P99:{' '}
            <span className="text-slate-200">{telemetry.latencyP99Us.toFixed(1)} µs</span>
          </div>
        </div>

        {/* Total Operations */}
        <div className="p-4 rounded-lg bg-[#12151d] border border-slate-800 relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-purple-500 to-transparent" />
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>TOTAL RETRIEVALS</span>
            <BarChart3 size={14} className="text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100">
            {telemetry.totalOperations.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 mt-2">Continuous hardware telemetry counter</div>
        </div>

        {/* Active Vectors */}
        <div className="p-4 rounded-lg bg-[#12151d] border border-slate-800 relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-amber-500 to-transparent" />
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>VECTOR RESIDENCY</span>
            <HardDrive size={14} className="text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100">
            {telemetry.activeVectors.toLocaleString()}{' '}
            <span className="text-xs font-normal text-amber-400">vecs</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-2">128-D FP32 / FP16 / INT8 tiered in RAM</div>
        </div>
      </div>

      {/* Cluster 1: Fleet Hardware Specialization Matrix (LAN Mesh) */}
      <div className="p-5 rounded-lg bg-[#12151d] border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Cpu size={18} className="text-cyan-400" />
            <h2 className="text-sm font-bold tracking-wider text-slate-200 uppercase">
              Cluster 1: Local LAN Sovereign Mesh Hardware Specialization & ISA Matrix
            </h2>
          </div>
          <div className="text-xs text-slate-400">
            Dynamic C99 / System Detection (<code className="text-cyan-400">qihse_cpu_detect()</code>)
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {lanNodes.map((node) => renderNodeCard(node))}
        </div>
      </div>

      {/* Cluster 2: Remote Sovereign Fallback Mesh Hardware & Cryptography Matrix */}
      <div className="p-5 rounded-lg bg-[#12151d] border border-purple-900/60">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <ShieldCheck size={18} className="text-purple-400" />
            <h2 className="text-sm font-bold tracking-wider text-purple-200 uppercase">
              Cluster 2: Remote Sovereign Fallback Mesh (PQC / WireGuard Overlay)
            </h2>
          </div>
          <div className="text-xs text-purple-400 font-mono">
            ML-DSA-87 / ML-KEM-1024 Post-Quantum Consensus
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {remoteNodes.map((node) => renderNodeCard(node))}
        </div>
      </div>
    </div>
  );
};
