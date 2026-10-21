import { useEffect, useRef, useState } from 'react';
import { Server, ArrowLeftRight, Layers, ShieldCheck, CheckCircle2 } from 'lucide-react';
import type { TelemetryFrame, SlotRange } from '../types';

interface ClusterMeshViewProps {
  telemetry: TelemetryFrame | null;
  apiToken: string;
}

export const ClusterMeshView: React.FC<ClusterMeshViewProps> = ({ telemetry, apiToken }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [migrationStatus, setMigrationStatus] = useState<string | null>(null);

  const lanNodes = telemetry?.nodes.filter((n) => n.clusterType === 'lan') || [];
  const remoteNodes = telemetry?.nodes.filter((n) => n.clusterType === 'remote') || [];

  // Dynamically derive 16,384 Shard Slot allocation from live LAN cluster nodes
  const dynamicSlotRanges: SlotRange[] = [];
  lanNodes.forEach((node) => {
    if (!node.shardSlots || node.shardSlots.includes('unassigned') || node.shardSlots.includes('Offline')) return;
    const ranges = node.shardSlots.split(' ');
    ranges.forEach((r) => {
      const parts = r.split('-');
      if (parts.length === 2) {
        const start = parseInt(parts[0], 10);
        const end = parseInt(parts[1], 10);
        if (!isNaN(start) && !isNaN(end)) {
          dynamicSlotRanges.push({
            start,
            end,
            masterNodeId: `${node.name} (${node.id})`,
          });
        }
      }
    });
  });
  dynamicSlotRanges.sort((a, b) => a.start - b.start);

  const slotRanges: SlotRange[] = dynamicSlotRanges.length > 0 ? dynamicSlotRanges : [
    { start: 0, end: 16383, masterNodeId: 'Discovered / All Slots' }
  ];

  const colors = ['#00f0ff', '#39ff14', '#a855f7', '#ffb700', '#f43f5e', '#ec4899'];

  // Draw 16,384 Slot Ring on Canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) - 30;
    const innerRadius = radius - 24;

    ctx.clearRect(0, 0, width, height);

    // Draw Shard Segments across 16,384 slots
    const totalSlots = 16384;
    slotRanges.forEach((range, idx) => {
      const startAngle = (range.start / totalSlots) * 2 * Math.PI - Math.PI / 2;
      const endAngle = (range.end / totalSlots) * 2 * Math.PI - Math.PI / 2;

      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, startAngle, endAngle);
      ctx.arc(centerX, centerY, innerRadius, endAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = colors[idx % colors.length] + 'cc';
      ctx.fill();

      // Border line between shards
      ctx.strokeStyle = '#0a0c10';
      ctx.lineWidth = 2;
      ctx.stroke();
    });

    // Center Display
    ctx.fillStyle = '#f8fafc';
    ctx.font = 'bold 15px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('16,384 SLOTS', centerX, centerY - 10);

    ctx.fillStyle = '#38bdf8';
    ctx.font = '10px monospace';
    ctx.fillText('LAN CLUSTER RING', centerX, centerY + 12);
  }, [telemetry, slotRanges]);

  const targetLanNode = lanNodes.find((n) => n.name !== 't420') || lanNodes[0];

  const handleSimulateMove = async () => {
    const targetName = targetLanNode ? `${targetLanNode.name} (${targetLanNode.id})` : 'Target Node';
    setMigrationStatus(`Migrating slots 1000-1100 to ${targetName}...`);
    try {
      const res = await fetch('/api/cluster/moveslots', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiToken}` },
        body: JSON.stringify({ start: 1000, end: 1100, masterNodeId: targetLanNode?.id || 'target' }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      setMigrationStatus(data.message || 'Migration request accepted.');
    } catch (err) {
      setMigrationStatus(`Migration unavailable: ${String(err)}`);
    }
  };

  const lanTitle = lanNodes.length > 0 ? lanNodes.map((n) => n.name).join(' · ') : 'Local Sovereign Mesh';
  const remoteTitle = remoteNodes.length > 0 ? remoteNodes.map((n) => n.name).join(' · ') : 'Remote Sovereign Mesh';

  return (
    <div className="space-y-6">
      {/* Cluster Mesh Topology & Ring */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Canvas Ring Visualizer */}
        <div className="lg:col-span-5 p-6 rounded-lg bg-[#12151d] border border-slate-800 flex flex-col items-center justify-center">
          <div className="w-full flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Layers size={16} className="text-cyan-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                LAN Cluster Shard Allocation Ring
              </h3>
            </div>
            <span className="text-[10px] text-emerald-400 font-mono">16,384 SLOTS</span>
          </div>

          <canvas
            ref={canvasRef}
            width={340}
            height={340}
            className="my-2 cursor-pointer hover:scale-[1.02] transition-transform"
          />

          <div className="grid grid-cols-1 gap-1.5 w-full mt-2 text-[11px] font-mono">
            {slotRanges.map((range, idx) => (
              <div
                key={range.masterNodeId + idx}
                className="p-1.5 rounded bg-slate-900 border border-slate-800 flex items-center justify-between"
              >
                <div className="flex items-center gap-2">
                  <div
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ backgroundColor: colors[idx % colors.length] }}
                  />
                  <span className="text-slate-200 font-semibold">{range.masterNodeId}</span>
                </div>
                <span className="text-slate-400">
                  [{range.start}..{range.end}]
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Node Mesh Table & Controls */}
        <div className="lg:col-span-7 space-y-4">
          {/* Cluster 1: Local LAN Mesh */}
          <div className="p-5 rounded-lg bg-[#12151d] border border-slate-800">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Server size={16} className="text-emerald-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  Cluster 1: Local LAN Sovereign Mesh ({lanTitle})
                </h3>
              </div>
              <button
                onClick={handleSimulateMove}
                className="px-2.5 py-1 rounded text-xs bg-cyan-600/20 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-600/30 flex items-center gap-1.5 transition-colors"
              >
                <ArrowLeftRight size={12} />
                Test CLUSTER MOVESLOTS
              </button>
            </div>

            {migrationStatus && (
              <div className="mb-4 p-2.5 rounded bg-cyan-950/50 border border-cyan-800 text-xs text-cyan-300 flex items-center gap-2">
                <CheckCircle2 size={14} className="text-cyan-400 shrink-0" />
                <span>{migrationStatus}</span>
              </div>
            )}

            <div className="space-y-2.5">
              {lanNodes.map((node, idx) => (
                <div
                  key={node.id}
                  className="p-3 rounded bg-[#0d1017] border border-slate-800 flex items-center justify-between"
                >
                  <div className="flex items-center gap-3">
                    <div
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: colors[idx % colors.length] }}
                    />
                    <div>
                      <div className="text-xs font-bold text-slate-100 flex items-center gap-2">
                        <span className="text-cyan-300 text-sm">{node.name}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 font-mono">
                          {node.id}
                        </span>
                        <span className="text-[11px] text-slate-400 font-mono">
                          {node.host}:{node.port}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">{node.architecture}</div>
                    </div>
                  </div>

                  <div className="flex items-center gap-5 text-xs font-mono">
                    <div>
                      <div className="text-slate-400 text-[10px]">SLOTS</div>
                      <div className="text-slate-200">{node.shardSlots}</div>
                    </div>
                    <div>
                      <div className="text-slate-400 text-[10px]">WIRE RTT</div>
                      <div className="text-emerald-400 font-bold">{node.pingMs > 0 ? `${node.pingMs.toFixed(2)} ms` : '—'}</div>
                    </div>
                    <div>
                      <div className="text-slate-400 text-[10px]">STATUS</div>
                      <div className={`font-bold ${node.status === 'online' ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {node.status.toUpperCase()}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Cluster 2: Remote Sovereign Fallback Mesh */}
          <div className="p-5 rounded-lg bg-[#12151d] border border-purple-900/60">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck size={16} className="text-purple-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-purple-200">
                  Cluster 2: Remote Sovereign Fallback Mesh ({remoteTitle})
                </h3>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950 border border-purple-700 text-purple-300 font-mono">
                WireGuard Sovereign Overlay
              </span>
            </div>

            <div className="space-y-2.5">
              {remoteNodes.map((node, idx) => (
                <div
                  key={node.id}
                  className="p-3 rounded bg-[#0d1017] border border-slate-800 flex items-center justify-between"
                >
                  <div className="flex items-center gap-3">
                    <div
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: colors[(idx + 3) % colors.length] }}
                    />
                    <div>
                      <div className="text-xs font-bold text-slate-100 flex items-center gap-2">
                        <span className="text-purple-300 text-sm">{node.name}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-950/80 border border-purple-800 text-purple-300 font-mono">
                          {node.role.toUpperCase()}
                        </span>
                        <span className="text-[11px] text-slate-400 font-mono">
                          {node.host}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">{node.architecture}</div>
                    </div>
                  </div>

                  <div className="flex items-center gap-5 text-xs font-mono">
                    <div>
                      <div className="text-slate-400 text-[10px]">CONSENSUS</div>
                      <div className="text-purple-300 font-semibold">{node.shardSlots}</div>
                    </div>
                    <div>
                      <div className="text-slate-400 text-[10px]">WIRE RTT</div>
                      <div className="text-purple-400 font-bold">{node.pingMs > 0 ? `${node.pingMs.toFixed(2)} ms` : '—'}</div>
                    </div>
                    <div>
                      <div className="text-slate-400 text-[10px]">STATUS</div>
                      <div className={`font-bold ${node.status === 'online' ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {node.status.toUpperCase()}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Wire Speed & Replication Notes */}
          <div className="p-4 rounded-lg bg-[#12151d] border border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <ShieldCheck size={16} className="text-cyan-400" />
              <span>Broadwell R730xd Line Rate: <strong className="text-slate-200">943 Mbps Wire Speed</strong> (&lt;0.1ms RTT)</span>
            </div>
            <span className="font-mono text-cyan-400">PCLMUL CRC32: 6.018 GiB/s</span>
          </div>
        </div>
      </div>
    </div>
  );
};
