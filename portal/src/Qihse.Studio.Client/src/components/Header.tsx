import { Activity, Server, Radio, Database, ShieldCheck } from 'lucide-react';
import type { TelemetryFrame } from '../types';

interface HeaderProps {
  telemetry: TelemetryFrame | null;
  isConnected: boolean;
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  telemetry,
  isConnected,
  activeTab,
  setActiveTab,
}) => {
  return (
    <header className="border-b border-slate-800 bg-[#0d1017]/90 backdrop-blur sticky top-0 z-50 px-6 py-3">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold">
            Q
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold tracking-wider text-slate-100">QIHSE STUDIO</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                v2.0 ASP.NET CORE
              </span>
            </div>
            <div className="text-xs text-slate-400">Ultra-High-Speed Native Memory Fabric</div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('telemetry')}
            className={`px-3 py-1.5 rounded text-xs flex items-center gap-2 transition-colors ${
              activeTab === 'telemetry'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-[0_0_10px_rgba(0,240,255,0.2)]'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Activity size={14} />
            Fleet Telemetry
          </button>
          <button
            onClick={() => setActiveTab('cluster')}
            className={`px-3 py-1.5 rounded text-xs flex items-center gap-2 transition-colors ${
              activeTab === 'cluster'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 shadow-[0_0_10px_rgba(57,255,20,0.2)]'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Server size={14} />
            Cluster Mesh & Slots
          </button>
          <button
            onClick={() => setActiveTab('vectors')}
            className={`px-3 py-1.5 rounded text-xs flex items-center gap-2 transition-colors ${
              activeTab === 'vectors'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/50 shadow-[0_0_10px_rgba(168,85,247,0.2)]'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Database size={14} />
            Vector DB & HNSW
          </button>
        </nav>

        {/* Real-time Status Pills */}
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-800">
            <Radio
              size={12}
              className={isConnected ? 'text-emerald-400 animate-pulse' : 'text-rose-400'}
            />
            <span className={isConnected ? 'text-emerald-400 font-semibold' : 'text-slate-400'}>
              {isConnected ? 'SignalR 10Hz' : 'Polling REST'}
            </span>
          </div>

          <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-800">
            <ShieldCheck size={13} className="text-cyan-400" />
            <span className="text-slate-300">State:</span>
            <span className="text-cyan-300 font-bold">
              {telemetry?.clusterState || 'HEALTHY_OK'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
