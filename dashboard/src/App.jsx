import React, { useState, useEffect } from 'react';
import { 
  Activity, Database, Cpu, HardDrive, 
  Network, Server, Settings, Zap,
  TrendingUp, TrendingDown, Clock, ShieldCheck
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer, BarChart, Bar, Legend
} from 'recharts';

// Initial seed data
const generateInitialData = () => {
  const data = [];
  let time = new Date().getTime();
  for (let i = 20; i >= 0; i--) {
    data.push({
      time: new Date(time - i * 1000).toLocaleTimeString([], { hour12: false, second: '2-digit', minute: '2-digit' }),
      qps: 0,
      latency: 0
    });
  }
  return data;
};

const MetricCard = ({ title, value, icon: Icon, trend, trendValue, color = "var(--primary)" }) => (
  <div className="card animate-slide-in">
    <div className="card-title">
      {title}
      <Icon size={18} color={color} />
    </div>
    <div className="card-value" style={{ color: "#fff" }}>{value}</div>
    {trend && (
      <div className={`value-trend ${trend === 'up' ? 'trend-up' : 'trend-down'}`}>
        {trend === 'up' ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
        {trendValue}
      </div>
    )}
  </div>
);

export default function App() {
  const [data, setData] = useState(generateInitialData());
  const [activeTab, setActiveTab] = useState('overview');
  const [activeVectors, setActiveVectors] = useState(0);

  // Poll native C backend telemetry server
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const response = await fetch("http://127.0.0.1:8080/metrics");
        const stats = await response.json();
        
        setData(prev => {
          const newData = [...prev.slice(1)];
          newData.push({
            time: new Date().toLocaleTimeString([], { hour12: false, second: '2-digit', minute: '2-digit' }),
            qps: stats.qps,
            latency: stats.latency
          });
          return newData;
        });
        setActiveVectors(stats.active_vectors);
      } catch (err) {
        // If server is down, push 0s
        setData(prev => {
          const newData = [...prev.slice(1)];
          newData.push({
            time: new Date().toLocaleTimeString([], { hour12: false, second: '2-digit', minute: '2-digit' }),
            qps: 0,
            latency: 0
          });
          return newData;
        });
      }
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="brand">
          <Zap size={28} />
          QIHSE
        </div>
        
        <ul className="nav-links">
          <li className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
            <Activity size={20} /> Overview
          </li>
          <li className={`nav-item ${activeTab === 'cluster' ? 'active' : ''}`} onClick={() => setActiveTab('cluster')}>
            <Server size={20} /> Cluster Nodes
          </li>
          <li className={`nav-item ${activeTab === 'storage' ? 'active' : ''}`} onClick={() => setActiveTab('storage')}>
            <Database size={20} /> Vector Storage
          </li>
          <li className={`nav-item ${activeTab === 'network' ? 'active' : ''}`} onClick={() => setActiveTab('network')}>
            <Network size={20} /> Network (XDP)
          </li>
          <li className="nav-item" style={{ marginTop: 'auto' }}>
            <Settings size={20} /> Settings
          </li>
        </ul>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <header className="header">
          <div>
            <h1>{activeTab.charAt(0).toUpperCase() + activeTab.slice(1)} Dashboard</h1>
            <p style={{ color: 'var(--text-muted)', marginTop: '4px' }}>Monitor cluster health and performance</p>
          </div>
          <div className="status-badge">
            <div className="status-dot"></div>
            Cluster Online (v1.4.2)
          </div>
        </header>

        {activeTab === 'overview' && (
          <>
            <div className="metrics-grid">
              <MetricCard 
                title="Throughput (QPS)" 
                value={Math.round(data[data.length-1].qps).toLocaleString()} 
                icon={Zap} 
                trend="up" 
                trendValue="+12.4% vs last hour"
                color="var(--primary)"
              />
              <MetricCard 
                title="P99 Latency" 
                value={`${data[data.length-1].latency.toFixed(2)} ms`} 
                icon={Clock} 
                trend="down" 
                trendValue="-0.15ms vs last hour"
                color="var(--secondary)"
              />
              <MetricCard 
                title="Active Vectors" 
                value={(activeVectors / 1000000000).toFixed(2) + "B"} 
                icon={Database} 
                trend="up" 
                trendValue="Live Sync"
                color="var(--accent)"
              />
              <MetricCard 
                title="Security / AST" 
                value="Secure" 
                icon={ShieldCheck} 
                color="#a78bfa"
              />
            </div>

            <div className="charts-grid animate-slide-in delay-1">
              <div className="card" style={{ height: '400px' }}>
                <h3 style={{ marginBottom: '1.5rem', fontWeight: 600 }}>Queries Per Second (Real-time)</h3>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={data} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorQps" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="var(--primary)" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="time" tick={{ fill: 'var(--text-muted)', fontSize: 12 }} />
                    <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 12 }} />
                    <Tooltip />
                    <Area 
                      type="monotone" 
                      dataKey="qps" 
                      stroke="var(--primary)" 
                      strokeWidth={2}
                      fillOpacity={1} 
                      fill="url(#colorQps)" 
                      isAnimationActive={false}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
                <h3 style={{ marginBottom: '1.5rem', fontWeight: 600 }}>Cluster Topology</h3>
                <div className="node-list">
                  <div className="node-item">
                    <div className="node-info">
                      <div className="node-icon"><Server size={20} /></div>
                      <div>
                        <div className="node-name">spinnaker-leader-01</div>
                        <div className="node-role">Raft Leader • 64 Cores</div>
                      </div>
                    </div>
                    <div style={{ color: 'var(--primary)', fontWeight: 600 }}>98%</div>
                  </div>
                  <div className="node-item">
                    <div className="node-info">
                      <div className="node-icon" style={{ color: 'var(--text-muted)' }}><Database size={20} /></div>
                      <div>
                        <div className="node-name">bombe-worker-02</div>
                        <div className="node-role">SIMD Worker • 32 Cores</div>
                      </div>
                    </div>
                    <div style={{ color: 'var(--text-main)', fontWeight: 600 }}>64%</div>
                  </div>
                  <div className="node-item">
                    <div className="node-info">
                      <div className="node-icon" style={{ color: 'var(--text-muted)' }}><Database size={20} /></div>
                      <div>
                        <div className="node-name">bombe-worker-03</div>
                        <div className="node-role">SIMD Worker • 32 Cores</div>
                      </div>
                    </div>
                    <div style={{ color: 'var(--text-main)', fontWeight: 600 }}>61%</div>
                  </div>
                </div>
                <div style={{ marginTop: 'auto', paddingTop: '1.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                    <span>Memory Capacity (UMA)</span>
                    <span>8.4 TB / 12 TB</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'var(--panel-border)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ width: '70%', height: '100%', background: 'var(--secondary)' }}></div>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {activeTab === 'cluster' && (
          <div className="card animate-slide-in">
            <h2>Cluster Nodes View</h2>
            <p style={{ color: 'var(--text-muted)', marginTop: '1rem' }}>Detailed individual node breakdown and thread affinities would appear here.</p>
          </div>
        )}

        {activeTab === 'storage' && (
          <div className="card animate-slide-in">
            <h2>Vector Storage Indexing</h2>
            <p style={{ color: 'var(--text-muted)', marginTop: '1rem' }}>HNSW memory levels, TRITON graphs, and Out-of-Core disk swapping metrics go here.</p>
          </div>
        )}

        {activeTab === 'network' && (
          <div className="card animate-slide-in">
            <h2>Network eBPF/XDP Stats</h2>
            <p style={{ color: 'var(--text-muted)', marginTop: '1rem' }}>Zero-copy packet bypass rates and latency jitter mapping.</p>
          </div>
        )}

      </main>
    </div>
  );
}
