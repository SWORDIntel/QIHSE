import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Clock,
  Cpu,
  Database,
  Gauge,
  Network,
  RefreshCw,
  Server,
  Settings,
  Wifi,
  WifiOff,
  Zap,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

const METRICS_ENDPOINT = 'http://127.0.0.1:8080/metrics';
const POLL_INTERVAL_MS = 1000;
const WINDOW_SIZE = 60;

const initialSample = () => ({
  timestamp: Date.now(),
  time: new Date().toLocaleTimeString([], {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }),
  qps: 0,
  latency: 0,
});

const percentile = (values, p) => {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(index, 0)];
};

const formatNumber = (value) => {
  const n = Number(value) || 0;
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(2)}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return Math.round(n).toLocaleString();
};

const formatLatency = (value) => `${(Number(value) || 0).toFixed(2)} ms`;

const MetricCard = ({ title, value, detail, icon: Icon, tone = 'primary' }) => (
  <div className={`card metric-card tone-${tone}`}>
    <div className="card-title">
      <span>{title}</span>
      <Icon size={18} aria-hidden="true" />
    </div>
    <div className="card-value">{value}</div>
    {detail && <div className="metric-detail">{detail}</div>}
  </div>
);

const EmptyState = ({ icon: Icon, title, children }) => (
  <div className="empty-state">
    <div className="empty-state-icon"><Icon size={22} /></div>
    <div>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  </div>
);

export default function App() {
  const [samples, setSamples] = useState(() => Array.from({ length: 20 }, initialSample));
  const [activeTab, setActiveTab] = useState('overview');
  const [activeVectors, setActiveVectors] = useState(0);
  const [connectionState, setConnectionState] = useState('connecting');
  const [lastUpdated, setLastUpdated] = useState(null);
  const [lastError, setLastError] = useState('');
  const [successfulPolls, setSuccessfulPolls] = useState(0);
  const [failedPolls, setFailedPolls] = useState(0);

  useEffect(() => {
    let cancelled = false;
    let controller = null;

    const poll = async () => {
      controller?.abort();
      controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 800);

      try {
        const response = await fetch(METRICS_ENDPOINT, {
          cache: 'no-store',
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const stats = await response.json();
        const qps = Number(stats.qps);
        const latency = Number(stats.latency);
        const vectors = Number(stats.active_vectors);
        const now = Date.now();

        if (!Number.isFinite(qps) || !Number.isFinite(latency)) {
          throw new Error('Malformed telemetry payload');
        }

        if (cancelled) return;
        setSamples((previous) => [
          ...previous,
          {
            timestamp: now,
            time: new Date(now).toLocaleTimeString([], {
              hour12: false,
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
            }),
            qps,
            latency,
          },
        ].slice(-WINDOW_SIZE));
        setActiveVectors(Number.isFinite(vectors) ? vectors : 0);
        setConnectionState('connected');
        setLastUpdated(now);
        setLastError('');
        setSuccessfulPolls((count) => count + 1);
      } catch (error) {
        if (cancelled) return;
        setConnectionState('down');
        setLastError(error?.name === 'AbortError' ? 'Metrics request timed out' : String(error?.message || error));
        setFailedPolls((count) => count + 1);
      } finally {
        window.clearTimeout(timeout);
      }
    };

    poll();
    const interval = window.setInterval(poll, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      controller?.abort();
      window.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    const interval = window.setInterval(() => {
      if (lastUpdated && Date.now() - lastUpdated > POLL_INTERVAL_MS * 3) {
        setConnectionState((state) => (state === 'connected' ? 'stale' : state));
      }
    }, 1000);
    return () => window.clearInterval(interval);
  }, [lastUpdated]);

  const telemetry = useMemo(() => {
    const observed = samples.filter((sample) => sample.timestamp && (sample.qps > 0 || sample.latency > 0));
    const qpsValues = observed.map((sample) => sample.qps);
    const latencyValues = observed.map((sample) => sample.latency);
    const latest = samples[samples.length - 1] || initialSample();
    const pollTotal = successfulPolls + failedPolls;

    return {
      latest,
      avgQps: qpsValues.length ? qpsValues.reduce((a, b) => a + b, 0) / qpsValues.length : 0,
      peakQps: qpsValues.length ? Math.max(...qpsValues) : 0,
      avgLatency: latencyValues.length ? latencyValues.reduce((a, b) => a + b, 0) / latencyValues.length : 0,
      p95Latency: percentile(latencyValues, 95),
      p99Latency: percentile(latencyValues, 99),
      pollSuccessRate: pollTotal ? (successfulPolls / pollTotal) * 100 : 0,
      observedSamples: observed.length,
    };
  }, [samples, successfulPolls, failedPolls]);

  const statusLabel = {
    connecting: 'Connecting',
    connected: 'Telemetry live',
    stale: 'Telemetry stale',
    down: 'Telemetry unavailable',
  }[connectionState];

  const lastUpdateAge = lastUpdated ? Math.max(0, Math.round((Date.now() - lastUpdated) / 1000)) : null;

  const tabs = [
    ['overview', Activity, 'Overview'],
    ['cluster', Server, 'Cluster'],
    ['storage', Database, 'Storage'],
    ['network', Network, 'Network'],
    ['settings', Settings, 'Telemetry'],
  ];

  return (
    <div className="dashboard-layout">
      <aside className="sidebar">
        <div className="brand"><Zap size={28} /> QIHSE</div>
        <div className="sidebar-caption">Runtime observability</div>
        <ul className="nav-links">
          {tabs.map(([id, Icon, label]) => (
            <li
              key={id}
              className={`nav-item ${activeTab === id ? 'active' : ''}`}
              onClick={() => setActiveTab(id)}
            >
              <Icon size={19} /> {label}
            </li>
          ))}
        </ul>
        <div className={`sidebar-health health-${connectionState}`}>
          {connectionState === 'connected' ? <Wifi size={16} /> : <WifiOff size={16} />}
          <div>
            <strong>{statusLabel}</strong>
            <span>{lastUpdateAge === null ? 'No samples yet' : `${lastUpdateAge}s since update`}</span>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="header">
          <div>
            <div className="eyebrow">QIHSE CONTROL PLANE</div>
            <h1>{tabs.find(([id]) => id === activeTab)?.[2] || 'Overview'}</h1>
            <p>Live runtime visibility from the native telemetry endpoint.</p>
          </div>
          <div className={`status-badge status-${connectionState}`}>
            <span className="status-dot" />
            {statusLabel}
          </div>
        </header>

        {connectionState !== 'connected' && (
          <div className={`telemetry-alert alert-${connectionState}`}>
            <AlertTriangle size={18} />
            <div>
              <strong>{connectionState === 'stale' ? 'Telemetry feed is stale' : 'Live telemetry is not available'}</strong>
              <span>{lastError || `Waiting for ${METRICS_ENDPOINT}`}</span>
            </div>
          </div>
        )}

        {activeTab === 'overview' && (
          <>
            <section className="metrics-grid">
              <MetricCard
                title="Current throughput"
                value={`${formatNumber(telemetry.latest.qps)} QPS`}
                detail={`Rolling avg ${formatNumber(telemetry.avgQps)} · peak ${formatNumber(telemetry.peakQps)}`}
                icon={Zap}
              />
              <MetricCard
                title="Current latency"
                value={formatLatency(telemetry.latest.latency)}
                detail={`p95 ${formatLatency(telemetry.p95Latency)} · p99 ${formatLatency(telemetry.p99Latency)}`}
                icon={Clock}
                tone="secondary"
              />
              <MetricCard
                title="Active vectors"
                value={formatNumber(activeVectors)}
                detail="Reported by native runtime"
                icon={Database}
                tone="accent"
              />
              <MetricCard
                title="Telemetry quality"
                value={`${telemetry.pollSuccessRate.toFixed(1)}%`}
                detail={`${successfulPolls} successful · ${failedPolls} failed polls`}
                icon={Gauge}
                tone={telemetry.pollSuccessRate >= 95 ? 'primary' : 'warning'}
              />
            </section>

            <section className="charts-grid">
              <div className="card chart-card">
                <div className="section-heading">
                  <div>
                    <span className="section-kicker">Throughput</span>
                    <h2>Queries per second</h2>
                  </div>
                  <BarChart3 size={20} />
                </div>
                <div className="chart-frame">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={samples} margin={{ top: 10, right: 8, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="qpsFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.35} />
                          <stop offset="95%" stopColor="var(--primary)" stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} />
                      <XAxis dataKey="time" minTickGap={36} />
                      <YAxis width={58} tickFormatter={formatNumber} />
                      <Tooltip formatter={(value) => [`${formatNumber(value)} QPS`, 'Throughput']} />
                      <Area type="monotone" dataKey="qps" stroke="var(--primary)" strokeWidth={2} fill="url(#qpsFill)" isAnimationActive={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="card chart-card">
                <div className="section-heading">
                  <div>
                    <span className="section-kicker">Latency</span>
                    <h2>Response time</h2>
                  </div>
                  <Clock size={20} />
                </div>
                <div className="chart-frame">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={samples} margin={{ top: 10, right: 8, left: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} />
                      <XAxis dataKey="time" minTickGap={36} />
                      <YAxis width={58} tickFormatter={(value) => `${Number(value).toFixed(1)}`} />
                      <Tooltip formatter={(value) => [formatLatency(value), 'Latency']} />
                      <Line type="monotone" dataKey="latency" stroke="var(--secondary)" strokeWidth={2} dot={false} isAnimationActive={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </section>

            <section className="detail-grid">
              <div className="card compact-card">
                <div className="section-heading">
                  <div>
                    <span className="section-kicker">Window</span>
                    <h2>Observed telemetry</h2>
                  </div>
                  <RefreshCw size={19} />
                </div>
                <dl className="kv-grid">
                  <div><dt>Samples with activity</dt><dd>{telemetry.observedSamples}</dd></div>
                  <div><dt>Rolling average QPS</dt><dd>{formatNumber(telemetry.avgQps)}</dd></div>
                  <div><dt>Rolling average latency</dt><dd>{formatLatency(telemetry.avgLatency)}</dd></div>
                  <div><dt>Polling interval</dt><dd>{POLL_INTERVAL_MS} ms</dd></div>
                </dl>
              </div>

              <div className="card compact-card">
                <div className="section-heading">
                  <div>
                    <span className="section-kicker">Data source</span>
                    <h2>Telemetry endpoint</h2>
                  </div>
                  <Cpu size={19} />
                </div>
                <code className="endpoint-code">{METRICS_ENDPOINT}</code>
                <p className="muted-copy">The dashboard only labels values as live when they are returned by the native runtime. Unsupported backend, cluster and network metrics are shown as unavailable rather than fabricated.</p>
              </div>
            </section>
          </>
        )}

        {activeTab === 'cluster' && (
          <section className="card tab-card">
            <div className="section-heading">
              <div><span className="section-kicker">Cluster</span><h2>Coordination visibility</h2></div>
              <Server size={20} />
            </div>
            <EmptyState icon={Server} title="Cluster-specific telemetry is not exposed by /metrics">
              Current visibility is limited to aggregate QPS, latency and active-vector count. Node identity, role, health, replication state and per-node load should remain unreported until the backend exports them.
            </EmptyState>
          </section>
        )}

        {activeTab === 'storage' && (
          <section className="detail-grid">
            <MetricCard title="Active vectors" value={formatNumber(activeVectors)} detail="Live aggregate from runtime" icon={Database} tone="accent" />
            <div className="card tab-card">
              <div className="section-heading"><div><span className="section-kicker">Storage</span><h2>Index visibility</h2></div><Database size={20} /></div>
              <EmptyState icon={Database} title="Detailed storage telemetry is not yet exported">
                HNSW levels, index bytes, cache residency, migration activity and out-of-core pressure should be added to the native metrics contract before they are visualized here.
              </EmptyState>
            </div>
          </section>
        )}

        {activeTab === 'network' && (
          <section className="detail-grid">
            <MetricCard title="Telemetry success" value={`${telemetry.pollSuccessRate.toFixed(1)}%`} detail={`${successfulPolls + failedPolls} total polls`} icon={Network} tone="secondary" />
            <div className="card tab-card">
              <div className="section-heading"><div><span className="section-kicker">Network</span><h2>Transport visibility</h2></div><Network size={20} /></div>
              <EmptyState icon={Network} title="Network/XDP counters are not in the current metrics payload">
                Packet rate, drop rate, XDP bypass, peer latency and transfer bytes should be sourced from native counters when available. The dashboard no longer displays placeholder network claims.
              </EmptyState>
            </div>
          </section>
        )}

        {activeTab === 'settings' && (
          <section className="card tab-card">
            <div className="section-heading"><div><span className="section-kicker">Telemetry</span><h2>Source status</h2></div><Settings size={20} /></div>
            <dl className="kv-grid wide">
              <div><dt>Endpoint</dt><dd><code>{METRICS_ENDPOINT}</code></dd></div>
              <div><dt>Poll interval</dt><dd>{POLL_INTERVAL_MS} ms</dd></div>
              <div><dt>Window</dt><dd>{WINDOW_SIZE} samples</dd></div>
              <div><dt>Status</dt><dd>{statusLabel}</dd></div>
              <div><dt>Last update</dt><dd>{lastUpdated ? new Date(lastUpdated).toLocaleString() : 'Never'}</dd></div>
              <div><dt>Last error</dt><dd>{lastError || 'None'}</dd></div>
            </dl>
          </section>
        )}
      </main>
    </div>
  );
}
