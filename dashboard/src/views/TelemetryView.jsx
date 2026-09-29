import { useEffect, useState } from 'react';
import { BarChart3, Clock, Gauge, Zap } from 'lucide-react';
import {
  Area, AreaChart, CartesianGrid, Line, LineChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';
import { apiGet } from '../api.js';

// The original metrics-only dashboard, preserved as one tab.  It polls
// the native telemetry endpoint (default :8080) — unchanged behavior.
const METRICS_ENDPOINT = import.meta.env.VITE_QIHSE_METRICS_URL || '/metrics';
const POLL_INTERVAL_MS = 1000;
const WINDOW_SIZE = 60;

const fmt = (v) => {
  const n = Number(v) || 0;
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return Math.round(n).toLocaleString();
};

export default function TelemetryView() {
  const [samples, setSamples] = useState([]);
  const [vectors, setVectors] = useState(0);
  const [state, setState] = useState('connecting');
  const [prom, setProm] = useState(null);
  const loadProm = async () => {
    const { status, body } = await apiGet('/metrics');
    if (status === 200) setProm(body);
  };

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await fetch(METRICS_ENDPOINT, { cache: 'no-store' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const stats = await res.json();
        if (cancelled) return;
        const now = Date.now();
        setSamples((prev) => [...prev, {
          time: new Date(now).toLocaleTimeString([], { hour12: false }),
          qps: Number(stats.qps) || 0,
          latency: Number(stats.latency) || 0,
        }].slice(-WINDOW_SIZE));
        setVectors(Number(stats.active_vectors) || 0);
        setState('connected');
      } catch {
        if (!cancelled) setState('down');
      }
    };
    poll();
    const iv = setInterval(poll, POLL_INTERVAL_MS);
    return () => { cancelled = true; clearInterval(iv); };
  }, []);

  return (
    <>
      <section className="metrics-grid">
        <div className="card metric-card tone-primary">
          <div className="card-title"><span>Throughput</span><Zap size={18} /></div>
          <div className="card-value">{fmt(samples.at(-1)?.qps)} QPS</div>
        </div>
        <div className="card metric-card tone-secondary">
          <div className="card-title"><span>Latency</span><Clock size={18} /></div>
          <div className="card-value">{(samples.at(-1)?.latency || 0).toFixed(2)} ms</div>
        </div>
        <div className="card metric-card tone-accent">
          <div className="card-title"><span>Active vectors</span><BarChart3 size={18} /></div>
          <div className="card-value">{fmt(vectors)}</div>
        </div>
        <div className="card metric-card tone-warning">
          <div className="card-title"><span>Feed</span><Gauge size={18} /></div>
          <div className="card-value">{state}</div>
        </div>
      </section>
      <section className="charts-grid">
        <div className="card chart-card">
          <div className="section-heading">
            <div><span className="section-kicker">Throughput</span><h2>Queries per second</h2></div>
          </div>
          <div className="chart-frame">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={samples} margin={{ top: 10, right: 8, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="qpsFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#CC0000" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#CC0000" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="time" minTickGap={36} />
                <YAxis width={58} tickFormatter={fmt} />
                <Tooltip formatter={(v) => [`${fmt(v)} QPS`, 'Throughput']} />
                <Area type="monotone" dataKey="qps" stroke="#CC0000"
                      strokeWidth={2} fill="url(#qpsFill)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card chart-card">
          <div className="section-heading">
            <div><span className="section-kicker">Latency</span><h2>Response time</h2></div>
          </div>
          <div className="chart-frame">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={samples} margin={{ top: 10, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="time" minTickGap={36} />
                <YAxis width={58} tickFormatter={(v) => Number(v).toFixed(1)} />
                <Tooltip formatter={(v) => [`${(Number(v) || 0).toFixed(2)} ms`, 'Latency']} />
                <Line type="monotone" dataKey="latency" stroke="#4488CC"
                      strokeWidth={2} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="card tab-card">
        <div className="section-heading">
          <div><span className="section-kicker">Prometheus</span>
            <h2>METRICS.RENDER / FEDERATION.METRICS</h2></div>
        </div>
        <button className="primary-btn" onClick={loadProm}>Scrape node metrics</button>
        {prom && prom.node && <pre className="json-block">{prom.node}</pre>}
        {prom && prom.node_error && (
          <div className="form-error">{JSON.stringify(prom.node_error)}</div>)}
        {prom && prom.federation && (
          <pre className="json-block">{prom.federation}</pre>)}
        {prom && prom.federation_error && (
          <div className="form-error">{JSON.stringify(prom.federation_error)}</div>)}
      </section>
    </>
  );
}
