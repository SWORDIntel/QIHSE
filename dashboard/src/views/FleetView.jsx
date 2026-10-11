import { useEffect, useState } from 'react';
import { Server } from 'lucide-react';
import { apiGet, apiError } from '../api.js';

// Shared poll hook: fetch a bridge endpoint on an interval.
export function usePoll(path, intervalMs, active = true) {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!active || !path) return undefined;
    let cancelled = false;
    const tick = async () => {
      const { status, body } = await apiGet(path);
      if (cancelled) return;
      const err = status !== 200 ? `HTTP ${status}` : apiError(body);
      if (err && status !== 200) {
        setError(err);
      } else {
        setError(apiError(body) || '');
        setData(body);
      }
      setLoading(false);
    };
    tick();
    const iv = setInterval(tick, intervalMs);
    return () => { cancelled = true; clearInterval(iv); };
  }, [path, intervalMs, active]);

  return { data, error, loading };
}

export function NodeTable({ overview }) {
  const nodes = overview?.nodes || [];
  const cluster = overview?.cluster || {};
  return (
    <>
      <div className="kv-grid wide">
        <div><dt>cluster_state</dt><dd>{cluster.cluster_state ?? '—'}</dd></div>
        <div><dt>slots assigned</dt><dd>{cluster.cluster_slots_assigned ?? '—'}</dd></div>
        <div><dt>slots ok</dt><dd>{cluster.cluster_slots_ok ?? '—'}</dd></div>
        <div><dt>known nodes</dt><dd>{cluster.cluster_known_nodes ?? nodes.length}</dd></div>
        <div><dt>current epoch</dt><dd>{cluster.cluster_current_epoch ?? '—'}</dd></div>
      </div>
      <table className="data-table">
        <thead>
          <tr>
            <th>node</th><th>id</th><th>addr</th><th>up</th><th>latency</th>
            <th>role</th><th>slots</th><th>dbsize</th><th>clients</th>
            <th>fed</th><th>version</th><th>error</th>
          </tr>
        </thead>
        <tbody>
          {nodes.map((n) => (
            <tr key={n.index} className={n.up ? '' : 'row-down'}>
              <td>#{n.index}</td>
              <td><code>{n.id ? n.id.slice(0, 12) + '…' : '—'}</code></td>
              <td><code>{n.addr}</code></td>
              <td><span className={`dot ${n.up ? 'ok' : 'dn'}`} /></td>
              <td>{n.latency_ms != null ? `${n.latency_ms} ms` : '—'}</td>
              <td>{Array.isArray(n.role) ? (n.role[0] || '—') : (n.role || '—')}</td>
              <td>{n.slots ?? '—'}</td>
              <td>{n.dbsize ?? '—'}</td>
              <td>{n.clients ?? '—'}</td>
              <td>{n.fed_state ?? '—'}</td>
              <td><code>{n.version ?? '—'}</code></td>
              <td style={n.error ? { color: 'var(--coral)' } : undefined}>
                {n.error ? `${n.error.error_class}: ${n.error.message}` : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export default function FleetView() {
  const { data, error, loading } = usePoll('/overview', 3000);
  const [events, setEvents] = useState([]);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      const { status, body } = await apiGet('/log?limit=10');
      if (!cancelled && status === 200) {
        setEvents((body.log || []).slice(-10).reverse());
      }
    };
    tick();
    const iv = setInterval(tick, 4000);
    return () => { cancelled = true; clearInterval(iv); };
  }, []);

  return (
    <>
      <section className="card tab-card">
        <div className="section-heading">
          <div><span className="section-kicker">Fleet</span><h2>Per-node state</h2></div>
          <span className="live-label">
            <span className={`dot ${data ? 'ok' : 'warn'}`} />
            {data && !error ? `live · 3s poll${data.nodes ? ` · ${data.nodes.length} nodes` : ''}` : 'connecting…'}
          </span>
        </div>
        {error && <div className="form-error">{error}</div>}
        {data ? <NodeTable overview={data} /> : (
          <p className="muted-copy">{loading ? 'Polling fleet…' : 'No data'}</p>
        )}
      </section>

      <section className="card tab-card">
        <div className="section-heading">
          <div><span className="section-kicker">Bridge</span><h2>Recent events</h2></div>
        </div>
        <div className="recent-events">
          {events.map((e, i) => (
            <div className="re-line" key={`${e.ts}-${i}`}>
              <span className="re-kind">{e.kind}</span>
              <span className="re-ts">
                {new Date(e.ts * 1000).toLocaleTimeString([], { hour12: false })}
              </span>
              <span>{e.msg}</span>
            </div>
          ))}
          {!events.length && <p className="muted-copy">waiting for events…</p>}
        </div>
      </section>
    </>
  );
}
