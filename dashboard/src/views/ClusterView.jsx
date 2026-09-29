import { useState } from 'react';
import { Server } from 'lucide-react';
import { apiGet, apiError } from '../api.js';
import { keyslot, ownerForSlot } from '../slots.js';
import { usePoll } from './FleetView.jsx';

// Cluster topology: CLUSTER NODES rendered for display; the bridge never
// dials discovered addresses (rendered truth only).
export default function ClusterView() {
  const { data, error } = usePoll('/cluster', 5000);
  const [probe, setProbe] = useState('');
  const [groups, setGroups] = useState(null);
  const [intros, setIntros] = useState(null);
  const loadIntros = async () => {
    const out = {};
    for (const key of ['qkp', 'bus', 'crl']) {
      const { status, body } = await apiGet(`/introspection/${key}`);
      out[key] = status === 200 ? body : { error: `HTTP ${status}` };
      const err = status === 200 ? apiError(body) : '';
      if (err) out[key] = { error: err };
    }
    setIntros(out);
  };
  const loadGroups = async () => {
    const { status, body } = await apiGet('/cluster/groups');
    if (status === 200) setGroups(body.groups || []);
  };
  const topology = data?.topology || {};
  const owners = data?.owners || {};
  const runs = topology.slots || [];
  const total = runs.reduce((a, r) => a + (r.count || 0), 0) || 1;

  return (
    <>
      <section className="card tab-card">
        <div className="section-heading">
          <div><span className="section-kicker">Cluster</span><h2>Slot ownership</h2></div>
          <Server size={19} />
        </div>
        {error && <div className="form-error">{error}</div>}
        <div className="slot-strip">
          {runs.map((r, i) => (
            <div key={i}
                 className="slot-run"
                 style={{ flexGrow: (r.count / total) * 100 }}
                 title={`${r.start}-${r.end} (${r.count}) → ${r.owner_id} @ ${r.owner_addr}`}>
              <span>{r.count}</span>
            </div>
          ))}
        </div>
        {probe && (() => {
          const slot = keyslot(probe);
          const owner = ownerForSlot(slot, runs);
          return (
            <div className="kv-grid" style={{ marginTop: 18 }}>
              <div><dt>key</dt><dd>{probe}</dd></div>
              <div><dt>slot</dt><dd>{slot}</dd></div>
              <div><dt>owner</dt><dd>{owner ? owner.owner_id.slice(0, 12) + ' @ ' + owner.owner_addr : 'unassigned'}</dd></div>
            </div>
          );
        })()}
        <table className="data-table">
          <thead><tr><th>owner</th><th>slots</th></tr></thead>
          <tbody>
            {Object.entries(owners).map(([addr, count]) => (
              <tr key={addr}><td><code>{addr}</code></td><td>{count}</td></tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card tab-card">
        <div className="section-heading">
          <div><span className="section-kicker">Node introspection</span>
            <h2>QKP · bus · CRL</h2></div>
        </div>
        <button className="ghost-btn" onClick={loadIntros}>Load counters</button>
        {intros && (
          <>
            {['qkp', 'bus', 'crl'].map((k) => (
              <div key={k} style={{ marginTop: 14 }}>
                <span className="section-kicker">{k}</span>
                {intros[k] && !intros[k].error
                  ? <pre className="json-block">{
                      JSON.stringify(intros[k].values ?? intros[k], null, 2)}</pre>
                  : <div className="form-error">{intros[k]?.error || 'unavailable'}</div>}
              </div>
            ))}
          </>
        )}
      </section>

      <section className="card tab-card">
        <div className="section-heading">
          <div><span className="section-kicker">Cluster</span><h2>Group broadcast</h2></div>
        </div>
        <button className="ghost-btn" onClick={loadGroups}>Load groups</button>
        {groups && groups.length > 0 && (
          <table className="data-table">
            <thead><tr><th>group</th><th>status</th></tr></thead>
            <tbody>
              {groups.map((g) => (
                <tr key={g.name}><td><code>{g.name}</code></td>
                  <td><code>{JSON.stringify(g.status)}</code></td></tr>
              ))}
            </tbody>
          </table>
        )}
        {groups && !groups.length && <p className="muted-copy">no groups defined</p>}
      </section>

      <section className="card tab-card">
        <div className="section-heading">
          <div><span className="section-kicker">Cluster</span><h2>Nodes (CLUSTER NODES)</h2></div>
        </div>
        <div className="keys-form" style={{ marginBottom: 14 }}>
          <input value={probe} placeholder="slot calculator — type a key…"
                 onChange={(e) => setProbe(e.target.value)} />
        </div>
        <table className="data-table">
          <thead>
            <tr><th>id</th><th>addr</th><th>flags</th><th>master</th>
                <th>epoch</th><th>link</th><th>slots</th></tr>
          </thead>
          <tbody>
            {(topology.nodes_text || []).map((n) => (
              <tr key={n.id} className={n.myself ? 'row-myself' : ''}>
                <td><code>{n.id?.slice(0, 12)}…</code></td>
                <td><code>{n.addr}</code></td>
                <td>{(n.flags || []).join(',')}</td>
                <td>{n.master ? `${n.master.slice(0, 8)}…` : '—'}</td>
                <td>{n.config_epoch}</td>
                <td>{n.link_state}</td>
                <td>{(n.slots || []).join(' ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
