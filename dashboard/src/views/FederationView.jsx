import { useState } from 'react';
import { Globe2 } from 'lucide-react';
import { apiGet, apiError } from '../api.js';

const SECTIONS = [
  ['status', 'STATUS'],
  ['trust', 'Trust plane'],
  ['namespaces', 'Namespaces'],
  ['leases', 'Leases'],
  ['epoch', 'Fencing epoch'],
  ['groups', 'Replication groups'],
  ['conflicts', 'Conflicts'],
  ['rejoin', 'Rejoin'],
  ['repl', 'Anti-entropy (REPL.STATUS)'],
  ['builds', 'Builds'],
  ['supply', 'Supply chain (snapshots / pkg)'],
  ['security', 'Security posture (ifaces)'],
];

function Section({ name, children }) {
  const [open, setOpen] = useState(name === 'status');
  return (
    <section className="card tab-card">
      <div className="section-heading clickable" onClick={() => setOpen(!open)}>
        <div><span className="section-kicker">Federation</span><h2>{name}</h2></div>
        <span className="chev">{open ? '▾' : '▸'}</span>
      </div>
      {open && children}
    </section>
  );
}

function Json({ data }) {
  return <pre className="json-block">{JSON.stringify(data, null, 2)}</pre>;
}

export default function FederationView() {
  const [cache, setCache] = useState({});
  const [errors, setErrors] = useState({});

  const load = async (key) => {
    const { status, body } = await apiGet(`/federation/${key}`);
    setErrors((e) => ({ ...e, [key]: status !== 200 ? `HTTP ${status}` : apiError(body) }));
    setCache((c) => ({ ...c, [key]: body }));
  };

  return (
    <div onLoad={undefined}>
      {SECTIONS.map(([key, label]) => (
        <Section key={key} name={label}>
          <button className="ghost-btn" onClick={() => load(key)}>Load {label}</button>
          {errors[key] && <div className="form-error">{errors[key]}</div>}
          {cache[key] && (
            key === 'trust'
              ? <table className="data-table">
                  <thead><tr><th>uuid</th><th>hostname</th><th>trust</th>
                      <th>kind</th><th>fingerprint</th><th>sig</th></tr></thead>
                  <tbody>
                    {(cache[key].nodes || []).map((n) => {
                      const s = n.show || [];
                      return (
                        <tr key={n.uuid}>
                          <td><code>{n.uuid?.slice(0, 13)}…</code></td>
                          <td>{s[0]}</td><td>{s[1] ?? n.trust}</td><td>{s[2]}</td>
                          <td><code>{s[6] ? `${s[6].slice(0, 16)}…` : '—'}</code></td>
                          <td>{s[8]}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              : key === 'leases'
              ? <table className="data-table">
                  <thead><tr><th>lease</th><th>state</th><th>epoch</th><th>expires</th></tr></thead>
                  <tbody>
                    {(cache[key].leases || []).map((l) => {
                      const r = l.read || [];
                      return (
                        <tr key={l.key}>
                          <td><code>{l.lease_id}</code></td>
                          <td>{r[1]}</td><td>{r[3]}</td><td>{r[4]}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              : key === 'repl'
              ? <pre className="json-block">{(cache[key].repl || '') + ''}</pre>
              : <Json data={cache[key]} />
          )}
        </Section>
      ))}
    </div>
  );
}
