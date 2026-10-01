import { useState } from 'react';
import { Cpu } from 'lucide-react';
import { apiGet, apiError } from '../api.js';

// FABRIC.CAPS — the compute fabric's per-node capability map (NODE_CAP
// durable records).  The raw reply is relayed verbatim beneath the table.
export default function FabricView() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  const load = async () => {
    const { status, body } = await apiGet('/fabric');
    if (status !== 200) { setError(`HTTP ${status}`); return; }
    setError(apiError(body) || '');
    setData(body);
  };

  const rows = Array.isArray(data?.caps)
    ? data.caps.filter((c) => Array.isArray(c))
    : [];

  return (
    <section className="card tab-card">
      <div className="section-heading">
        <div><span className="section-kicker">Compute fabric</span><h2>Node capabilities</h2></div>
        <Cpu size={19} />
      </div>
      <button className="primary-btn" onClick={load}>Load capabilities</button>
      {error && <div className="form-error">{error}</div>}
      {rows.length > 0 && (
        <table className="data-table">
          <thead><tr><th>node</th><th>isa</th><th>npu</th><th>gpu</th>
              <th>ram</th><th>load</th><th>trust</th><th>source</th></tr></thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                {r.slice(0, 8).map((cell, j) => (
                  <td key={j} style={j === 0 ? { whiteSpace: 'nowrap' } : undefined}>
                    {String(cell)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && !rows.length && (
        <pre className="json-block">{JSON.stringify(data.caps, null, 2)}</pre>
      )}
    </section>
  );
}
