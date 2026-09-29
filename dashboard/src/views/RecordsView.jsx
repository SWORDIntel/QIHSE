import { useState } from 'react';
import { Archive } from 'lucide-react';
import { apiGet, apiError } from '../api.js';
import { keyslot } from '../slots.js';

// The record browser: a prefix census over EVERYTHING the session's
// principal can see — federation records, groups, tasks, tenant data,
// bare keys — then drill into a family, then into a single record with
// typed preview and a raw hex head for binary envelopes.
export default function RecordsView() {
  const [census, setCensus] = useState(null);
  const [family, setFamily] = useState(null);   // selected prefix
  const [keys, setKeys] = useState(null);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [showHex, setShowHex] = useState(false);
  const [error, setError] = useState('');

  const loadCensus = async () => {
    const { status, body } = await apiGet('/records/census');
    if (status !== 200) { setError(`HTTP ${status}`); return; }
    setError(apiError(body) || '');
    setCensus(body);
  };

  const openFamily = async (prefix) => {
    setFamily(prefix);
    setSelected(null);
    setDetail(null);
    const pattern = prefix === '(bare)' ? '*' : `${prefix}:*`;
    const { status, body } = await apiGet(`/keys?pattern=${encodeURIComponent(pattern)}`);
    if (status === 200) setKeys(body);
  };

  const openKey = async (name) => {
    setSelected(name);
    setDetail(null);
    setShowHex(false);
    const { status, body } = await apiGet(`/key?name=${encodeURIComponent(name)}`);
    if (status === 200) setDetail(body);
  };

  return (
    <>
      <section className="card tab-card">
        <div className="section-heading">
          <div><span className="section-kicker">Records</span>
            <h2>{census ? `All families (${census.total} keys)` : 'Prefix census'}</h2></div>
          <Archive size={19} />
        </div>
        <button className="primary-btn" onClick={loadCensus}>Census the keyspace</button>
        {error && <div className="form-error">{error}</div>}
        {census && census.truncated && (
          <div className="form-error">Census truncated at the fetch cap — counts are lower bounds</div>
        )}
        {census && (
          <table className="data-table">
            <thead><tr><th>family</th><th>records</th><th>per node</th>
                <th>sample</th></tr></thead>
            <tbody>
              {census.families.map((f) => (
                <tr key={f.prefix} className={family === f.prefix ? 'row-selected' : ''}
                    style={{ cursor: 'pointer' }} onClick={() => openFamily(f.prefix)}>
                  <td><code>{f.prefix}:</code></td>
                  <td>{f.count}</td>
                  <td><code>{Object.entries(f.nodes).map(([n, c]) => `#${n}:${c}`).join(' ')}</code></td>
                  <td><code>{f.sample}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {family && (
        <section className="card tab-card">
          <div className="section-heading">
            <div><span className="section-kicker">Family</span>
              <h2><code>{family === '(bare)' ? '(bare keys)' : family + ':'}</code>
                {keys ? ` — ${keys.keys.length} shown` : ''}</h2></div>
          </div>
          {keys && keys.truncated && (
            <div className="form-error">Truncated — many records; refine in Keyspace with a pattern</div>
          )}
          <table className="data-table">
            <thead><tr><th>key</th><th>node</th></tr></thead>
            <tbody>
              {(keys?.keys || []).map((k) => (
                <tr key={`${k.node}:${k.key}`}
                    className={selected === k.key ? 'row-selected' : ''}
                    style={{ cursor: 'pointer' }} onClick={() => openKey(k.key)}>
                  <td><code>{k.key}</code></td>
                  <td>#{k.node}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {selected && (
        <section className="card tab-card">
          <div className="section-heading">
            <div><span className="section-kicker">Record</span>
              <h2><code>{selected}</code></h2></div>
            {detail?.hex && (
              <button className="ghost-btn" onClick={() => setShowHex(!showHex)}>
                {showHex ? 'text view' : 'hex head'}
              </button>
            )}
          </div>
          {!detail && <p className="muted-copy">Loading…</p>}
          {detail && (
            <>
              {apiError(detail) && <div className="form-error">{apiError(detail)}</div>}
              {detail.record_meta && Array.isArray(detail.record_meta)
                && detail.record_meta.length === 4
                && detail.record_meta[0] !== null && (
                <div className="kv-grid wide">
                  <div><dt>classification</dt><dd>{detail.record_meta[0]}</dd></div>
                  <div><dt>sci</dt><dd>0x{Number(detail.record_meta[1]).toString(16)}</dd></div>
                </div>
              )}
              {detail.meta && (
                <div className="kv-grid wide">
                  <div><dt>type</dt><dd>{detail.meta.type || '—'}</dd></div>
                  <div><dt>exists</dt><dd>{String(detail.meta.exists)}</dd></div>
                  <div><dt>ttl</dt><dd>{detail.meta.ttl ?? '—'}</dd></div>
                  <div><dt>size</dt><dd>{detail.meta.size ?? '—'}</dd></div>
                  <div><dt>owner node</dt><dd>#{detail.node}</dd></div>
                  <div><dt>slot</dt><dd>{keyslot(selected)}</dd></div>
                </div>
              )}
              {showHex && detail.hex && (
                <pre className="json-block">{detail.hex.replace(/(..)/g, '$1 ').trim()}</pre>
              )}
              {!showHex && detail.preview_kind === 'text' && (
                <pre className="json-block">{detail.preview}</pre>
              )}
              {!showHex && Array.isArray(detail.preview) && (
                <pre className="json-block">{JSON.stringify(detail.preview, null, 2)}</pre>
              )}
              {detail.truncated && <p className="muted-copy">Preview truncated.</p>}
            </>
          )}
        </section>
      )}
    </>
  );
}
