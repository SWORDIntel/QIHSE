import { useState } from 'react';
import { Database, Search } from 'lucide-react';
import { apiGet, apiError } from '../api.js';

const PREFIXES = ['*', 'fednode:*', 'fedns:*', 'fedlease:*', 'fedconf:*',
                  'fedreplay:*', 'grp:*', 'task:*', 'pub:*', 'sec:*', 't:*'];

// Keyspace browser.  What you see is exactly what the session principal
// is allowed to see — under-cleared keys are absent server-side, not
// hidden client-side.  SCAN is single-shot server-side, so pages are
// client-side with truncation flagged.
export default function KeyspaceView() {
  const [pattern, setPattern] = useState('*');
  const [node, setNode] = useState('');
  const [listing, setListing] = useState(null);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [channels, setChannels] = useState(null);

  const run = async (p = pattern) => {
    const q = `?pattern=${encodeURIComponent(p)}${node ? `&node=${node}` : ''}`;
    const { status, body } = await apiGet(`/keys${q}`);
    if (status !== 200) { setError(`HTTP ${status}`); return; }
    const err = apiError(body);
    setError(err || '');
    setListing(body);
  };

  const loadChannels = async () => {
    const { status, body } = await apiGet('/pubsub');
    if (status === 200) setChannels(body.channels || []);
  };

  const openKey = async (name) => {
    setSelected(name);
    setDetail(null);
    const { status, body } = await apiGet(`/key?name=${encodeURIComponent(name)}`);
    if (status === 200) setDetail(body);
  };

  return (
    <>
      <section className="card tab-card">
        <div className="section-heading">
          <div><span className="section-kicker">Keyspace</span><h2>Browse</h2></div>
          <Database size={19} />
        </div>
        <form className="keys-form" onSubmit={(e) => { e.preventDefault(); run(); }}>
          <input value={pattern} onChange={(e) => setPattern(e.target.value)}
                 placeholder="pattern (e.g. fedns:*)" />
          <input value={node} onChange={(e) => setNode(e.target.value)}
                 placeholder="node # (blank = all)" className="node-input" />
          <button className="primary-btn"><Search size={14} /> Scan</button>
        </form>
        <div className="prefix-chips">
          {PREFIXES.map((p) => (
            <button key={p} className="chip" onClick={() => { setPattern(p); run(p); }}>{p}</button>
          ))}
        </div>
        {error && <div className="form-error">{error}</div>}
        {listing && (
          <>
            {listing.truncated && (
              <div className="form-error">Truncated — refine the pattern</div>
            )}
            <table className="data-table">
              <thead><tr><th>key</th><th>node</th></tr></thead>
              <tbody>
                {(listing.keys || []).map((k) => (
                  <tr key={`${k.node}:${k.key}`}
                      className={selected === k.key ? 'row-selected' : ''}
                      onClick={() => openKey(k.key)}>
                    <td><code>{k.key}</code></td>
                    <td>#{k.node}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </section>

      <section className="card tab-card">
        <div className="section-heading">
          <div><span className="section-kicker">Pub/sub</span><h2>Channels</h2></div>
        </div>
        <button className="ghost-btn" onClick={loadChannels}>List channels</button>
        {channels && (channels.length
          ? <div className="prefix-chips">{channels.map((c) => (
              <span className="chip" key={c}>{c}</span>))}</div>
          : <p className="muted-copy">no active channels</p>)}
      </section>

      {selected && (
        <section className="card tab-card">
          <div className="section-heading">
            <div><span className="section-kicker">Key</span><h2><code>{selected}</code></h2></div>
          </div>
          {!detail && <p className="muted-copy">Loading…</p>}
          {detail && (
            <>
              {apiError(detail) && <div className="form-error">{apiError(detail)}</div>}
              {detail.meta && (
                <div className="kv-grid wide">
                  <div><dt>type</dt><dd>{detail.meta.type || '—'}</dd></div>
                  <div><dt>exists</dt><dd>{String(detail.meta.exists)}</dd></div>
                  <div><dt>ttl</dt><dd>{detail.meta.ttl ?? '—'}</dd></div>
                  <div><dt>size</dt><dd>{detail.meta.size ?? '—'}</dd></div>
                  <div><dt>owner node</dt><dd>#{detail.node}</dd></div>
                </div>
              )}
              {detail.preview_kind === 'text' && (
                <pre className="json-block">{detail.preview}</pre>
              )}
              {Array.isArray(detail.preview) && (
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
