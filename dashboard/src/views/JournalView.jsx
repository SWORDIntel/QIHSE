import { useState } from 'react';
import { ChevronLeft, ChevronRight, ScrollText } from 'lucide-react';
import { apiGet, apiError } from '../api.js';

// Federation journal (F2): FEDERATION.EVENT.REPLAY pager.  Brain
// envelopes (QHBO/QHBD) are annotated magic-only — the badge says
// "signed flag set (unverified)" because ML-DSA verification lives in
// the C helpers, not the browser.
export default function JournalView() {
  const [cursor, setCursor] = useState('0');
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = async (c) => {
    setBusy(true);
    const { status, body } = await apiGet(`/journal?cursor=${c}&count=20`);
    setBusy(false);
    if (status !== 200) { setError(`HTTP ${status}`); return; }
    const err = apiError(body);
    if (err) { setError(err); return; }
    setError('');
    setData(body);
  };

  const entries = data?.entries || [];
  const nextCursor = entries.length
    ? String((parseInt(cursor, 10) || 0) + entries.length) : cursor;

  return (
    <section className="card tab-card">
      <div className="section-heading">
        <div><span className="section-kicker">Journal</span>
          <h2>Federation events {data ? `(length ${data.length})` : ''}</h2></div>
        <ScrollText size={19} />
      </div>
      <div className="pager">
        <button className="ghost-btn" onClick={() => { setCursor('0'); load('0'); }} disabled={busy}>
          First page
        </button>
        <span>cursor {cursor}</span>
        <button className="ghost-btn" onClick={() => { const n = nextCursor; setCursor(n); load(n); }} disabled={busy || !entries.length}>
          <ChevronRight size={14} /> Next
        </button>
      </div>
      {!data && <button className="primary-btn" onClick={() => load(cursor)}>Load journal</button>}
      {error && <div className="form-error">{error}</div>}
      {entries.map((e, i) => {
        const brain = e && e._brain;
        const text = JSON.stringify(e);
        return (
          <details key={i} className="journal-entry">
            <summary>
              <span className="entry-idx">#{(parseInt(cursor, 10) || 0) + i}</span>
              <span className="entry-type">{Array.isArray(e) ? e[0] : (e?.type || e?.event_type || 'event')}</span>
              {brain && <span className="badge-unverified">brain {brain.magic} · signed flag set (unverified)</span>}
            </summary>
            <pre className="json-block">{text}</pre>
          </details>
        );
      })}
      <ChevronLeft size={0} />
    </section>
  );
}
