import { useEffect, useRef, useState } from 'react';
import { Terminal } from 'lucide-react';
import { apiGet } from '../api.js';

const KIND_COLOR = {
  startup: 'var(--periwinkle)',
  request: 'var(--ink-dim)',
  auth: 'var(--blue)',
  webauthn: 'var(--cyan)',
  action: 'var(--chartreuse)',
  error: 'var(--coral)',
};

// The bridge log: everything that happens — requests, auth, ceremonies,
// dispatches — tailed live.  Nothing is summarized away.
export default function LogView() {
  const [lines, setLines] = useState([]);
  const [error, setError] = useState('');
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState('');
  const boxRef = useRef(null);

  useEffect(() => {
    if (paused) return undefined;
    let cancelled = false;
    let last = 0;
    const tick = async () => {
      const { status, body } = await apiGet('/log?limit=400', 5000);
      if (cancelled) return;
      if (status !== 200) { setError(`HTTP ${status}`); return; }
      setError('');
      setLines(body.log || []);
    };
    tick();
    const iv = setInterval(tick, 1000);
    return () => { cancelled = true; clearInterval(iv); };
  }, [paused]);

  useEffect(() => {
    if (!paused && boxRef.current) {
      boxRef.current.scrollTop = boxRef.current.scrollHeight;
    }
  }, [lines, paused]);

  const shown = filter
    ? lines.filter((l) => l.msg.toLowerCase().includes(filter.toLowerCase())
                    || l.kind.includes(filter.toLowerCase()))
    : lines;

  return (
    <section className="card tab-card">
      <div className="section-heading">
        <div><span className="section-kicker">Bridge</span><h2>Everything, logged</h2></div>
        <Terminal size={19} />
      </div>
      <div className="log-controls">
        <input className="log-filter" value={filter}
               placeholder="filter…"
               onChange={(e) => setFilter(e.target.value)} />
        <button className="text-btn" onClick={() => setPaused(!paused)}>
          {paused ? 'resume' : 'pause'}
        </button>
        <span className="muted-copy">{shown.length} lines</span>
      </div>
      {error && <div className="form-error">{error}</div>}
      <div className="log-stream" ref={boxRef}>
        {shown.map((l, i) => (
          <div className="log-line" key={`${l.ts}-${i}`}>
            <span className="log-kind" style={{ color: KIND_COLOR[l.kind] || 'var(--ink-dim)' }}>
              {l.kind}
            </span>
            <span className="log-ts">{new Date(l.ts * 1000).toLocaleTimeString([], { hour12: false })}</span>
            <span className="log-msg">{l.msg}</span>
          </div>
        ))}
        {!shown.length && <p className="muted-copy">waiting for events…</p>}
      </div>
    </section>
  );
}
