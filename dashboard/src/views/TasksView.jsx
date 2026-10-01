import { useState } from 'react';
import { ListChecks } from 'lucide-react';
import { apiGet, apiError } from '../api.js';

const Json = ({ data }) => (
  <pre className="json-block">{JSON.stringify(data, null, 2)}</pre>
);

// Task queue + scheduler: TASK.STATS / TASK.QUEUE / TASK.WORKERS /
// SCHEDULE.LIST — relayed verbatim; typed errors render as errors.
export default function TasksView() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  const load = async () => {
    const { status, body } = await apiGet('/tasks');
    if (status !== 200) { setError(`HTTP ${status}`); return; }
    setError('');
    setData(body);
  };

  return (
    <section className="card tab-card">
      <div className="section-heading">
        <div><span className="section-kicker">Ops</span><h2>Tasks & scheduler</h2></div>
        <ListChecks size={19} />
      </div>
      <button className="primary-btn" onClick={load}>Load task state</button>
      {error && <div className="form-error">{error}</div>}
      {data && (
        <>
          {data.stats_error
            ? <div className="form-error">{apiError({ error: data.stats_error }) || JSON.stringify(data.stats_error)}</div>
            : <div className="kv-grid wide">
                {Array.isArray(data.stats)
                  ? data.stats.map(([k, v], i) => (
                      <div key={i}><dt>{String(k)}</dt><dd>{String(v)}</dd></div>
                    ))
                  : Object.entries(data.stats || {}).map(([k, v]) => (
                      <div key={k}><dt>{k}</dt><dd>{String(v)}</dd></div>
                    ))}
              </div>}
          {data.queue && <h3 className="sub-head">Queue</h3>}
          {data.queue && <Json data={data.queue} />}
          {data.workers && <h3 className="sub-head">Workers</h3>}
          {data.workers && <Json data={data.workers} />}
          {data.schedule && <h3 className="sub-head">Schedule</h3>}
          {data.schedule && <Json data={data.schedule} />}
        </>
      )}
    </section>
  );
}
