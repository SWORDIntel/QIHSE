import { useEffect, useState } from 'react';
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
