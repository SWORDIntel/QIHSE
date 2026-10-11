// Bridge API helpers. Cookie-based session; CSRF header on POSTs
// (token handed out at login / whoami).

export async function apiGet(path, timeoutMs = 30000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`/api${path}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      signal: ctrl.signal,
    });
    const body = await res.json().catch(() => ({}));
    return { status: res.status, body };
  } catch (err) {
    return { status: 0, body: { error_class: 'NETWORK', message: String(err?.message || err) } };
  } finally {
    clearTimeout(timer);
  }
}

export async function apiPost(path, payload, csrf, timeoutMs = 90000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`/api${path}`, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        ...(csrf ? { 'X-QIHSE-CSRF': csrf } : {}),
      },
      body: JSON.stringify(payload ?? {}),
      signal: ctrl.signal,
    });
    const body = await res.json().catch(() => ({}));
    return { status: res.status, body };
  } catch (err) {
    return { status: 0, body: { error_class: 'NETWORK', message: String(err?.message || err) } };
  } finally {
    clearTimeout(timer);
  }
}

// Error rendering: a bridge payload is either data or the server's own
// typed refusal ({error_class, message}) — never fabricated emptiness.
export function apiError(body) {
  if (!body) return 'unknown error';
  if (body.error_class) return `${body.error_class}: ${body.message || ''}`;
  if (body.error && body.error.error_class) {
    return `${body.error.error_class}: ${body.error.message || ''}`;
  }
  return null;
}
