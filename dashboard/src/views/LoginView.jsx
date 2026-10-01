import { useState } from 'react';
import { KeyRound, Loader2, ShieldCheck } from 'lucide-react';
import { apiPost } from '../api.js';
import { getAssertion } from '../webauthn.js';

// Two-factor login: QIHSE password (knowledge, one PBKDF2 exchange on
// the server — expect seconds) + YubiKey touch with PIN (possession).
export default function LoginView({ onLoggedIn }) {
  const [username, setUsername] = useState('GODMODE_OP');
  const [password, setPassword] = useState('');
  const [phase, setPhase] = useState('password'); // password | touch | done
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [csrf, setCsrf] = useState('');

  const submitPassword = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    const { status, body } = await apiPost('/login/password', { username, password });
    setBusy(false);
    if (status === 401 || status === 403 || status === 429 || status === 503) {
      setError(`${body.error_class || 'REFUSED'}: ${body.message || ''}`);
      return;
    }
    if (status !== 200) {
      setError(`login failed (HTTP ${status})`);
      return;
    }
    setCsrf(body.csrf || '');
    if (body.status === 'webauthn_required') {
      setPhase('touch');
      runCeremony();
    } else {
      onLoggedIn();
    }
  };

  const runCeremony = async () => {
    setError('');
    setBusy(true);
    try {
      const begin = await apiPost('/webauthn/begin', { purpose: 'login' }, csrf);
      if (begin.status !== 200) {
        setError(`${begin.body.error_class || 'ERROR'}: ${begin.body.message || ''}`);
        setBusy(false);
        return;
      }
      const credential = await getAssertion(begin.body);
      const done = await apiPost('/webauthn/complete',
        { purpose: 'login', credential }, csrf);
      setBusy(false);
      if (done.status === 200 && done.body.ok) {
        setPhase('done');
        onLoggedIn();
      } else {
        setError(`${done.body.error_class || 'REFUSED'}: ${done.body.message || ''}`);
        setPhase('password');
      }
    } catch (err) {
      setBusy(false);
      setPhase('password');
      setError(`ceremony failed: ${err?.message || err} (touch the key when prompted)`);
    }
  };

  return (
    <div className="login-wrap">
      <form className="card login-card" onSubmit={submitPassword}>
        <div className="section-heading">
          <div>
            <span className="section-kicker">Operator access</span>
            <h2>QIHSE Browser</h2>
          </div>
          {phase === 'touch' ? <KeyRound size={20} /> : <ShieldCheck size={20} />}
        </div>
        {phase === 'password' && (
          <>
            <label className="field">
              <span>Principal</span>
              <input value={username} onChange={(e) => setUsername(e.target.value)}
                     autoComplete="username" required />
            </label>
            <label className="field">
              <span>Password</span>
              <input type="password" value={password}
                     onChange={(e) => setPassword(e.target.value)}
                     autoComplete="current-password" required />
            </label>
            <button className="primary-btn" disabled={busy}>
              {busy ? <Loader2 size={16} className="spin" /> : 'Sign in'}
            </button>
            <p className="muted-copy">
              AUTH runs the server-side CNSA 2.0 KDF — signing in takes a few
              seconds. Two-factor (YubiKey touch + PIN) follows when a
              credential is enrolled.
            </p>
          </>
        )}
        {phase === 'touch' && (
          <p className="touch-prompt">
            {busy ? 'Waiting for your YubiKey — touch it now (PIN if asked)…'
                  : 'Ceremony paused. '}
          </p>
        )}
        {error && <div className="form-error">{error}</div>}
      </form>
    </div>
  );
}
