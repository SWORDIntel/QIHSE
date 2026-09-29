import { useEffect, useState } from 'react';
import { Loader2, ShieldAlert, KeyRound, Usb } from 'lucide-react';
import { apiGet, apiPost, apiError } from '../api.js';
import { getAssertion, createAttestation } from '../webauthn.js';

// Guarded actions: allowlist only, exact-command dialog, per-action
// YubiKey touch bound to the command bytes, single-use dispatch token.
// No passwords anywhere — the only credential is the key in the slot.
export default function ActionsView({ me, csrf }) {
  const [schema, setSchema] = useState([]);
  const [armed, setArmed] = useState(false);
  const [action, setAction] = useState(null);
  const [args, setArgs] = useState({});
  const [stage, setStage] = useState('form');   // form | confirm | dispatching
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [token, setToken] = useState(null);
  const [command, setCommand] = useState('');
  const [enrollMsg, setEnrollMsg] = useState('');

  useEffect(() => {
    apiGet('/actions').then(({ status, body }) => {
      if (status === 200) setSchema(body.actions || []);
    });
  }, []);

  const enrollKey = async () => {
    setEnrollMsg('Touch the key now (PIN if asked)…');
    setError('');
    try {
      const begin = await apiPost('/webauthn/begin', { purpose: 'enroll' }, csrf);
      if (begin.status !== 200) {
        setError(`${begin.body.error_class || 'ERROR'}: ${begin.body.message || ''}`);
        setEnrollMsg('');
        return;
      }
      const credential = await createAttestation(begin.body);
      const done = await apiPost('/webauthn/complete',
        { purpose: 'enroll', credential }, csrf);
      if (done.status === 200 && done.body.ok) {
        setEnrollMsg(`Enrolled (${done.body.credential_id.slice(0, 12)}…). ` +
                     'The key now gates guarded actions.');
      } else {
        setError(`${done.body.error_class || 'REFUSED'}: ${done.body.message || ''}`);
        setEnrollMsg('');
      }
    } catch (err) {
      setError(`ceremony failed: ${err?.message || err}`);
      setEnrollMsg('');
    }
  };

  const pick = (a) => {
    setAction(a);
    setArgs({});
    setStage('form');
    setResult(null);
    setError('');
  };

  const beginConfirm = async () => {
    setError('');
    const { status, body } = await apiPost('/webauthn/begin',
      { purpose: 'action', action: action.name, args }, csrf);
    if (status !== 200) {
      setError(`${body.error_class || 'ERROR'}: ${body.message || ''}`);
      return;
    }
    setCommand(body.bound_command || '');
    setStage('confirm');
    try {
      const credential = await getAssertion(body);   // touch + PIN now
      const done = await apiPost('/webauthn/complete',
        { purpose: 'action', command: body.bound_command, credential }, csrf);
      if (done.status === 200 && done.body.ok) {
        setToken(done.body.dispatch_token);
        setError('');
      } else {
        setError(`${done.body.error_class || 'REFUSED'}: ${done.body.message || ''}`);
        setStage('form');
      }
    } catch (err) {
      setError(`ceremony failed: ${err?.message || err}`);
      setStage('form');
    }
  };

  const dispatch = async () => {
    setStage('dispatching');
    const { status, body } = await apiPost('/action',
      { action: action.name, args, dispatch_token: token }, csrf);
    setStage('form');
    if (status !== 200) {
      setError(`HTTP ${status}: ${body.error_class || ''} ${body.message || ''}`);
      return;
    }
    setResult(body);
  };

  // Operator-context mode: the bridge is the operator; the touch is the
  // only gate.  Login mode keeps the two-factor session requirement.
  const canAct = me?.mode === 'operator-context' || me?.factor >= 2;
  const needKey = canAct && me && me.enrolled === false;

  return (
    <section className="card tab-card">
      <div className="section-heading">
        <div><span className="section-kicker">Ops</span><h2>Guarded actions</h2></div>
        <ShieldAlert size={19} />
      </div>
      {!canAct && (
        <div className="form-error">
          Session is single-factor — guarded actions require a two-factor
          session (WebAuthn).
        </div>
      )}
      {needKey && (
        <div className="confirm-box">
          <p>No FIDO key enrolled</p>
          <p className="muted-copy">
            Put your YubiKey in the slot and enroll it — it becomes the only
            credential this UI ever asks for.
          </p>
          <button className="primary-btn" onClick={enrollKey}>
            <Usb size={14} /> Enroll the key in the slot
          </button>
          {enrollMsg && <p className="touch-prompt">{enrollMsg}</p>}
        </div>
      )}
      <label className="arm-row">
        <input type="checkbox" checked={armed}
               onChange={(e) => setArmed(e.target.checked)} disabled={!canAct} />
        <span>Arm (enable action dispatch)</span>
      </label>
      <div className="prefix-chips">
        {schema.map((a) => (
          <button key={a.name} className="chip"
                  disabled={!armed || !canAct}
                  data-active={action?.name === a.name}
                  onClick={() => pick(a)}>{a.title}</button>
        ))}
      </div>
      {action && armed && canAct && (
        <div className="action-form">
          {action.args.map((arg) => (
            <label key={arg.name} className="field">
              <span>{arg.name}{arg.type === 'enum' ? ` (${arg.values.join('|')})` : ''}</span>
              <input value={args[arg.name] ?? ''}
                     onChange={(e) => setArgs((a) => ({
                       ...a,
                       [arg.name]: arg.type === 'int' ? Number(e.target.value) : e.target.value,
                     }))} />
            </label>
          ))}
          {stage === 'form' && (
            <button className="primary-btn" onClick={beginConfirm}>
              <KeyRound size={14} /> Prepare (touch to bind)
            </button>
          )}
          {stage === 'confirm' && !token && <p className="touch-prompt">Waiting for YubiKey touch…</p>}
          {stage === 'confirm' && token && command && (
            <div className="confirm-box">
              <p>Touch-bound to exactly</p>
              <code className="command-code">{command}</code>
              <button className="primary-btn danger" onClick={dispatch} disabled={stage === 'dispatching'}>
                {stage === 'dispatching' ? <Loader2 size={14} className="spin" /> : 'DISPATCH'}
              </button>
            </div>
          )}
        </div>
      )}
      {error && <div className="form-error">{error}</div>}
      {result && (
        <div className={result.ok ? 'result-ok' : 'result-bad'}>
          <strong>{result.ok ? 'OK' : 'REFUSED'}</strong>
          {' '}{result.ok ? result.reply : `${result.error?.error_class}: ${result.error?.message}`}
        </div>
      )}
    </section>
  );
}
