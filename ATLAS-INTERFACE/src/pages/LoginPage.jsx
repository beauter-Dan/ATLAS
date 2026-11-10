import { useState } from 'react';
import Field from '../components/Field.jsx';
import { useAuth } from '../auth/AuthContext.jsx';
import { describeAuthError } from '../utils/errors.js';

export default function LoginPage() {
  const { login, notice } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [needsCode, setNeedsCode] = useState(false);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      await login({ username: username.trim(), password, totpCode: needsCode ? totpCode.trim() : undefined });
    } catch (err) {
      if (err.code === 'mfa_required') setNeedsCode(true);
      else setPassword('');                       // never keep a rejected password in the form
      setError(err);
      setBusy(false);
    }
  }

  const mfaPrompt = error?.code === 'mfa_required';
  return (
    <main className="login">
      <form className="panel login__card" onSubmit={submit} noValidate aria-labelledby="login-title">
        <div className="brand"><span className="brand__mark" aria-hidden="true" /><span className="brand__name">ATLAS</span></div>
        <h1 id="login-title" className="login__title">Sign in</h1>
        {notice && !error && <div className="notice notice--warn" role="status">{notice}</div>}
        {error && (
          <div className={`notice ${mfaPrompt ? '' : 'notice--warn'}`} role="alert">{describeAuthError(error)}</div>
        )}
        <Field label="Username">{(p) => <input className="input" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} {...p} />}</Field>
        <Field label="Password">{(p) => <input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} {...p} />}</Field>
        {needsCode && (
          <Field label="One-time code" hint="From your authenticator app.">
            {(p) => <input className="input" inputMode="numeric" autoComplete="one-time-code" maxLength={6} autoFocus value={totpCode} onChange={(e) => setTotpCode(e.target.value)} {...p} />}
          </Field>
        )}
        <button className="btn btn--primary login__submit" type="submit" disabled={busy || !username || !password || (needsCode && totpCode.length !== 6)}>
          {busy ? 'Signing in' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}
