import { useState } from 'react'
import { api } from '../api'
import { PageHeader, Card, Icon } from '../components/ui'

export default function Login({ go, onAuth }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!email.trim() || !password) {
      setError('Please provide both email and password.')
      return
    }

    setBusy(true)
    try {
      const res = await api.login({ email: email.trim(), password })
      if (onAuth) onAuth(res.user)
      go('dashboard')
    } catch (err) {
      setError(err.message || 'Login failed. Please check your credentials.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="page" style={{ maxWidth: 460, margin: '40px auto' }}>
      <PageHeader title="Sign in to your account">
        Enter your credentials to access your session.
      </PageHeader>

      {error && (
        <div className="alert bad" style={{ marginBottom: 16 }}>
          <Icon name="alert" size={16} />
          <span>{error}</span>
        </div>
      )}

      <Card>
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label style={{ fontSize: 13, fontWeight: 500, color: 'var(--muted)' }}>
              Email address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              autoComplete="email"
              required
              disabled={busy}
              style={{ padding: '10px 12px', fontSize: 14 }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label style={{ fontSize: 13, fontWeight: 500, color: 'var(--muted)' }}>
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
              required
              disabled={busy}
              style={{ padding: '10px 12px', fontSize: 14 }}
            />
          </div>

          <button
            type="submit"
            className="btn primary"
            disabled={busy}
            style={{ width: '100%', justifyContent: 'center', padding: '10px 14px', marginTop: 4 }}
          >
            {busy ? 'Signing in...' : 'Sign in'}
          </button>
        </form>

        <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)', textAlign: 'center', fontSize: 13, color: 'var(--muted)' }}>
          Don't have an account?{' '}
          <button
            type="button"
            className="btn ghost sm"
            onClick={() => go('signup')}
            style={{ padding: '2px 6px', fontWeight: 600 }}
          >
            Create an account
          </button>
        </div>
      </Card>
    </div>
  )
}
