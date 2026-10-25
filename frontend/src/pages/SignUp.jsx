import { useState } from 'react'
import { api } from '../api'
import { PageHeader, Card, Icon } from '../components/ui'

export default function SignUp({ go, onAuth }) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')

    if (!name.trim()) {
      setError('Please provide your name.')
      return
    }
    if (!email.trim()) {
      setError('Please provide your email address.')
      return
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters long.')
      return
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.')
      return
    }

    setBusy(true)
    try {
      const res = await api.signup({
        name: name.trim(),
        email: email.trim(),
        password,
        confirm_password: confirmPassword,
      })
      if (onAuth) onAuth(res.user)
      go('dashboard')
    } catch (err) {
      setError(err.message || 'Registration failed. Please try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="page" style={{ maxWidth: 460, margin: '40px auto' }}>
      <PageHeader title="Create an account">
        Sign up to create your user profile and establish a secure session.
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
              Full name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Alice Smith"
              autoComplete="name"
              required
              disabled={busy}
              style={{ padding: '10px 12px', fontSize: 14 }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label style={{ fontSize: 13, fontWeight: 500, color: 'var(--muted)' }}>
              Email address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="alice@example.com"
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
              placeholder="At least 8 characters"
              autoComplete="new-password"
              required
              disabled={busy}
              style={{ padding: '10px 12px', fontSize: 14 }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label style={{ fontSize: 13, fontWeight: 500, color: 'var(--muted)' }}>
              Confirm password
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Repeat password"
              autoComplete="new-password"
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
            {busy ? 'Creating account...' : 'Create account'}
          </button>
        </form>

        <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)', textAlign: 'center', fontSize: 13, color: 'var(--muted)' }}>
          Already have an account?{' '}
          <button
            type="button"
            className="btn ghost sm"
            onClick={() => go('login')}
            style={{ padding: '2px 6px', fontWeight: 600 }}
          >
            Sign in
          </button>
        </div>
      </Card>
    </div>
  )
}
