import { useEffect, useState } from 'react'
import { api } from '../api'
import { Badge, Card } from './ui'

// Controls for the gateway's per-client token-bucket rate limiter.
export default function RateLimit({ status, refreshStatus }) {
  const cfg = status?.rate_limit_config
  const stats = status?.rate_limit
  const enforce = status?.mode === 'enforce'
  const [rate, setRate] = useState('1')
  const [burst, setBurst] = useState('3')
  const [err, setErr] = useState('')
  const [dirty, setDirty] = useState(false)

  // Show the live values until the user starts editing.
  useEffect(() => {
    if (cfg && !dirty) { setRate(String(cfg.rate_per_second)); setBurst(String(cfg.burst)) }
  }, [cfg, dirty])

  async function save(patch) {
    setErr('')
    try {
      await api.setRateLimit({ rate_per_second: Number(rate), burst: Number(burst), ...patch })
      setDirty(false)
      refreshStatus?.()
    } catch {
      setErr('Rate must be above 0 and burst at least 1.')
    }
  }

  const on = !!cfg?.enabled
  return (
    <Card title="Rate limiting"
      hint="Per-client token bucket, checked before any inspection. Each request costs one token."
      right={<Badge tone={on ? 'good' : 'neutral'} dot>{on ? 'Enabled' : 'Disabled'}</Badge>}>
      <div className="rl">
        <div className="rl-toggle">
          <button className={'switch' + (on ? ' on' : '')} role="switch" aria-checked={on}
            onClick={() => save({ enabled: !on })} disabled={!cfg}>
            <i />
          </button>
          <div>
            <b>{on ? 'Rate limiter on' : 'Rate limiter off'}</b>
            <div className="muted">
              {on ? (enforce ? 'Excess requests get HTTP 429.' : 'Shadow/Monitor: excess requests are logged, not rejected.')
                : 'Off by default so real users are never limited by surprise.'}
            </div>
          </div>
        </div>

        <div className="rl-fields">
          <label>
            <span>Sustained rate (requests per second)</span>
            <input type="number" min="0.1" step="0.5" value={rate}
              onChange={(e) => { setRate(e.target.value); setDirty(true) }} />
          </label>
          <label>
            <span>Burst allowance (requests)</span>
            <input type="number" min="1" step="1" value={burst}
              onChange={(e) => { setBurst(e.target.value); setDirty(true) }} />
          </label>
          <button className="btn primary" disabled={!dirty || !cfg} onClick={() => save({})}>Apply</button>
        </div>

        <div className="rl-stats">
          <div><b>{stats?.limited ?? 0}</b><span>limited</span></div>
          <div><b>{stats?.allowed ?? 0}</b><span>within limit</span></div>
          <div><b>{stats?.tracked_principals ?? 0}</b><span>clients tracked</span></div>
        </div>
      </div>
      {err && <div className="alert bad" style={{ marginTop: 10 }}>{err}</div>}
      <p className="note">
        To see it work: turn the limiter on, start the traffic generator (about 2 requests per second), and
        keep the rate at 1 per second. The suite and token tests send requests quickly, so switch the limiter off
        before running them.
      </p>
    </Card>
  )
}
