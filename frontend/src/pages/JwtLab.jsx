import { useEffect, useState } from 'react'
import { api } from '../api'

function decode(part) {
  try {
    const s = part.replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(atob(s + '='.repeat((4 - (s.length % 4)) % 4)))
  } catch { return null }
}

export default function JwtLab({ refreshStatus }) {
  const [info, setInfo] = useState(null)
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  useEffect(() => { api.tokens().then(setInfo).catch(() => {}) }, [])

  async function test(t) {
    const sent = await api.send({ method: 'GET', path: '/admin', token: t.token })
    setResults((r) => ({ ...r, [t.id]: sent }))
    refreshStatus()
  }
  async function all() {
    setBusy(true)
    for (const t of info.tokens) await test(t)
    setBusy(false)
  }

  const done = info ? info.tokens.filter((t) => results[t.id]) : []
  const correct = done.filter((t) => (results[t.id].status === 200) === (t.expect === 'allow')).length

  return (
    <div className="page">
      <h1>JWT Lab</h1>
      <p className="lead">
        Each button sends <code>GET /admin</code> with a different token. The gateway verifies signatures cryptographically
        (RFC 8725) — only the genuinely valid RS256 token may pass. {info && <>Issuer <code>{info.issuer}</code>, audience <code>{info.audience}</code>.</>}
      </p>
      <div className="toolbar">
        <button className="primary" disabled={!info || busy} onClick={all}>{busy ? 'Running…' : 'Run all attacks'}</button>
        {done.length > 0 && <span className="score">{correct}/{done.length} handled correctly</span>}
      </div>
      <div className="tokens">
        {info?.tokens.map((t) => {
          const r = results[t.id]
          const [h, p] = t.token.split('.')
          const ok = r && (r.status === 200) === (t.expect === 'allow')
          return (
            <div key={t.id} className={'card tok ' + (r ? (ok ? 'ok' : 'bad') : '')}>
              <div className="tok-head">
                <div>
                  <b>{t.label}</b>
                  <div className="atk">{t.attack === 'none' ? 'legitimate request' : 'attack: ' + t.attack}</div>
                </div>
                <button onClick={() => test(t)}>Send</button>
              </div>
              <p className="hint">{t.note}</p>
              <div className="jwt">
                <span className="j1">{h.slice(0, 18)}…</span>.<span className="j2">{p.slice(0, 18)}…</span>.<span className="j3">sig</span>
              </div>
              <details>
                <summary>decoded</summary>
                <pre>{JSON.stringify(decode(h), null, 1)}{'\n'}{JSON.stringify(decode(p), null, 1)}</pre>
              </details>
              {r && (
                <div className={'res ' + (r.status === 200 ? 'pass' : 'block')}>
                  HTTP {r.status} · {r.status === 200 ? 'admin panel reached' : 'rejected: ' + (r.event?.reason || '')}
                  <span className="exp"> (expected {t.expect})</span>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
