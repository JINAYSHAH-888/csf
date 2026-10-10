import { useEffect, useState } from 'react'
import { api } from '../api'
import { PageHeader, Card, Badge, Icon } from '../components/ui'

function decode(part) {
  try {
    const s = part.replace(/-/g, '+').replace(/_/g, '/')
    return JSON.stringify(JSON.parse(atob(s + '='.repeat((4 - (s.length % 4)) % 4))), null, 2)
  } catch { return '(not decodable)' }
}

export default function JwtLab({ refreshStatus }) {
  const [info, setInfo] = useState(null)
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState(null)

  useEffect(() => { api.tokens().then(setInfo).catch(() => {}) }, [])

  async function test(t) {
    const sent = await api.send({ method: 'GET', path: '/admin', token: t.token })
    setResults((r) => ({ ...r, [t.id]: sent }))
    refreshStatus()
  }
  async function all() {
    setBusy(true)
    for (const t of info.tokens) { await test(t); await new Promise((r) => setTimeout(r, 200)) }
    setBusy(false)
  }

  const done = info ? info.tokens.filter((t) => results[t.id]) : []
  const correct = done.filter((t) => (results[t.id].status === 200) === (t.expect === 'allow')).length

  return (
    <div className="page">
      <PageHeader title="Token verification"
        actions={<button className="btn primary" disabled={!info || busy} onClick={all}>
          <Icon name="play" size={15} /> {busy ? 'Running' : 'Test all tokens'}</button>}>
        RFC 8725 JWT verification on <code>/admin</code>: RS256 and ES256 (ECDSA P-256) signatures, issuer, audience and expiry.
      </PageHeader>

      {done.length > 0 && (
        <div className={'alert ' + (correct === done.length ? 'good' : 'warn')}>
          {correct} of {done.length} tokens were handled correctly.
        </div>
      )}

      <Card>
        <table className="table jwt-table">
          <thead>
            <tr><th>Token</th><th>Alg</th><th>What it tries</th><th>Expected</th><th>Result</th><th></th></tr>
          </thead>
          <tbody>
            {info?.tokens.map((t) => {
              const r = results[t.id]
              const ok = r && (r.status === 200) === (t.expect === 'allow')
              const [h, p] = t.token.split('.')
              return [
                <tr key={t.id}>
                  <td><b>{t.label}</b><div className="muted">{t.note}</div></td>
                  <td><code>{t.alg}</code></td>
                  <td>{t.attack === 'none' ? <span className="muted">Legitimate request</span> : t.attack}</td>
                  <td><Badge tone={t.expect === 'allow' ? 'good' : 'bad'}>{t.expect === 'allow' ? 'Accept' : 'Reject'}</Badge></td>
                  <td>
                    {r ? (
                      <div>
                        <Badge tone={r.status === 200 ? 'good' : 'bad'}>{r.status === 200 ? 'Accepted' : 'Rejected'} · {r.status}</Badge>
                        {r.status !== 200 && <div className="muted">{(r.event?.reason || '').replaceAll('_', ' ')}</div>}
                        {!ok && <div className="muted bad-t">Unexpected</div>}
                      </div>
                    ) : <span className="muted">Not tested</span>}
                  </td>
                  <td className="actions">
                    <button className="btn sm" onClick={() => test(t)}>Test</button>
                    <button className="btn sm ghost" onClick={() => setOpen(open === t.id ? null : t.id)}>{open === t.id ? 'Hide' : 'Inspect'}</button>
                  </td>
                </tr>,
                open === t.id && (
                  <tr key={t.id + 'x'} className="inspect">
                    <td colSpan={6}>
                      <div className="grid g2">
                        <div><div className="mini-title">Header</div><pre>{decode(h)}</pre></div>
                        <div><div className="mini-title">Payload</div><pre>{decode(p)}</pre></div>
                      </div>
                    </td>
                  </tr>
                ),
              ]
            })}
          </tbody>
        </table>
      </Card>
    </div>
  )
}
