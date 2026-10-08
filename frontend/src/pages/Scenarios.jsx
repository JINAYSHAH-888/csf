import { useEffect, useState } from 'react'
import { api } from '../api'
import { PageHeader, Card, Badge, Icon } from '../components/ui'

const STEPS = [
  { id: 'benign', title: 'Legitimate product search', cls: 'Baseline', expect: 'allow', req: { method: 'GET', path: '/search', query: 'q=blue+running+shoes' } },
  { id: 'sqli', title: 'UNION-based SQL injection', cls: 'SQL injection', expect: 'block', req: { method: 'GET', path: '/search', query: "q=x' UNION SELECT username,password FROM users--" } },
  { id: 'sqli2', title: 'Obfuscated SQL injection (case + comments)', cls: 'SQL injection', expect: 'block', req: { method: 'GET', path: '/search', query: "q=1'/**/UnIoN/**/SeLeCt/**/password/**/FROM/**/users--" } },
  { id: 'xss', title: 'Reflected script injection', cls: 'Cross-site scripting', expect: 'block', req: { method: 'GET', path: '/search', query: 'q=<script>alert(document.cookie)</script>' } },
  { id: 'cmd', title: 'Shell command chaining', cls: 'Command injection', expect: 'block', req: { method: 'GET', path: '/search', query: 'q=shoes; cat /etc/passwd' } },
  { id: 'jwt-bad', title: 'JWT with alg=none on /admin', cls: 'Token forgery', expect: 'block', token: 'alg_none', req: { method: 'GET', path: '/admin', query: '' } },
  { id: 'jwt-ok', title: 'Valid RS256 token on /admin', cls: 'Baseline', expect: 'allow', token: 'valid', req: { method: 'GET', path: '/admin', query: '' } },
]

export default function Scenarios({ refreshStatus }) {
  const [tokens, setTokens] = useState({})
  const [out, setOut] = useState({})
  const [running, setRunning] = useState(false)
  useEffect(() => {
    api.tokens().then((t) => setTokens(Object.fromEntries(t.tokens.map((x) => [x.id, x.token])))).catch(() => {})
  }, [])
  const ready = Object.keys(tokens).length > 0

  async function run(step) {
    setOut((o) => ({ ...o, [step.id]: { busy: true } }))
    const sent = await api.send({ ...step.req, token: step.token ? tokens[step.token] : undefined })
    const blocked = sent.status >= 400
    setOut((o) => ({ ...o, [step.id]: { sent, pass: blocked === (step.expect === 'block') } }))
    refreshStatus()
  }
  async function runAll() {
    setRunning(true); setOut({})
    for (const s of STEPS) { await run(s); await new Promise((r) => setTimeout(r, 300)) }
    setRunning(false)
  }

  const done = STEPS.filter((s) => out[s.id]?.sent)
  const passed = done.filter((s) => out[s.id].pass).length
  const pct = done.length ? (passed / STEPS.length) * 100 : 0

  return (
    <div className="page">
      <PageHeader title="Scenario suite"
        actions={<button className="btn primary" disabled={running || !ready} onClick={runAll}>
          <Icon name="play" size={15} /> {running ? 'Running' : 'Run suite'}</button>}>
        Reference attacks and baselines executed against the live gateway.
      </PageHeader>

      <Card className="suite-bar">
        <div className="suite-top">
          <div><b className="suite-num">{passed}</b><span className="suite-of"> / {STEPS.length} passed</span></div>
          <Badge tone={done.length === 0 ? 'neutral' : passed === done.length ? 'good' : 'warn'} dot>
            {done.length === 0 ? 'Not run' : done.length < STEPS.length ? 'Running' : passed === STEPS.length ? 'All scenarios passed' : 'Failures'}
          </Badge>
        </div>
        <div className="suite-track"><div className="suite-fill" style={{ width: pct + '%' }} /></div>
      </Card>

      <Card>
        <table className="table">
          <thead><tr><th style={{ width: 36 }}></th><th>Scenario</th><th>Class</th><th>Expected</th><th>Observed</th><th></th></tr></thead>
          <tbody>
            {STEPS.map((s) => {
              const o = out[s.id]
              const ev = o?.sent?.event
              return (
                <tr key={s.id}>
                  <td>
                    {o?.sent ? <span className={'tick ' + (o.pass ? 'good' : 'bad')}><Icon name={o.pass ? 'check' : 'x'} size={13} /></span>
                      : o?.busy ? <span className="spin" /> : <span className="tick idle" />}
                  </td>
                  <td>
                    <b>{s.title}</b>
                    <div className="mono sub">{s.req.method} {s.req.path}{s.req.query ? '?' + s.req.query.slice(0, 70) : ''}</div>
                  </td>
                  <td className="muted-c">{s.cls}</td>
                  <td><Badge tone={s.expect === 'allow' ? 'good' : 'bad'}>{s.expect === 'allow' ? 'Allow' : 'Block'}</Badge></td>
                  <td>
                    {o?.sent ? (
                      <div>
                        <Badge tone={o.sent.status >= 400 ? 'bad' : 'good'}>{o.sent.status >= 400 ? 'Blocked' : 'Allowed'} · {o.sent.status}</Badge>
                        {ev?.decision === 'block' && <div className="sub">{ev.stage.replace('_', ' ')}</div>}
                      </div>
                    ) : <span className="muted-c">—</span>}
                  </td>
                  <td className="actions"><button className="btn sm" disabled={!ready || o?.busy} onClick={() => run(s)}>Run</button></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </Card>
    </div>
  )
}
