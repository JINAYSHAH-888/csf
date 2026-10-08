import { useEffect, useState } from 'react'
import { api } from '../api'
import { PageHeader, Card, Badge, Icon } from '../components/ui'

const STEPS = [
  { id: 'benign', title: 'Legitimate product search', cls: 'Baseline', expect: 'allow',
    what: 'An ordinary customer searching the catalogue. Included to prove the gateway does not block real users.',
    how: 'Passes every stage; nothing suspicious is found.',
    req: { method: 'GET', path: '/search', query: 'q=blue+running+shoes' } },
  { id: 'sqli', title: 'UNION-based SQL injection', cls: 'SQL injection', expect: 'block',
    what: 'Appends a second SQL query so the database returns the usernames and passwords table.',
    how: 'Signature rules match the UNION SELECT pattern; the semantic stage parses the SQL and confirms an injected UNION.',
    req: { method: 'GET', path: '/search', query: "q=x' UNION SELECT username,password FROM users--" } },
  { id: 'sqli2', title: 'Obfuscated SQL injection', cls: 'SQL injection', expect: 'block',
    what: 'The same attack disguised with mixed case and inline comments so simple pattern matching misses it.',
    how: 'Input is normalised and comment-stripped, then parsed as SQL, so the attack shape is still visible.',
    req: { method: 'GET', path: '/search', query: "q=1'/**/UnIoN/**/SeLeCt/**/password/**/FROM/**/users--" } },
  { id: 'xss', title: 'Reflected script injection', cls: 'Cross-site scripting', expect: 'block',
    what: 'Injects JavaScript that would run in another user’s browser and steal their session cookie.',
    how: 'Detected as an HTML script element in a query parameter.',
    req: { method: 'GET', path: '/search', query: 'q=<script>alert(document.cookie)</script>' } },
  { id: 'cmd', title: 'Shell command chaining', cls: 'Command injection', expect: 'block',
    what: 'Chains an operating-system command after the input to read a sensitive file on the server.',
    how: 'The shell analyser identifies a command separator followed by a file-reading command.',
    req: { method: 'GET', path: '/search', query: 'q=shoes; cat /etc/passwd' } },
  { id: 'jwt-bad', title: 'JWT with alg=none', cls: 'Token forgery', expect: 'block', token: 'alg_none',
    what: 'A login token that claims no signature is required, a classic way to impersonate an administrator.',
    how: 'Rejected at S0: the token’s algorithm is not on the issuer’s allow-list.',
    req: { method: 'GET', path: '/admin', query: '' } },
  { id: 'jwt-ok', title: 'Valid RS256 token', cls: 'Baseline', expect: 'allow', token: 'valid',
    what: 'A correctly signed token with the right issuer, audience and expiry requesting the admin page.',
    how: 'Signature and claims verify; the request is forwarded with a gateway-asserted identity.',
    req: { method: 'GET', path: '/admin', query: '' } },
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
  const pct = (done.length / STEPS.length) * 100

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
          <Badge tone={done.length === 0 ? 'neutral' : done.length < STEPS.length ? 'neutral' : passed === STEPS.length ? 'good' : 'warn'} dot>
            {done.length === 0 ? 'Not run' : done.length < STEPS.length ? 'Running' : passed === STEPS.length ? 'All scenarios passed' : 'Failures detected'}
          </Badge>
        </div>
        <div className="suite-track"><div className="suite-fill" style={{ width: pct + '%' }} /></div>
      </Card>

      <div className="steps">
        {STEPS.map((s, i) => {
          const o = out[s.id]
          const ev = o?.sent?.event
          const blocked = o?.sent && o.sent.status >= 400
          return (
            <Card key={s.id} className={'step' + (o?.sent ? (o.pass ? ' ok' : ' fail') : '')}>
              <div className="step-n">
                {o?.sent ? <Icon name={o.pass ? 'check' : 'x'} size={16} /> : o?.busy ? <span className="spin" /> : i + 1}
              </div>
              <div className="step-main">
                <div className="step-title">
                  {s.title}
                  <Badge tone={s.expect === 'allow' ? 'good' : 'bad'}>Expected: {s.expect === 'allow' ? 'allow' : 'block'}</Badge>
                  <span className="step-cls">{s.cls}</span>
                </div>
                <div className="step-grid">
                  <div><div className="step-k">What it does</div><p>{s.what}</p></div>
                  <div><div className="step-k">How CSF handles it</div><p>{s.how}</p></div>
                </div>
                <code className="req">{s.req.method} {s.req.path}{s.req.query ? '?' + s.req.query : ''}</code>
                {o?.sent && (
                  <div className={'step-result ' + (blocked ? 'bad' : 'good')}>
                    <b>{blocked ? `Blocked · HTTP ${o.sent.status}` : `Allowed · HTTP ${o.sent.status}`}</b>
                    {ev?.decision === 'block' && ev.stage && <span> at {ev.stage.replaceAll('_', ' ')}</span>}
                    {ev?.reason && ev.decision === 'block' && <div className="step-reason">{ev.reason.length > 150 ? ev.reason.slice(0, 150) + '…' : ev.reason.replaceAll('_', ' ')}</div>}
                    {!o.pass && <div className="step-reason">Unexpected result. Check the gateway mode.</div>}
                  </div>
                )}
              </div>
              <button className="btn sm" disabled={!ready || o?.busy} onClick={() => run(s)}>Run</button>
            </Card>
          )
        })}
      </div>
    </div>
  )
}
