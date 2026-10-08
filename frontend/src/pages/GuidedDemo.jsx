import { useEffect, useState } from 'react'
import { api } from '../api'
import { PageHeader, Card, Badge, Icon } from '../components/ui'

const STEPS = [
  { id: 'benign', title: 'A normal customer search', expect: 'allow', req: { method: 'GET', path: '/search', query: 'q=blue+running+shoes' },
    why: 'Legitimate traffic must pass untouched. A firewall that blocks real users is useless.' },
  { id: 'sqli', title: 'SQL injection', expect: 'block', req: { method: 'GET', path: '/search', query: "q=x' UNION SELECT username,password FROM users--" },
    why: 'The classic attack: steal the user table by appending a second query.' },
  { id: 'sqli2', title: 'Disguised SQL injection', expect: 'block', req: { method: 'GET', path: '/search', query: "q=1'/**/UnIoN/**/SeLeCt/**/password/**/FROM/**/users--" },
    why: 'Mixed case and inline comments defeat simple pattern matching. CSF parses the SQL instead.' },
  { id: 'xss', title: 'Cross-site scripting', expect: 'block', req: { method: 'GET', path: '/search', query: 'q=<script>alert(document.cookie)</script>' },
    why: 'Injects JavaScript that would run in other users’ browsers to steal sessions.' },
  { id: 'cmd', title: 'Command injection', expect: 'block', req: { method: 'GET', path: '/search', query: 'q=shoes; cat /etc/passwd' },
    why: 'Tries to make the server run an operating-system command.' },
  { id: 'jwt-bad', title: 'Forged login token (alg: none)', expect: 'block', token: 'alg_none', req: { method: 'GET', path: '/admin', query: '' },
    why: 'Claims no signature is needed. Many systems have been breached this way.' },
  { id: 'jwt-ok', title: 'Genuine login token', expect: 'allow', token: 'valid', req: { method: 'GET', path: '/admin', query: '' },
    why: 'A correctly signed token for the admin page is accepted.' },
]

export default function GuidedDemo({ refreshStatus }) {
  const [tokens, setTokens] = useState({})
  const [out, setOut] = useState({})
  const [running, setRunning] = useState(false)
  useEffect(() => {
    api.tokens().then((t) => setTokens(Object.fromEntries(t.tokens.map((x) => [x.id, x.token])))).catch(() => {})
  }, [])

  async function run(step) {
    setOut((o) => ({ ...o, [step.id]: { busy: true } }))
    const sent = await api.send({ ...step.req, token: step.token ? tokens[step.token] : undefined })
    const blocked = sent.status >= 400
    setOut((o) => ({ ...o, [step.id]: { sent, ok: blocked === (step.expect === 'block') } }))
    refreshStatus()
  }
  async function runAll() {
    setRunning(true)
    setOut({})
    for (const s of STEPS) { await run(s); await new Promise((r) => setTimeout(r, 350)) }
    setRunning(false)
  }

  const done = STEPS.filter((s) => out[s.id]?.sent)
  const correct = done.filter((s) => out[s.id].ok).length

  return (
    <div className="page">
      <PageHeader title="Guided demo"
        actions={<button className="btn primary" disabled={running || !Object.keys(tokens).length} onClick={runAll}>
          <Icon name="play" size={15} /> {running ? 'Running…' : 'Run all steps'}</button>}>
        Seven requests that tell the whole story. Run them all, or one at a time. Set the mode to
        <b> Enforce</b> (top right) to see attacks blocked.
      </PageHeader>

      {done.length > 0 && (
        <div className={'alert ' + (correct === done.length ? 'good' : 'warn')}>
          {correct} of {done.length} requests were handled as expected.
        </div>
      )}

      <div className="steps">
        {STEPS.map((s, i) => {
          const o = out[s.id]
          const ev = o?.sent?.event
          return (
            <Card key={s.id} className="step">
              <div className="step-n">{i + 1}</div>
              <div className="step-main">
                <div className="step-title">{s.title}
                  <Badge tone={s.expect === 'allow' ? 'good' : 'bad'}>Expected: {s.expect === 'allow' ? 'allow' : 'block'}</Badge>
                </div>
                <p>{s.why}</p>
                <code className="req">{s.req.method} {s.req.path}{s.req.query ? '?' + s.req.query : ''}</code>
                {o?.sent && (
                  <div className={'step-result ' + (o.sent.status >= 400 ? 'bad' : 'good')}>
                    <b>{o.sent.status >= 400 ? `Blocked (HTTP ${o.sent.status})` : `Allowed (HTTP ${o.sent.status})`}</b>
                    {ev?.decision === 'block' && ev.stage && <> by {ev.stage.replace('_', ' ')}</>}
                    {ev?.reason && <div className="step-reason">{ev.reason.split(':')[0].replaceAll('_', ' ')}</div>}
                    {!o.ok && <div className="step-reason">Not what was expected. Check the gateway mode.</div>}
                  </div>
                )}
              </div>
              <button className="btn" disabled={o?.busy || !Object.keys(tokens).length} onClick={() => run(s)}>Run</button>
            </Card>
          )
        })}
      </div>
    </div>
  )
}
