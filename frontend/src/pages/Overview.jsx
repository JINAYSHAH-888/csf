import { Icon, PageHeader, Card, Stat, Badge } from '../components/ui'

const STEPS = [
  ['1', 'Request arrives', 'Every request to the application passes through the gateway first.'],
  ['2', 'Protocol and identity', 'Malformed HTTP is rejected. JWT tokens are cryptographically verified.'],
  ['3', 'Known patterns', 'Industry rules (OWASP CRS) catch well-known attack strings quickly.'],
  ['4', 'Structure analysis', 'The input is parsed as SQL, HTML or shell to catch disguised attacks.'],
  ['5', 'Decision', 'Results are combined: forward the request, flag it, or block it.'],
]

export default function Overview({ status, go }) {
  const s = status?.stats
  const mode = status?.mode
  const s1 = status?.stages?.find((x) => x.id === 's1_rules')?.enabled
  return (
    <div className="page">
      <PageHeader title="Overview">
        CSF is a security gateway that sits in front of a web application and inspects every request
        before the application sees it. It blocks SQL injection, cross-site scripting, command injection
        and forged login tokens.
      </PageHeader>

      <div className="grid g4">
        <Card><Stat label="Requests inspected" value={s?.total ?? '—'} /></Card>
        <Card><Stat label="Allowed" value={s?.allowed ?? '—'} tone="good" /></Card>
        <Card><Stat label="Blocked" value={s ? s.blocked : '—'} tone="bad" /></Card>
        <Card>
          <Stat label="Gateway mode" value={mode ? mode[0].toUpperCase() + mode.slice(1) : '—'}
            sub={mode === 'enforce' ? 'Attacks are being blocked' : 'Observing only, not blocking'} />
        </Card>
      </div>

      <Card title="How a request is inspected" hint="Cheap checks first; costlier ones only when needed">
        <div className="flow">
          {STEPS.map(([n, t, d], i) => (
            <div key={n} className="flow-step">
              <div className="flow-n">{n}</div>
              <div className="flow-t">{t}</div>
              <div className="flow-d">{d}</div>
              {i < STEPS.length - 1 && <span className="flow-arrow"><Icon name="chevron" /></span>}
            </div>
          ))}
        </div>
        <div className="flow-foot">
          <Badge tone={s1 ? 'good' : 'neutral'}>{s1 ? 'Signature rules active' : 'Signature rules offline'}</Badge>
          <Badge tone="good">Semantic analysis active</Badge>
          <Badge tone="good">Token verification active</Badge>
        </div>
      </Card>

      <h2 className="section-title">Where to start</h2>
      <div className="grid g3">
        <button className="tile" onClick={() => go('guided')}>
          <span className="tile-icon"><Icon name="play" /></span>
          <b>Guided demo</b>
          <span>Seven scripted requests, one click. Best for a first look or a presentation.</span>
          <span className="tile-cta">Open <Icon name="arrow" size={15} /></span>
        </button>
        <button className="tile" onClick={() => go('lab')}>
          <span className="tile-icon"><Icon name="target" /></span>
          <b>Attack lab</b>
          <span>Pick or write any payload and see exactly which stage catches it and why.</span>
          <span className="tile-cta">Open <Icon name="arrow" size={15} /></span>
        </button>
        <button className="tile" onClick={() => go('jwt')}>
          <span className="tile-icon"><Icon name="key" /></span>
          <b>Token lab</b>
          <span>Try forged, expired and tampered login tokens against a protected admin page.</span>
          <span className="tile-cta">Open <Icon name="arrow" size={15} /></span>
        </button>
      </div>

      <Card title="Gateway modes">
        <div className="modes">
          <div><b>Shadow</b><p>Inspects and logs everything but blocks nothing. Recommended first, to learn what normal traffic looks like.</p></div>
          <div><b>Monitor</b><p>Same as shadow, intended for alerting on suspicious traffic.</p></div>
          <div><b>Enforce</b><p>Blocks requests judged malicious. Switch modes from the top-right of any page.</p></div>
        </div>
      </Card>
    </div>
  )
}
