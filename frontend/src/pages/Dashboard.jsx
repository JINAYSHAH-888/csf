import { Icon, Card, Kpi, Badge, Donut, category, decisionTone, decisionLabel } from '../components/ui'

const PIPE = [
  { id: 's0_framing', code: 'S0', name: 'Protocol', sub: 'HTTP framing' },
  { id: 's0_auth', code: 'S0', name: 'Identity', sub: 'JWT verification' },
  { id: 's1_rules', code: 'S1', name: 'Signatures', sub: 'OWASP CRS' },
  { id: 's2_semantic', code: 'S2', name: 'Semantics', sub: 'Grammar analysis' },
  { id: 's4_decision', code: 'S4', name: 'Decision', sub: 'Policy fusion' },
]

const CAT_TONE = {
  'SQL injection': '#f87171', 'Cross-site scripting': '#fb923c', 'Command injection': '#fbbf24',
  'Path traversal': '#a78bfa', 'Token forgery': '#38bdf8', 'Protocol abuse': '#f472b6',
  'Rule match (CRS)': '#34d399', Other: '#8493ad',
}

function ago(ts) {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts))
  return s < 60 ? `${s}s ago` : `${Math.floor(s / 60)}m ago`
}

export default function Dashboard({ status, events, series, go }) {
  const s = status?.stats
  const total = s?.total ?? 0
  const blocked = (s?.blocked ?? 0) + (s?.shadow_would_block ?? 0)
  const allowed = s?.allowed ?? 0
  const rate = total ? ((blocked / total) * 100).toFixed(1) : '0.0'
  const lat = events.length ? events.reduce((a, e) => a + e.latency_us, 0) / events.length / 1000 : 0
  const enforce = status?.mode === 'enforce'
  const enabled = (id) => status?.stages?.find((x) => x.id === id)?.enabled

  // Per-stage counts of what each stage stopped, from the recent audit window.
  const stopped = {}
  events.forEach((e) => { if (e.decision === 'block') stopped[e.stage] = (stopped[e.stage] || 0) + 1 })

  const cats = {}
  events.forEach((e) => { const c = category(e); if (c) cats[c] = (cats[c] || 0) + 1 })
  const catRows = Object.entries(cats).sort((a, b) => b[1] - a[1])
  const catMax = Math.max(1, ...catRows.map((r) => r[1]))
  const threats = events.filter((e) => e.decision !== 'allow').slice(0, 7)

  return (
    <div className="page">
      <div className={'hero ' + (enforce ? 'enforce' : 'observe')}>
        <div className="hero-shield"><Icon name={enforce ? 'shieldcheck' : 'shield'} size={30} /></div>
        <div className="hero-main">
          <div className="hero-title">{enforce ? 'Protection active' : 'Observation mode'}</div>
          <div className="hero-sub">
            {enforce ? 'Malicious requests are being blocked before they reach the application.'
              : 'Requests are inspected and logged; nothing is blocked.'}
          </div>
        </div>
        <div className="hero-meta">
          <div><span>Protected app</span><b>demo-shop</b></div>
          <div><span>Mode</span><b className="cap">{status?.mode || '—'}</b></div>
          <div><span>Uptime</span><b>{status ? Math.floor(status.uptime_s / 60) + 'm ' + (status.uptime_s % 60) + 's' : '—'}</b></div>
        </div>
      </div>

      <div className="grid g4">
        <Card><Kpi label="Requests inspected" value={total.toLocaleString()} series={series} /></Card>
        <Card><Kpi label="Threats stopped" value={blocked.toLocaleString()} tone="bad" sub={enforce ? '' : 'would-block'} /></Card>
        <Card><Kpi label="Attack share" value={rate} unit="%" tone={Number(rate) > 40 ? 'warn' : 'good'} /></Card>
        <Card><Kpi label="Mean inspection latency" value={lat.toFixed(1)} unit="ms" /></Card>
      </div>

      <div className="grid g3-2">
        <Card title="Inspection pipeline" hint="Cost-ordered: cheap checks first, costlier stages only when needed"
          right={<Badge tone="good" dot>Live</Badge>}>
          <div className="pipe">
            {PIPE.map((p, i) => {
              const on = p.id === 's1_rules' ? enabled('s1_rules') : true
              return (
                <div key={p.id} className="pipe-item">
                  <div className={'pnode' + (on ? '' : ' off')}>
                    <div className="pnode-code">{p.code}</div>
                    <div className="pnode-name">{p.name}</div>
                    <div className="pnode-sub">{p.sub}</div>
                    <div className="pnode-count">{on ? (stopped[p.id] || 0) : '—'}<small>{on ? ' stopped' : ' offline'}</small></div>
                  </div>
                  {i < PIPE.length - 1 && <div className="plink"><i /><i /><i /></div>}
                </div>
              )
            })}
          </div>
          <div className="pipe-foot">
            <span><i className="sw good" /> Forwarded to application: <b>{allowed}</b></span>
            <span><i className="sw bad" /> Stopped at gateway: <b>{blocked}</b></span>
          </div>
        </Card>

        <Card title="Outcomes">
          <div className="donut-wrap">
            <Donut size={150} center={total ? Math.round((allowed / total) * 100) + '%' : '—'} centerSub="allowed"
              parts={[{ label: 'allowed', value: allowed, tone: 'good' }, { label: 'blocked', value: blocked, tone: 'bad' }]} />
            <ul className="legend">
              <li><i className="sw good" /> Allowed <b>{allowed}</b></li>
              <li><i className="sw bad" /> Blocked <b>{blocked}</b></li>
            </ul>
          </div>
        </Card>
      </div>

      <div className="grid g2">
        <Card title="Threat categories" hint="Recent audit window">
          {catRows.length ? (
            <div className="cats">
              {catRows.map(([name, n]) => (
                <div key={name} className="cat">
                  <span className="cat-name">{name}</span>
                  <div className="cat-track"><div className="cat-fill" style={{ width: `${(n / catMax) * 100}%`, background: CAT_TONE[name] }} /></div>
                  <b>{n}</b>
                </div>
              ))}
            </div>
          ) : <div className="empty-inline">No threats recorded</div>}
        </Card>

        <Card title="Latest detections" right={<button className="link-btn" onClick={() => go('traffic')}>View all <Icon name="arrow" size={14} /></button>}>
          {threats.length ? (
            <ul className="feed">
              {threats.map((e) => (
                <li key={e.seq}>
                  <span className={'feed-dot ' + decisionTone(e.decision, e.enforced)} />
                  <div className="feed-main">
                    <div className="feed-title">{category(e)}</div>
                    <code>{e.method} {e.path}{e.payload?.query ? '?' + e.payload.query.slice(0, 44) : ''}</code>
                  </div>
                  <div className="feed-side">
                    <Badge tone={decisionTone(e.decision, e.enforced)}>{decisionLabel(e.decision, e.enforced)}</Badge>
                    <span>{ago(e.ts)}</span>
                  </div>
                </li>
              ))}
            </ul>
          ) : <div className="empty-inline">No detections yet</div>}
        </Card>
      </div>
    </div>
  )
}
