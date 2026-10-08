import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { PageHeader, Card, Stat, Badge, Icon, decisionTone, decisionLabel } from '../components/ui'

const BENIGN = [
  { method: 'GET', path: '/search', query: 'q=wireless+headphones' },
  { method: 'GET', path: '/search', query: 'q=organic+coffee' },
  { method: 'GET', path: '/', query: '' },
  { method: 'POST', path: '/login', query: '', body: 'user=alice&password=hunter2' },
  { method: 'GET', path: '/search', query: "q=O'Brien+books" },
]
const ATTACKS = [
  { method: 'GET', path: '/search', query: "q=x' UNION SELECT password FROM users--" },
  { method: 'GET', path: '/search', query: 'q=<script>alert(1)</script>' },
  { method: 'GET', path: '/search', query: 'q=shoes; cat /etc/passwd' },
  { method: 'GET', path: '/search', query: 'q=../../../../etc/passwd' },
  { method: 'GET', path: '/search', query: "q=1'/**/UnIoN/**/SeLeCt/**/pass/**/FROM/**/users--" },
  { method: 'GET', path: '/admin', query: '' },
]
const pick = (a) => a[Math.floor(Math.random() * a.length)]

export default function Monitor({ status, refreshStatus }) {
  const [events, setEvents] = useState([])
  const [series, setSeries] = useState([])
  const [sim, setSim] = useState(false)
  const [filter, setFilter] = useState('all')
  const [open, setOpen] = useState(null)
  const seq = useRef(0)
  const last = useRef({ t: Date.now(), total: 0 })

  useEffect(() => {
    const t = setInterval(async () => {
      try {
        const { events: ev, latest } = await api.events(seq.current)
        if (ev.length) setEvents((old) => [...ev.reverse(), ...old].slice(0, 100))
        seq.current = latest
      } catch { /* offline banner covers it */ }
    }, 1000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    if (!status) return
    const now = Date.now()
    const dt = (now - last.current.t) / 1000
    const rps = dt > 0 ? (status.stats.total - last.current.total) / dt : 0
    last.current = { t: now, total: status.stats.total }
    setSeries((s) => [...s, Math.max(0, rps)].slice(-45))
  }, [status])

  useEffect(() => {
    if (!sim) return
    const t = setInterval(() => {
      api.send(pick(Math.random() < 0.4 ? ATTACKS : BENIGN)).catch(() => {})
    }, 450)
    return () => clearInterval(t)
  }, [sim])

  const s = status?.stats
  const d = status?.decision
  const total = s?.total || 0
  const flagged = (s?.blocked ?? 0) + (s?.shadow_would_block ?? 0)
  const shown = events.filter((e) => filter === 'all' || (filter === 'blocked' ? e.decision === 'block' : e.decision !== 'block'))

  return (
    <div className="page">
      <PageHeader title="Traffic monitor"
        actions={<>
          <button className="btn" onClick={() => api.reset().then(() => { setEvents([]); setSeries([]); seq.current = 0; refreshStatus() })}>
            <Icon name="reset" size={15} /> Reset
          </button>
          <button className={'btn ' + (sim ? 'danger' : 'primary')} onClick={() => setSim(!sim)}>
            <Icon name="play" size={15} /> {sim ? 'Stop simulator' : 'Start traffic simulator'}
          </button>
        </>}>
        Live counters and the audit log from the running gateway. Start the simulator to generate a
        realistic mix of normal and malicious requests.
      </PageHeader>

      <div className="grid g4">
        <Card><Stat label="Total requests" value={total} /></Card>
        <Card><Stat label="Allowed" value={s?.allowed ?? 0} tone="good" /></Card>
        <Card><Stat label="Blocked" value={s?.blocked ?? 0} tone="bad" sub={s?.auth_rejected ? `${s.auth_rejected} for invalid token` : undefined} /></Card>
        <Card><Stat label="Attack share" value={total ? ((flagged / total) * 100).toFixed(0) + '%' : '0%'} sub="blocked or would-block" /></Card>
      </div>

      <div className="grid g2">
        <Card title="Requests per second" hint="last 45 seconds">
          <Chart data={series} />
        </Card>
        <Card title="System health">
          <ul className="kv">
            <li><span>Block-rate budget</span>
              <b>{d ? d.block_rate_pct + '%' : '—'}{d?.over_budget ? ' (over budget)' : ''}</b></li>
            <li><span>Circuit breaker</span>
              <Badge tone={status?.circuit_breaker.tripped ? 'bad' : 'good'}>{status?.circuit_breaker.tripped ? 'Tripped' : 'Healthy'}</Badge></li>
            <li><span>Rate limiting</span><b>{status?.rate_limit.limited ?? 0} requests limited</b></li>
            <li><span>Malformed HTTP rejected</span><b>{s?.framing_rejected ?? 0}</b></li>
          </ul>
        </Card>
      </div>

      <Card title="Audit log" hint="Click a row for details">
        <div className="tabs compact">
          {[['all', 'All'], ['blocked', 'Blocked'], ['allowed', 'Allowed']].map(([id, l]) => (
            <button key={id} className={'tab' + (filter === id ? ' on' : '')} onClick={() => setFilter(id)}>{l}</button>
          ))}
        </div>
        <div className="scroll">
          <table className="table hover">
            <thead><tr><th>Time</th><th>Request</th><th>Outcome</th><th>Decided by</th><th className="r">Latency</th></tr></thead>
            <tbody>
              {shown.map((e) => [
                <tr key={e.seq} onClick={() => setOpen(open === e.seq ? null : e.seq)}>
                  <td className="nowrap">{new Date(e.ts * 1000).toLocaleTimeString()}</td>
                  <td className="mono wrap">{e.method} {e.path}{e.payload?.query ? '?' + e.payload.query.slice(0, 48) : ''}</td>
                  <td><Badge tone={decisionTone(e.decision, e.enforced)}>{decisionLabel(e.decision, e.enforced)}</Badge></td>
                  <td>{e.decision === 'allow' ? <span className="muted">—</span> : e.stage.replace('_', ' ')}</td>
                  <td className="r nowrap">{(e.latency_us / 1000).toFixed(1)} ms</td>
                </tr>,
                open === e.seq && (
                  <tr key={e.seq + 'x'} className="inspect"><td colSpan={5}>
                    <div className="detail"><b>Reason:</b> {e.reason || 'No stage objected.'}</div>
                    <div className="detail"><b>Score:</b> {e.score?.toFixed?.(1)} · <b>Mode:</b> {e.mode} · <b>Request ID:</b> {e.request_id}</div>
                  </td></tr>
                ),
              ])}
              {!shown.length && <tr><td colSpan={5} className="empty">No traffic yet. Start the simulator, or send requests from the Attack lab.</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

function Chart({ data }) {
  const w = 520, h = 140
  const max = Math.max(2, ...data)
  const pts = data.map((v, i) => [(i / Math.max(1, data.length - 1)) * w, h - 16 - (v / max) * (h - 30)])
  const line = pts.map((p) => p.join(',')).join(' ')
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="chart" preserveAspectRatio="none">
      {[0, 0.5, 1].map((f) => <line key={f} x1="0" x2={w} y1={h - 16 - f * (h - 30)} y2={h - 16 - f * (h - 30)} className="grid-line" />)}
      {pts.length > 1 && <polygon points={`0,${h - 16} ${line} ${w},${h - 16}`} className="area" />}
      {pts.length > 1 && <polyline points={line} className="line" />}
      <text x="4" y="12" className="axis">{max.toFixed(0)} req/s</text>
    </svg>
  )
}
