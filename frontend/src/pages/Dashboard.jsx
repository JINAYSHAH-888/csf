import { useEffect, useRef, useState } from 'react'
import { api } from '../api'

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

export default function Dashboard({ status, refreshStatus }) {
  const [events, setEvents] = useState([])
  const [series, setSeries] = useState([])
  const [sim, setSim] = useState(false)
  const seq = useRef(0)
  const last = useRef({ t: Date.now(), total: 0 })

  useEffect(() => {
    const t = setInterval(async () => {
      try {
        const { events: ev, latest } = await api.events(seq.current)
        if (ev.length) setEvents((old) => [...ev.reverse(), ...old].slice(0, 80))
        seq.current = latest
      } catch { /* offline banner handles it */ }
    }, 1000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    if (!status) return
    const now = Date.now()
    const dt = (now - last.current.t) / 1000
    const rps = dt > 0 ? (status.stats.total - last.current.total) / dt : 0
    last.current = { t: now, total: status.stats.total }
    setSeries((s) => [...s, { rps, blocked: status.stats.blocked }].slice(-40))
  }, [status])

  useEffect(() => {
    if (!sim) return
    const t = setInterval(() => {
      const attack = Math.random() < 0.4
      api.send(pick(attack ? ATTACKS : BENIGN)).catch(() => {})
    }, 450)
    return () => clearInterval(t)
  }, [sim])

  const s = status?.stats
  const d = status?.decision
  const total = s?.total || 0
  const blockRate = total ? (((s.blocked + s.shadow_would_block) / total) * 100).toFixed(1) : '0.0'

  return (
    <div className="page">
      <h1>Live Dashboard</h1>
      <p className="lead">Real counters from the running gateway. Start the simulator for mixed benign + attack traffic.</p>
      <div className="toolbar">
        <button className={sim ? 'danger' : 'primary'} onClick={() => setSim(!sim)}>
          {sim ? '■ Stop traffic simulator' : '▶ Start traffic simulator'}
        </button>
        <button onClick={() => { api.reset().then(() => { setEvents([]); setSeries([]); seq.current = 0; refreshStatus() }) }}>
          Reset counters
        </button>
      </div>

      <div className="kpis">
        <Kpi label="Requests" value={total} />
        <Kpi label="Allowed" value={s?.allowed ?? 0} tone="good" />
        <Kpi label="Blocked" value={s?.blocked ?? 0} tone="bad" />
        <Kpi label="Auth rejected" value={s?.auth_rejected ?? 0} tone="warn" />
        <Kpi label="Shadow would-block" value={s?.shadow_would_block ?? 0} tone="warn" />
        <Kpi label="Block rate" value={blockRate + '%'} />
      </div>

      <div className="cols two">
        <div className="card">
          <h3>Throughput (req/s)</h3>
          <Spark data={series.map((x) => x.rps)} />
          <div className="hint">
            Block-rate budget: {d ? `${d.block_rate_pct}% observed` : '—'}
            {d && !d.block_rate_conclusive && ' (not enough samples yet)'}
            {d?.over_budget && <b className="bad-t"> · OVER BUDGET — thresholds may not fit this traffic</b>}
          </div>
        </div>
        <div className="card">
          <h3>Resilience</h3>
          <ul className="kv">
            <li><span>Circuit breaker</span><b className={status?.circuit_breaker.tripped ? 'bad-t' : 'good-t'}>{status?.circuit_breaker.tripped ? 'TRIPPED' : 'closed'}</b></li>
            <li><span>Rate limiter</span><b>{status?.rate_limit.limited ?? 0} limited</b></li>
            <li><span>Framing rejects</span><b>{s?.framing_rejected ?? 0}</b></li>
            <li><span>Enforcement blockers</span><b>{status?.enforcement_blockers.length ? status.enforcement_blockers.length + ' active' : 'none'}</b></li>
          </ul>
        </div>
      </div>

      <div className="card">
        <h3>Audit log</h3>
        <div className="tbl-wrap">
          <table>
            <thead><tr><th>time</th><th>request</th><th>decision</th><th>stage</th><th>score</th><th>reason</th><th>µs</th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.seq} className={e.decision}>
                  <td>{new Date(e.ts * 1000).toLocaleTimeString()}</td>
                  <td className="mono">{e.method} {e.path}{e.payload?.query ? '?' + e.payload.query.slice(0, 40) : ''}</td>
                  <td><span className={'pill ' + e.decision}>{e.decision === 'allow_and_flag' ? 'flag' : e.decision}{e.decision === 'block' && !e.enforced ? ' (shadow)' : ''}</span></td>
                  <td>{e.stage}</td>
                  <td>{e.score?.toFixed?.(1)}</td>
                  <td className="reason-cell">{e.reason?.slice(0, 90)}</td>
                  <td>{e.latency_us}</td>
                </tr>
              ))}
              {!events.length && <tr><td colSpan={7} className="empty">No traffic yet — use the Attack Lab or start the simulator.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function Kpi({ label, value, tone = '' }) {
  return <div className={'kpi ' + tone}><div className="v">{value}</div><div className="l">{label}</div></div>
}

function Spark({ data }) {
  const w = 480, h = 90
  const max = Math.max(1, ...data)
  const pts = data.map((v, i) => `${(i / Math.max(1, data.length - 1)) * w},${h - (v / max) * (h - 8) - 4}`).join(' ')
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="spark" preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke="var(--accent)" strokeWidth="2" />
    </svg>
  )
}
