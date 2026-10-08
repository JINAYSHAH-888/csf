import { useState } from 'react'
import { PageHeader, Card, Kpi, Badge, Icon, category, decisionTone, decisionLabel } from '../components/ui'

export default function Traffic({ status, events, series, reset }) {
  const [filter, setFilter] = useState('all')
  const [open, setOpen] = useState(null)
  const s = status?.stats
  const d = status?.decision
  const total = s?.total || 0
  const blocked = (s?.blocked ?? 0) + (s?.shadow_would_block ?? 0)
  const shown = events.filter((e) => filter === 'all' || (filter === 'blocked' ? e.decision === 'block' : e.decision !== 'block'))

  return (
    <div className="page">
      <PageHeader title="Live traffic"
        actions={<button className="btn" onClick={reset}><Icon name="reset" size={15} /> Reset counters</button>}>
        Real-time audit stream from the gateway.
      </PageHeader>

      <div className="grid g4">
        <Card><Kpi label="Requests" value={total.toLocaleString()} series={series} /></Card>
        <Card><Kpi label="Allowed" value={(s?.allowed ?? 0).toLocaleString()} tone="good" /></Card>
        <Card><Kpi label="Blocked" value={blocked.toLocaleString()} tone="bad" sub={s?.auth_rejected ? `${s.auth_rejected} identity` : ''} /></Card>
        <Card><Kpi label="Rate limited" value={status?.rate_limit.limited ?? 0} /></Card>
      </div>

      <div className="grid g3-2">
        <Card title="Throughput" hint="requests / second, last 40 s"><Chart data={series} /></Card>
        <Card title="Gateway health">
          <ul className="kv">
            <li><span>Block-rate budget</span><b>{d ? d.block_rate_pct + '%' : '—'}</b></li>
            <li><span>Circuit breaker</span><Badge tone={status?.circuit_breaker.tripped ? 'bad' : 'good'} dot>{status?.circuit_breaker.tripped ? 'Tripped' : 'Healthy'}</Badge></li>
            <li><span>Malformed HTTP rejected</span><b>{s?.framing_rejected ?? 0}</b></li>
            <li><span>Enforcement blockers</span><b>{status?.enforcement_blockers.length || 'None'}</b></li>
          </ul>
        </Card>
      </div>

      <Card title="Audit log"
        right={<div className="tabs compact">
          {[['all', 'All'], ['blocked', 'Blocked'], ['allowed', 'Allowed']].map(([id, l]) => (
            <button key={id} className={'tab' + (filter === id ? ' on' : '')} onClick={() => setFilter(id)}>{l}</button>
          ))}</div>}>
        <div className="scroll">
          <table className="table hover">
            <thead><tr><th>Time</th><th>Request</th><th>Outcome</th><th>Category</th><th>Stage</th><th className="r">Latency</th></tr></thead>
            <tbody>
              {shown.map((e) => [
                <tr key={e.seq} onClick={() => setOpen(open === e.seq ? null : e.seq)}>
                  <td className="nowrap muted-c">{new Date(e.ts * 1000).toLocaleTimeString()}</td>
                  <td className="mono wrap">{e.method} {e.path}{e.payload?.query ? '?' + e.payload.query.slice(0, 48) : ''}</td>
                  <td><Badge tone={decisionTone(e.decision, e.enforced)} dot>{decisionLabel(e.decision, e.enforced)}</Badge></td>
                  <td>{category(e) || <span className="muted-c">—</span>}</td>
                  <td className="muted-c">{e.decision === 'allow' ? '—' : e.stage.replace('_', ' ')}</td>
                  <td className="r nowrap">{(e.latency_us / 1000).toFixed(1)} ms</td>
                </tr>,
                open === e.seq && (
                  <tr key={e.seq + 'x'} className="inspect"><td colSpan={6}>
                    <div className="detail"><b>Finding</b> {e.reason || 'No stage objected.'}</div>
                    <div className="detail"><b>Score</b> {e.score?.toFixed?.(1)} <b>Mode</b> {e.mode} <b>Request</b> {e.request_id}</div>
                  </td></tr>
                ),
              ])}
              {!shown.length && <tr><td colSpan={6} className="empty">No events</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

function Chart({ data }) {
  const w = 520, h = 150
  const max = Math.max(2, ...data)
  const pts = data.map((v, i) => [(i / Math.max(1, data.length - 1)) * w, h - 16 - (v / max) * (h - 30)])
  const line = pts.map((p) => p.join(',')).join(' ')
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="chart" preserveAspectRatio="none">
      <defs>
        <linearGradient id="cg" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stopColor="#4f8cff" stopOpacity=".45" /><stop offset="1" stopColor="#4f8cff" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0, 0.5, 1].map((f) => <line key={f} x1="0" x2={w} y1={h - 16 - f * (h - 30)} y2={h - 16 - f * (h - 30)} className="grid-line" />)}
      {pts.length > 1 && <polygon points={`0,${h - 16} ${line} ${w},${h - 16}`} fill="url(#cg)" />}
      {pts.length > 1 && <polyline points={line} className="line" />}
      <text x="4" y="12" className="axis">{max.toFixed(0)} req/s</text>
    </svg>
  )
}
