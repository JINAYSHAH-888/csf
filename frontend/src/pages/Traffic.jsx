import { useEffect, useState } from 'react'
import { api, EXPORT_URL } from '../api'
import { PageHeader, Card, Badge, Icon, Drawer, category, decisionTone, decisionLabel } from '../components/ui'

export default function Traffic({ status, events, series, reset }) {
  const [filter, setFilter] = useState('all')
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(null)
  const [fb, setFb] = useState(null)
  useEffect(() => {
    const load = () => api.exportSummary().then(setFb).catch(() => {})
    load()
    const t = setInterval(load, 4000)
    return () => clearInterval(t)
  }, [])

  const text = (e) => `${e.method} ${e.path}${e.payload?.query ? '?' + e.payload.query : ''} ${category(e) || ''} ${e.stage}`.toLowerCase()
  const shown = events.filter((e) =>
    (filter === 'all' || (filter === 'blocked' ? e.decision === 'block' : e.decision !== 'block')) &&
    (!q || text(e).includes(q.toLowerCase())))
  const selected = events.find((e) => e.seq === sel)
  const counts = {
    all: events.length,
    blocked: events.filter((e) => e.decision === 'block').length,
    allowed: events.filter((e) => e.decision !== 'block').length,
  }

  return (
    <div className="page">
      <PageHeader title="Live traffic"
        actions={<>
          <a className="btn" href={EXPORT_URL} download><Icon name="download" size={15} /> Export feedback dataset{fb ? ` (${fb.records})` : ''}</a>
          <button className="btn" onClick={reset}><Icon name="reset" size={15} /> Clear log</button>
        </>}>
        Request-level audit stream. Select a row to inspect the decision.
      </PageHeader>

      <Card title="Throughput" hint="requests per second, last 40 s"
        right={<span className="live-tag"><i /> Live</span>}>
        <Chart data={series} />
      </Card>

      <Card className="log-card">
        <div className="log-bar">
          <div className="seg2">
            {[['all', 'All'], ['blocked', 'Blocked'], ['allowed', 'Allowed']].map(([id, l]) => (
              <button key={id} className={filter === id ? 'on' : ''} onClick={() => setFilter(id)}>
                {l}<span>{counts[id]}</span>
              </button>
            ))}
          </div>
          <input className="search" placeholder="Filter by path, category or stage" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="scroll">
          <table className="table hover">
            <thead><tr><th>Time</th><th>Request</th><th>Outcome</th><th>Category</th><th>Stage</th><th className="r">Latency</th></tr></thead>
            <tbody>
              {shown.map((e) => (
                <tr key={e.seq} className={'row-in' + (sel === e.seq ? ' sel' : '')} onClick={() => setSel(e.seq)}>
                  <td className="nowrap muted-c">{new Date(e.ts * 1000).toLocaleTimeString()}</td>
                  <td className="mono wrap">{e.method} {e.path}{e.payload?.query ? '?' + e.payload.query.slice(0, 48) : ''}</td>
                  <td><Badge tone={decisionTone(e.decision, e.enforced)} dot>{decisionLabel(e.decision, e.enforced)}</Badge></td>
                  <td>{category(e) || <span className="muted-c">—</span>}</td>
                  <td className="muted-c nowrap">{e.decision === 'allow' ? '—' : e.stage.replaceAll('_', ' ')}</td>
                  <td className="r nowrap">{(e.latency_us / 1000).toFixed(1)} ms</td>
                </tr>
              ))}
              {!shown.length && <tr><td colSpan={6} className="empty">No matching events</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>

      <Drawer open={!!selected} onClose={() => setSel(null)} title="Request detail">
        {selected && <Detail e={selected} />}
      </Drawer>
    </div>
  )
}

function Detail({ e }) {
  const cat = category(e)
  const p = e.payload
  return (
    <div className="dt">
      <div className={'dt-verdict ' + decisionTone(e.decision, e.enforced)}>
        <Icon name={e.decision === 'block' ? 'x' : 'check'} size={18} />
        <div>
          <b>{decisionLabel(e.decision, e.enforced)}</b>
          <span>{cat ? cat : 'No threat detected'}</span>
        </div>
      </div>
      <dl className="dt-grid">
        <div><dt>Request ID</dt><dd className="mono">{e.request_id}</dd></div>
        <div><dt>Decided by</dt><dd>{e.decision === 'allow' ? 'No stage objected' : e.stage.replaceAll('_', ' ')}</dd></div>
        <div><dt>Score</dt><dd>{e.score?.toFixed?.(1)}</dd></div>
        <div><dt>Latency</dt><dd>{(e.latency_us / 1000).toFixed(2)} ms</dd></div>
        <div><dt>Mode</dt><dd className="cap">{e.mode}</dd></div>
        <div><dt>Time</dt><dd>{new Date(e.ts * 1000).toLocaleTimeString()}</dd></div>
      </dl>
      <div className="dt-k">Request</div>
      <pre>{e.method} {e.path}{p?.query ? '?' + p.query : ''}{p?.body ? '\n\n' + p.body : ''}</pre>
      {e.reason && <><div className="dt-k">Finding</div><pre>{e.reason}</pre></>}
    </div>
  )
}

function Chart({ data }) {
  const w = 720, h = 150
  const max = Math.max(2, ...data)
  const pts = data.map((v, i) => [(i / Math.max(1, data.length - 1)) * w, h - 16 - (v / max) * (h - 30)])
  const line = pts.map((p) => p.join(',')).join(' ')
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="chart" preserveAspectRatio="none">
      <defs>
        <linearGradient id="cg" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stopColor="#255dce" stopOpacity=".5" /><stop offset="1" stopColor="#255dce" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0, 0.5, 1].map((f) => <line key={f} x1="0" x2={w} y1={h - 16 - f * (h - 30)} y2={h - 16 - f * (h - 30)} className="grid-line" />)}
      {pts.length > 1 && <polygon points={`0,${h - 16} ${line} ${w},${h - 16}`} fill="url(#cg)" />}
      {pts.length > 1 && <polyline points={line} className="line" />}
      <text x="4" y="12" className="axis">{max.toFixed(0)} req/s</text>
    </svg>
  )
}
