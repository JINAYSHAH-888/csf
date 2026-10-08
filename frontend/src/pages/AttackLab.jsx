import { useEffect, useState } from 'react'
import { api } from '../api'
import Pipeline, { buildNodes } from '../components/Pipeline'

export default function AttackLab({ status, refreshStatus }) {
  const [presets, setPresets] = useState([])
  const [req, setReq] = useState({ method: 'GET', path: '/search', query: "q=' OR '1'='1", body: '' })
  const [res, setRes] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => { api.presets().then(setPresets).catch(() => {}) }, [])
  const groups = [...new Set(presets.map((p) => p.group))]

  async function run(spec = req) {
    setBusy(true); setErr('')
    try {
      const [analysis, sent] = await Promise.all([api.analyze(spec), api.send(spec)])
      setRes({ spec, analysis, sent })
      refreshStatus()
    } catch (e) { setErr(String(e)) }
    setBusy(false)
  }
  function pick(p) {
    const spec = { method: p.method, path: p.path, query: p.query, body: p.body }
    setReq(spec); run(spec)
  }

  const nodes = res ? buildNodes({ analysis: res.analysis, sent: res.sent, hasToken: false }) : {}
  const ev = res?.sent?.event
  const blocked = res && res.sent.status >= 400
  const wouldBlock = ev?.decision === 'block' && !ev?.enforced

  return (
    <div className="page">
      <h1>Attack Lab</h1>
      <p className="lead">
        Pick a payload and fire it through the real gateway. Watch the request travel the cost-ordered
        cascade and see whether the vulnerable demo shop ever receives it.
      </p>

      <div className="cols">
        <div className="card presets">
          <h3>Payloads</h3>
          {groups.map((g) => (
            <div key={g}>
              <div className={'grp ' + (g === 'Benign' ? 'good' : '')}>{g}</div>
              {presets.filter((p) => p.group === g).map((p) => (
                <button key={p.label} className="preset" onClick={() => pick(p)}>{p.label}</button>
              ))}
            </div>
          ))}
        </div>

        <div className="grow">
          <div className="card">
            <h3>Request</h3>
            <div className="form">
              <select value={req.method} onChange={(e) => setReq({ ...req, method: e.target.value })}>
                <option>GET</option><option>POST</option>
              </select>
              <input className="path" value={req.path} onChange={(e) => setReq({ ...req, path: e.target.value })} />
              <input className="query" placeholder="query string (no ?)" value={req.query}
                onChange={(e) => setReq({ ...req, query: e.target.value })} />
            </div>
            <textarea rows={2} placeholder="request body (POST)" value={req.body}
              onChange={(e) => setReq({ ...req, body: e.target.value })} />
            <button className="primary" disabled={busy} onClick={() => run()}>
              {busy ? 'Sending…' : 'Send through CSF gateway →'}
            </button>
            {err && <div className="err">{err}</div>}
          </div>

          <div className="card">
            <h3>Cascade</h3>
            <Pipeline nodes={nodes} />
            {res && (
              <div className={'verdict ' + (blocked ? 'block' : wouldBlock ? 'flag' : 'pass')}>
                <div className="big">
                  {blocked ? `BLOCKED · HTTP ${res.sent.status}`
                    : wouldBlock ? 'ALLOWED (shadow) · would have been blocked'
                    : `ALLOWED · HTTP ${res.sent.status}`}
                </div>
                <div className="meta">
                  {ev && <>decided by <b>{ev.stage}</b> · {(ev.latency_us / 1000).toFixed(1)} ms gateway latency · mode {ev.mode} · id {res.sent.request_id}</>}
                </div>
                {ev?.reason && <div className="reason">{ev.reason}</div>}
              </div>
            )}
          </div>

          {res && (
            <div className="cols two">
              <div className="card">
                <h3>What the app received</h3>
                {res.sent.reached_app ? (
                  <>
                    <div className="note warn">The request reached the application.</div>
                    <pre>{pretty(res.sent.response_body)}</pre>
                  </>
                ) : (
                  <div className="note ok">
                    Nothing. The demo shop never saw this request — the gateway answered {res.sent.status} itself.
                  </div>
                )}
              </div>
              <div className="card">
                <h3>Extracted candidates</h3>
                <table className="mini">
                  <thead><tr><th>where</th><th>param</th><th>decoded value</th></tr></thead>
                  <tbody>
                    {res.analysis.candidates.map((c, i) => (
                      <tr key={i}><td>{c.location}</td><td>{c.parameter}</td><td className="mono">{c.normalized}</td></tr>
                    ))}
                  </tbody>
                </table>
                <p className="hint">Values are URL/Unicode-decoded and SQL-comment-stripped before analysis, so encoding tricks don't hide the payload.</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function pretty(s) {
  try { return JSON.stringify(JSON.parse(s), null, 2) } catch { return s }
}
