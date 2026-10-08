import { useEffect, useState } from 'react'
import { api } from '../api'
import Cascade, { buildRows } from '../components/Cascade'
import { PageHeader, Card, Icon } from '../components/ui'

export default function AttackLab({ status, refreshStatus }) {
  const [presets, setPresets] = useState([])
  const [group, setGroup] = useState('SQL injection')
  const [req, setReq] = useState(null)
  const [label, setLabel] = useState('')
  const [res, setRes] = useState(null)
  const [busy, setBusy] = useState(false)
  const [custom, setCustom] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => { api.presets().then(setPresets).catch(() => {}) }, [])
  const groups = [...new Set(presets.map((p) => p.group))]

  async function run(spec, name) {
    setBusy(true); setErr(''); setReq(spec); setLabel(name || 'Custom request')
    try {
      const [analysis, sent] = await Promise.all([api.analyze(spec), api.send(spec)])
      setRes({ analysis, sent })
      refreshStatus()
    } catch (e) { setErr(String(e)) }
    setBusy(false)
  }
  const pick = (p) => run({ method: p.method, path: p.path, query: p.query, body: p.body }, p.label)

  const ev = res?.sent?.event
  const blocked = res && res.sent.status >= 400
  const shadow = ev?.decision === 'block' && !ev?.enforced
  const rows = res ? buildRows({ analysis: res.analysis, sent: res.sent, hasToken: false, status }) : null

  return (
    <div className="page">
      <PageHeader title="Threat simulator">
        Send a payload through the gateway and inspect the verdict of every stage.
      </PageHeader>

      <div className="lab">
        <Card title="Payload library" className="lab-pick">
          <div className="tabs">
            {groups.map((g) => (
              <button key={g} className={'tab' + (g === group ? ' on' : '')} onClick={() => setGroup(g)}>{g}</button>
            ))}
          </div>
          <div className="plist">
            {presets.filter((p) => p.group === group).map((p) => (
              <button key={p.label} className={'pitem' + (label === p.label ? ' on' : '')} disabled={busy} onClick={() => pick(p)}>
                <b>{p.label}</b>
                <code>{p.query || p.body}</code>
              </button>
            ))}
          </div>
          <button className="link" onClick={() => { setCustom(!custom); if (!req) setReq({ method: 'GET', path: '/search', query: '', body: '' }) }}>
            {custom ? 'Hide custom request' : 'Custom request'}
          </button>
          {custom && req && (
            <div className="custom">
              <div className="row">
                <select value={req.method} onChange={(e) => setReq({ ...req, method: e.target.value })}>
                  <option>GET</option><option>POST</option>
                </select>
                <input value={req.path} onChange={(e) => setReq({ ...req, path: e.target.value })} aria-label="path" />
              </div>
              <input placeholder="Query string, for example q=hello" value={req.query || ''} onChange={(e) => setReq({ ...req, query: e.target.value })} />
              <textarea rows={2} placeholder="Body (POST only)" value={req.body || ''} onChange={(e) => setReq({ ...req, body: e.target.value })} />
              <button className="btn primary" disabled={busy} onClick={() => run(req)}>Send request</button>
            </div>
          )}
        </Card>

        <div className="lab-out">
          {!res && !busy && (
            <Card className="empty-state">
              <Icon name="target" size={28} />
              <b>No request sent</b>
              <p>Select a payload to inspect the gateway verdict.</p>
            </Card>
          )}
          {err && <div className="alert bad">{err}</div>}
          {res && (
            <>
              <div className={'verdict ' + (blocked ? 'bad' : shadow ? 'warn' : 'good')}>
                <div className="verdict-icon"><Icon name={blocked ? 'x' : shadow ? 'alert' : 'check'} size={22} /></div>
                <div>
                  <div className="verdict-title">
                    {blocked ? 'Blocked by the gateway' : shadow ? 'Allowed through (shadow mode)' : 'Allowed'}
                  </div>
                  <div className="verdict-sub">
                    {label}{ev && <> · decided in {(ev.latency_us / 1000).toFixed(1)} ms · HTTP {res.sent.status}</>}
                  </div>
                  {shadow && <div className="verdict-sub">Enforce mode would have blocked this request.</div>}
                </div>
              </div>

              <Card title="Inspection trace">
                <Cascade rows={rows} />
              </Card>

              <div className="grid g2">
                <Card title="Application response">
                  {res.sent.reached_app ? (
                    <>
                      <div className={'alert ' + (shadow ? 'warn' : 'good')}>
                        {shadow ? 'Request reached the application.' : 'Request delivered to the application.'}
                      </div>
                      <pre>{pretty(res.sent.response_body)}</pre>
                    </>
                  ) : (
                    <div className="alert good">
                      No response from the application. The gateway answered directly.
                    </div>
                  )}
                </Card>
                <Card title="Inspected values" hint="decoded">
                  <table className="table">
                    <thead><tr><th>Where</th><th>Name</th><th>Decoded value</th></tr></thead>
                    <tbody>
                      {res.analysis.candidates.map((c, i) => (
                        <tr key={i}><td>{c.location}</td><td>{c.parameter}</td><td className="mono wrap">{c.normalized}</td></tr>
                      ))}
                    </tbody>
                  </table>
                </Card>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function pretty(s) {
  try { return JSON.stringify(JSON.parse(s), null, 2) } catch { return s }
}
