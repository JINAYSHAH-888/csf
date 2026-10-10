import { Icon } from './ui'

// The inspection stages, in the order a request meets them, with a plain-English
// description of what each one does.
export const STAGES = [
  { id: 's0_framing', code: 'S0', name: 'Protocol check', what: 'Strict HTTP framing; rejects request-smuggling primitives.' },
  { id: 's0_auth', code: 'S0', name: 'Token verification', what: 'JWT signature, issuer, audience and expiry on protected routes.' },
  { id: 's1_rules', code: 'S1', name: 'Signature rules', what: 'OWASP Core Rule Set evaluated by Coraza.' },
  { id: 's2_semantic', code: 'S2', name: 'Semantic analysis', what: 'Parses input as SQL, HTML and shell; attack shape survives obfuscation.' },
  { id: 's3_model', code: 'S3', name: 'Learned model', what: 'Statistical classifier. Advisory only (ADR-0017).' },
  { id: 's4_decision', code: 'S4', name: 'Final decision', what: 'Fuses stage evidence and applies the gateway mode.' },
]

// Turn an /api/analyze + /api/send result into one row per stage.
export function buildRows({ analysis, sent, hasToken, status }) {
  const ev = sent?.event
  const stopAt = ev && ev.decision === 'block' ? ev.stage : null
  const enabled = (id) => status?.stages?.find((s) => s.id === id)?.enabled
  const rows = {}
  let cut = false

  const put = (id, row) => { rows[id] = row; if (row.state === 'block') cut = true }

  put('s0_framing', stopAt === 's0_framing'
    ? { state: 'block', text: ev.reason } : { state: 'pass', text: 'Request is well-formed' })
  if (!cut) {
    put('s0_auth', stopAt === 's0_auth'
      ? { state: 'block', text: 'Rejected: ' + ev.reason.replaceAll('_', ' ') }
      : { state: 'pass', text: hasToken ? 'Token verified' : 'Public route, no token needed' })
  }
  for (const id of ['s1_rules', 's2_semantic']) {
    if (cut) break
    if (id === 's1_rules' && !enabled('s1_rules')) { rows[id] = { state: 'off', text: 'Not running in this environment' }; continue }
    const s = analysis?.stages?.find((x) => x.stage === id)
    if (!s) { rows[id] = { state: 'off', text: 'Not running in this environment' }; continue }
    if (s.status === 'skipped') { rows[id] = { state: 'skipped', text: 'Not needed' }; continue }
    const st = s.decision === 'block' ? 'block' : s.decision === 'allow_and_flag' ? 'flag' : 'pass'
    put(id, {
      state: st,
      text: st === 'pass' ? 'Nothing suspicious found' : s.reason,
      meta: `score ${s.score.toFixed(1)} · ${(s.latency_us / 1000).toFixed(1)} ms`,
    })
  }
  if (!cut) rows.s3_model = { state: 'off', text: 'Switched off by default' }
  if (ev) {
    const st = ev.decision === 'block' ? 'block' : ev.decision === 'allow_and_flag' ? 'flag' : 'pass'
    rows.s4_decision = {
      state: st,
      text: st === 'block' ? (ev.enforced ? 'Request blocked' : 'Would be blocked (shadow mode: forwarded anyway)')
        : st === 'flag' ? 'Allowed, but flagged for review' : 'Request forwarded to the application',
    }
  }
  for (const s of STAGES) if (!rows[s.id]) rows[s.id] = { state: 'skipped', text: 'Not reached' }
  return rows
}

const ICON = { pass: 'check', block: 'x', flag: 'alert', off: 'minus', skipped: 'minus' }

export default function Cascade({ rows }) {
  return (
    <ol className="cascade">
      {STAGES.map((s) => {
        const r = rows?.[s.id] || { state: 'idle', text: '' }
        return (
          <li key={s.id} className={'casc ' + r.state}>
            <span className="casc-icon"><Icon name={ICON[r.state] || 'minus'} size={15} /></span>
            <div className="casc-body">
              <div className="casc-top">
                <span className="casc-code">{s.code}</span>
                <b>{s.name}</b>
                {r.meta && <span className="casc-meta">{r.meta}</span>}
              </div>
              <div className="casc-what">{s.what}</div>
              {r.text && <div className="casc-result">{r.text}</div>}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
