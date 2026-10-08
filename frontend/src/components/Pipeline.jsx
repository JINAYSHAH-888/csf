// Visual cascade: S0 framing -> S0 JWT -> S1 -> S2 -> S3 -> S4
// node state: idle | pass | block | flag | skipped | off
export const STAGES = [
  { id: 's0_framing', short: 'S0', name: 'HTTP framing', sub: 'smuggling / ambiguity' },
  { id: 's0_auth', short: 'S0', name: 'JWT verify', sub: 'RS256 · iss · aud · exp' },
  { id: 's1_rules', short: 'S1', name: 'CRS rules', sub: 'Coraza sidecar' },
  { id: 's2_semantic', short: 'S2', name: 'Semantic parse', sub: 'SQL · XSS · shell · path' },
  { id: 's3_model', short: 'S3', name: 'Learned model', sub: 'advisory only' },
  { id: 's4_decision', short: 'S4', name: 'Decision', sub: 'fusion + budget' },
]

function label(n) {
  switch (n.state) {
    case 'pass': return n.text || 'pass'
    case 'block': return n.text || 'BLOCK'
    case 'flag': return n.text || 'flag'
    case 'skipped': return 'not reached'
    case 'off': return n.text || 'disabled'
    default: return '—'
  }
}

export default function Pipeline({ nodes }) {
  return (
    <div className="pipe">
      {STAGES.map((s, i) => {
        const n = nodes[s.id] || { state: 'idle' }
        return (
          <div key={s.id} className="pipe-item">
            <div className={'node ' + n.state}>
              <div className="tag">{s.short}</div>
              <div className="nm">{s.name}</div>
              <div className="sb">{s.sub}</div>
              <div className="st">{label(n)}</div>
            </div>
            {i < STAGES.length - 1 && (
              <div className={'arrow ' + (n.state === 'block' ? 'cut' : '')}>›</div>
            )}
          </div>
        )
      })}
    </div>
  )
}

function fill(nodes) {
  let cut = false
  for (const s of STAGES) {
    if (cut && !nodes[s.id]) nodes[s.id] = { state: 'skipped' }
    if (nodes[s.id]?.state === 'block') cut = true
  }
  return nodes
}

// Build node states from an /api/analyze result and an /api/send result.
export function buildNodes({ analysis, sent, hasToken }) {
  const nodes = {}
  const ev = sent?.event
  const stopAt = ev && ev.decision === 'block' ? ev.stage : null

  if (stopAt === 's0_framing') {
    nodes.s0_framing = { state: 'block', text: ev.reason }
    return fill(nodes)
  }
  nodes.s0_framing = { state: 'pass', text: 'ok' }

  if (stopAt === 's0_auth') {
    nodes.s0_auth = { state: 'block', text: ev.reason }
    return fill(nodes)
  }
  nodes.s0_auth = { state: 'pass', text: hasToken ? 'verified' : 'public route' }

  nodes.s1_rules = { state: 'off', text: 'needs Docker' }
  const s2 = analysis?.stages?.find((s) => s.stage === 's2_semantic')
  if (s2) {
    const st = s2.decision === 'block' ? 'block' : s2.decision === 'allow_and_flag' ? 'flag' : 'pass'
    nodes.s2_semantic = {
      state: st,
      text: `${s2.decision === 'allow' ? 'clean' : s2.decision.replace('allow_and_flag', 'flag')} · ${s2.score.toFixed(1)} · ${(s2.latency_us / 1000).toFixed(1)}ms`,
    }
  }
  nodes.s3_model = { state: 'off', text: 'off by default' }
  if (ev) {
    const st = ev.decision === 'block' ? 'block' : ev.decision === 'allow_and_flag' ? 'flag' : 'pass'
    nodes.s4_decision = {
      state: st,
      text: ev.decision === 'block' && !ev.enforced ? 'WOULD BLOCK' : ev.decision.replace('allow_and_flag', 'flag'),
    }
  }
  return fill(nodes)
}
