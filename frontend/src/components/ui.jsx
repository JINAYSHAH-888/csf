// Shared building blocks: icons, headers, cards, badges, charts.

const PATHS = {
  grid: 'M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z',
  play: 'M8 5v14l11-7z',
  target: 'M12 21a9 9 0 100-18 9 9 0 000 18zM12 16a4 4 0 100-8 4 4 0 000 8zM12 12h.01',
  key: 'M15 7a4 4 0 11-3.9 4.9L4 19v-3H1v-3l7.1-7.1A4 4 0 0115 7zM16 8h.01',
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  chart: 'M4 20V10M10 20V4M16 20v-7M22 20H2',
  check: 'M5 12l5 5 9-10',
  x: 'M6 6l12 12M18 6L6 18',
  minus: 'M6 12h12',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  shieldcheck: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM8.5 12l2.5 2.5L16 9.5',
  arrow: 'M5 12h14M13 6l6 6-6 6',
  chevron: 'M9 6l6 6-6 6',
  alert: 'M12 4l9 16H3zM12 10v4M12 17h.01',
  reset: 'M4 12a8 8 0 108-8M4 4v5h5',
  list: 'M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01',
  zap: 'M13 2L4 14h7l-1 8 9-12h-7z',
  server: 'M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01',
  layers: 'M12 3l9 5-9 5-9-5zM3 13l9 5 9-5M3 17l9 5 9-5',
}

export function Icon({ name, size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={PATHS[name]} />
    </svg>
  )
}

export function PageHeader({ title, children, actions }) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        {children && <p>{children}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  )
}

export function Badge({ tone = 'neutral', children, dot }) {
  return <span className={'badge ' + tone}>{dot && <i className="bdot" />}{children}</span>
}

export function Card({ title, hint, children, className = '', right }) {
  return (
    <section className={'card ' + className}>
      {(title || hint || right) && (
        <div className="card-head">
          <div>{title && <h2>{title}</h2>}{hint && <span className="card-hint">{hint}</span>}</div>
          {right}
        </div>
      )}
      {children}
    </section>
  )
}

export function Sparkline({ data, tone = 'accent', height = 36 }) {
  const w = 120
  const max = Math.max(1, ...data)
  const pts = data.map((v, i) => [(i / Math.max(1, data.length - 1)) * w, height - 3 - (v / max) * (height - 8)])
  const line = pts.map((p) => p.join(',')).join(' ')
  return (
    <svg viewBox={`0 0 ${w} ${height}`} className={'spark ' + tone} preserveAspectRatio="none">
      {pts.length > 1 && <polygon points={`0,${height} ${line} ${w},${height}`} className="spark-area" />}
      {pts.length > 1 && <polyline points={line} className="spark-line" />}
    </svg>
  )
}

export function Kpi({ label, value, unit, tone, series, sub }) {
  return (
    <div className="kpi">
      <div className="kpi-top">
        <span className="kpi-label">{label}</span>
        {sub && <span className="kpi-sub">{sub}</span>}
      </div>
      <div className="kpi-row">
        <div className={'kpi-value ' + (tone || '')}>{value}{unit && <small>{unit}</small>}</div>
        {series && <Sparkline data={series} tone={tone || 'accent'} />}
      </div>
    </div>
  )
}

export function Donut({ parts, size = 150, center, centerSub }) {
  const total = parts.reduce((a, p) => a + p.value, 0)
  const r = 54, c = 2 * Math.PI * r
  let off = 0
  return (
    <div className="donut" style={{ width: size, height: size }}>
      <svg viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={r} className="donut-bg" />
        {total > 0 && parts.map((p) => {
          const len = (p.value / total) * c
          const el = <circle key={p.label} cx="70" cy="70" r={r} className={'donut-seg ' + p.tone}
            strokeDasharray={`${len} ${c - len}`} strokeDashoffset={-off} />
          off += len
          return el
        })}
      </svg>
      <div className="donut-center"><b>{center}</b>{centerSub && <span>{centerSub}</span>}</div>
    </div>
  )
}

export const decisionTone = (d, enforced = true) =>
  d === 'block' ? (enforced ? 'bad' : 'warn') : d === 'allow_and_flag' ? 'warn' : 'good'
export const decisionLabel = (d, enforced = true) =>
  d === 'block' ? (enforced ? 'Blocked' : 'Would block') : d === 'allow_and_flag' ? 'Flagged' : 'Allowed'

// Classify an audit event into a threat category.
export function category(e) {
  if (e.decision === 'allow') return null
  if (e.stage === 's0_auth') return 'Token forgery'
  if (e.stage === 's0_framing') return 'Protocol abuse'
  const r = (e.reason || '').toLowerCase()
  if (r.startsWith('sqli')) return 'SQL injection'
  if (r.startsWith('xss')) return 'Cross-site scripting'
  if (r.startsWith('shell') || r.startsWith('cmd')) return 'Command injection'
  if (r.startsWith('traversal') || r.startsWith('path')) return 'Path traversal'
  if (e.stage === 's1_rules') {
    const m = /cats=([a-z,]+)/.exec(r)
    const cats = m ? m[1].split(',').filter((c) => c !== 'protocol') : []
    const map = { sqli: 'SQL injection', xss: 'Cross-site scripting', cmdi: 'Command injection', rce: 'Command injection', lfi: 'Path traversal', traversal: 'Path traversal' }
    return (cats[0] && map[cats[0]]) || 'Rule match (CRS)'
  }
  return 'Other'
}

export function Stat({ label, value, tone, sub }) {
  return (
    <div>
      <div className="stat-label">{label}</div>
      <div className={'stat-value ' + (tone || '')}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}
