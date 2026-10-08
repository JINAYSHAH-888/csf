// Small shared building blocks: icons, page header, badges.

const PATHS = {
  home: 'M3 11l9-8 9 8M5 10v10h5v-6h4v6h5V10',
  play: 'M8 5v14l11-7z',
  target: 'M12 21a9 9 0 100-18 9 9 0 000 18zM12 16a4 4 0 100-8 4 4 0 000 8zM12 12h.01',
  key: 'M15 7a4 4 0 11-3.9 4.9L4 19v-3H1v-3l7.1-7.1A4 4 0 0115 7zM16 8h.01',
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  chart: 'M4 20V10M10 20V4M16 20v-7M22 20H2',
  check: 'M5 12l5 5 9-10',
  x: 'M6 6l12 12M18 6L6 18',
  minus: 'M6 12h12',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  arrow: 'M5 12h14M13 6l6 6-6 6',
  chevron: 'M9 6l6 6-6 6',
  alert: 'M12 4l9 16H3zM12 10v4M12 17h.01',
  reset: 'M4 12a8 8 0 108-8M4 4v5h5',
  info: 'M12 21a9 9 0 100-18 9 9 0 000 18zM12 11v5M12 8h.01',
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

export function Badge({ tone = 'neutral', children }) {
  return <span className={'badge ' + tone}>{children}</span>
}

export function Card({ title, hint, children, className = '' }) {
  return (
    <section className={'card ' + className}>
      {(title || hint) && (
        <div className="card-head">
          {title && <h2>{title}</h2>}
          {hint && <span className="card-hint">{hint}</span>}
        </div>
      )}
      {children}
    </section>
  )
}

export function Stat({ label, value, tone, sub }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className={'stat-value ' + (tone || '')}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

export const decisionTone = (d, enforced = true) =>
  d === 'block' ? (enforced ? 'bad' : 'warn') : d === 'allow_and_flag' ? 'warn' : 'good'
export const decisionLabel = (d, enforced = true) =>
  d === 'block' ? (enforced ? 'Blocked' : 'Would block') : d === 'allow_and_flag' ? 'Flagged' : 'Allowed'
