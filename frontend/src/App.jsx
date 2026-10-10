import { useEffect, useRef, useState } from 'react'
import { api } from './api'
import { Icon } from './components/ui'
import Dashboard from './pages/Dashboard'
import AttackLab from './pages/AttackLab'
import JwtLab from './pages/JwtLab'
import Traffic from './pages/Traffic'
import Benchmarks from './pages/Benchmarks'
import Palette from './components/Palette'
import Logo from './components/Logo'

const NAV = [
  { group: 'Monitor', items: [
    ['dashboard', 'Dashboard', 'grid', Dashboard],
    ['traffic', 'Live traffic', 'activity', Traffic],
  ] },
  { group: 'Validate', items: [
    ['lab', 'Threat simulator', 'target', AttackLab],
    ['jwt', 'Token verification', 'key', JwtLab],
  ] },
  { group: 'Analytics', items: [
    ['bench', 'Detection performance', 'chart', Benchmarks],
  ] },
]
const ALL = NAV.flatMap((g) => g.items)
const MODES = [['shadow', 'Shadow'], ['monitor', 'Monitor'], ['enforce', 'Enforce']]

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

export default function App() {
  const [page, setPage] = useState(() => location.hash.slice(1) || 'dashboard')
  const [status, setStatus] = useState(null)
  const [down, setDown] = useState(false)
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [series, setSeries] = useState([])
  const [gen, setGen] = useState(false)
  const [pal, setPal] = useState(false)
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || 'dark')
  const seq = useRef(0)
  const last = useRef({ t: Date.now(), total: 0 })

  const go = (id) => { setPage(id); location.hash = id; window.scrollTo(0, 0) }
  const refresh = () =>
    api.status().then((s) => { setStatus(s); setDown(false) }).catch(() => setDown(true))

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 2000)
    return () => clearInterval(t)
  }, [])

  // One shared event stream so every page sees the same live data.
  useEffect(() => {
    const t = setInterval(async () => {
      try {
        const { events: ev, latest } = await api.events(seq.current)
        if (latest < seq.current) { seq.current = 0; setEvents([]); return }
        if (ev.length) setEvents((old) => [...ev.reverse(), ...old].slice(0, 400))
        seq.current = latest
      } catch { /* connection state handled by status poll */ }
    }, 1000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    if (!status) return
    const now = Date.now()
    const prev = last.current
    last.current = { t: now, total: status.stats.total, primed: true }
    // The first sample has no baseline; counting it would show lifetime
    // requests as one second of throughput.
    if (!prev.primed) return
    const dt = (now - prev.t) / 1000
    const rps = dt > 0 ? (status.stats.total - prev.total) / dt : 0
    setSeries((s) => [...s, Math.max(0, rps)].slice(-40))
  }, [status])

  useEffect(() => {
    if (!gen) return
    const t = setInterval(() => {
      api.send(pick(Math.random() < 0.4 ? ATTACKS : BENIGN)).catch(() => {})
    }, 500)
    return () => clearInterval(t)
  }, [gen])

  useEffect(() => {
    const h = (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPal((v) => !v) } }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('csf-theme', theme) } catch { /* storage unavailable */ }
  }, [theme])
  const toggleTheme = () => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))

  useEffect(() => {
    const t = setInterval(() => api.alerts().then((r) => setAlerts(r.alerts)).catch(() => {}), 2000)
    return () => clearInterval(t)
  }, [])
  const ackAlert = (id) => api.ackAlert(id).then((a) => setAlerts((l) => l.map((x) => (x.id === a.id ? a : x))))

  const reset = () => api.reset().then(() => { setEvents([]); setSeries([]); seq.current = 0; refresh() })

  const commands = [
    ...ALL.map(([id, label, icon]) => ({ group: 'Go to', label, icon, run: () => go(id) })),
    ...MODES.map(([id, label]) => ({ group: 'Gateway mode', label: `Set mode: ${label}`, icon: 'shield', run: () => api.setMode(id).then(refresh) })),
    { group: 'Action', label: theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme', icon: theme === 'dark' ? 'sun' : 'moon', run: toggleTheme },
    { group: 'Action', label: gen ? 'Stop traffic generator' : 'Start traffic generator', icon: 'zap', run: () => setGen((v) => !v) },
    { group: 'Action', label: 'Clear counters and log', icon: 'reset', run: reset },
  ]

  const current = ALL.find((p) => p[0] === page) || ALL[0]
  const Page = current[3]
  const live = { status, events, series, alerts, ackAlert, reset, refreshStatus: refresh, go }
  const openAlerts = alerts.filter((a) => !a.acknowledged)

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><Logo size={38} /></span>
          <div>
            <div className="brand-name">CSF</div>
            <div className="brand-sub">Cascaded Semantic Firewall</div>
          </div>
        </div>
        <nav>
          {NAV.map((g) => (
            <div key={g.group} className="nav-group">
              <div className="nav-title">{g.group}</div>
              {g.items.map(([id, label, icon]) => (
                <button key={id} className={'nav-item' + (current[0] === id ? ' on' : '')} onClick={() => go(id)}>
                  <Icon name={icon} size={17} /> {label}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="side-foot">
          <div className="env"><span className="env-dot" /> Demo environment</div>
          <div className="env-sub">v{status?.version || '0.1.0'} · {status?.stages?.find((s) => s.id === 's1_rules')?.enabled ? '4' : '3'} inspection stages</div>
        </div>
      </aside>

      <div className="content">
        <div className="topbar">
          <div className="crumb"><span>CSF</span><Icon name="chevron" size={14} /><b>{current[1]}</b></div>
          <div className="top-right">
            <button className={'bell' + (openAlerts.length ? ' on' : '')} onClick={() => go('dashboard')} title="Open alerts" aria-label="Alerts">
              <Icon name="bell" size={16} />{openAlerts.length > 0 && <i>{openAlerts.length}</i>}
            </button>
            <button className="kbd-hint" onClick={() => setPal(true)}><Icon name="search" size={14} /> Search <kbd>Ctrl K</kbd></button>
            <button className={'gen' + (gen ? ' on' : '')} onClick={() => setGen(!gen)}>
              <span className="gen-dot" /> {gen ? 'Traffic generator on' : 'Traffic generator off'}
            </button>
            <button className="theme-btn" onClick={toggleTheme} title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} aria-label="Toggle theme">
              <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={16} />
            </button>
            <div className="segmented">
              {MODES.map(([id, label]) => (
                <button key={id} className={status?.mode === id ? 'on ' + id : ''}
                  onClick={() => api.setMode(id).then(refresh)}>{label}</button>
              ))}
            </div>
            <span className={'conn ' + (down ? 'bad' : 'ok')}>{down ? 'Offline' : 'Online'}</span>
          </div>
        </div>
        <main>
          {down && (
            <div className="alert bad">
              Console API unreachable on port 8000. Start it with <code>run-demo.bat</code>.
            </div>
          )}
          <Page {...live} />
        </main>
      </div>
      <Palette open={pal} onClose={() => setPal(false)} commands={commands} />
    </div>
  )
}
