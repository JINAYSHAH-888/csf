import { useEffect, useState } from 'react'
import { api } from './api'
import { Icon } from './components/ui'
import Overview from './pages/Overview'
import GuidedDemo from './pages/GuidedDemo'
import AttackLab from './pages/AttackLab'
import JwtLab from './pages/JwtLab'
import Monitor from './pages/Monitor'
import Benchmarks from './pages/Benchmarks'

const NAV = [
  { group: null, items: [['overview', 'Overview', 'home', Overview]] },
  {
    group: 'Try it',
    items: [
      ['guided', 'Guided demo', 'play', GuidedDemo],
      ['lab', 'Attack lab', 'target', AttackLab],
      ['jwt', 'Token lab', 'key', JwtLab],
    ],
  },
  {
    group: 'Observe',
    items: [
      ['monitor', 'Traffic monitor', 'activity', Monitor],
      ['bench', 'Benchmarks', 'chart', Benchmarks],
    ],
  },
]
const ALL = NAV.flatMap((g) => g.items)

const MODES = [
  ['shadow', 'Shadow', 'Log only. Nothing is blocked (JWT checks still apply).'],
  ['monitor', 'Monitor', 'Log and alert. Nothing is blocked.'],
  ['enforce', 'Enforce', 'Block attacks.'],
]

export default function App() {
  const [page, setPage] = useState(() => location.hash.slice(1) || 'overview')
  const [status, setStatus] = useState(null)
  const [down, setDown] = useState(false)

  const go = (id) => { setPage(id); location.hash = id; window.scrollTo(0, 0) }
  const refresh = () =>
    api.status().then((s) => { setStatus(s); setDown(false) }).catch(() => setDown(true))
  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 2000)
    return () => clearInterval(t)
  }, [])

  const current = ALL.find((p) => p[0] === page) || ALL[0]
  const Page = current[3]
  const mode = MODES.find((m) => m[0] === status?.mode)

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><Icon name="shield" size={20} /></span>
          <div>
            <div className="brand-name">CSF</div>
            <div className="brand-sub">Cascaded Semantic Firewall</div>
          </div>
        </div>
        <nav>
          {NAV.map((g, i) => (
            <div key={i} className="nav-group">
              {g.group && <div className="nav-title">{g.group}</div>}
              {g.items.map(([id, label, icon]) => (
                <button key={id} className={'nav-item' + (current[0] === id ? ' on' : '')} onClick={() => go(id)}>
                  <Icon name={icon} size={17} /> {label}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="side-note">
          Demo environment. Traffic goes through the real gateway to a deliberately vulnerable sample shop.
        </div>
      </aside>

      <div className="content">
        <div className="topbar">
          <div className="crumb">{current[1]}</div>
          <div className="top-right">
            <div className="mode" title={mode?.[2]}>
              <span className="mode-label">Gateway mode</span>
              <div className="segmented">
                {MODES.map(([id, label, tip]) => (
                  <button key={id} title={tip} className={status?.mode === id ? 'on ' + id : ''}
                    onClick={() => api.setMode(id).then(refresh)}>{label}</button>
                ))}
              </div>
            </div>
            <span className={'conn ' + (down ? 'bad' : 'ok')}>{down ? 'Offline' : 'Connected'}</span>
          </div>
        </div>
        <main>
          {down && (
            <div className="alert bad">
              The console API is not reachable on port 8000. Start it with <code>run-demo.bat</code>.
            </div>
          )}
          <Page status={status} refreshStatus={refresh} go={go} />
        </main>
      </div>
    </div>
  )
}
