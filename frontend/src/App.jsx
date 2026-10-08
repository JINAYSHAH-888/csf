import { useEffect, useState } from 'react'
import { api } from './api'
import AttackLab from './pages/AttackLab'
import JwtLab from './pages/JwtLab'
import Dashboard from './pages/Dashboard'
import Evidence from './pages/Evidence'

const PAGES = [
  ['lab', 'Attack Lab', AttackLab],
  ['jwt', 'JWT Lab', JwtLab],
  ['dash', 'Live Dashboard', Dashboard],
  ['evidence', 'Evidence', Evidence],
]
const MODES = ['shadow', 'monitor', 'enforce']
const MODE_HINT = {
  enforce: 'Attacks are blocked (403 / 401).',
  monitor: 'Evaluates and logs, but forwards every request.',
  shadow: 'Evaluates and logs, forwards everything. JWT auth is still enforced.',
}

export default function App() {
  const [page, setPage] = useState('lab')
  const [status, setStatus] = useState(null)
  const [down, setDown] = useState(false)

  const refresh = () =>
    api.status().then((s) => { setStatus(s); setDown(false) }).catch(() => setDown(true))
  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 2000)
    return () => clearInterval(t)
  }, [])

  const Page = PAGES.find((p) => p[0] === page)[2]
  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <span className="logo">◈</span> CSF<small>Cascaded Semantic Firewall</small>
        </div>
        <nav>
          {PAGES.map(([id, label]) => (
            <button key={id} className={page === id ? 'on' : ''} onClick={() => setPage(id)}>
              {label}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <div className="lbl">Gateway mode</div>
          <div className="seg">
            {MODES.map((m) => (
              <button key={m} className={status?.mode === m ? 'on ' + m : ''}
                onClick={() => api.setMode(m).then(refresh)}>{m}</button>
            ))}
          </div>
          <p className="hint">{MODE_HINT[status?.mode]}</p>
          <div className={'conn ' + (down ? 'bad' : 'ok')}>{down ? 'API offline' : 'Gateway online'}</div>
        </div>
      </aside>
      <main>
        {down && (
          <div className="banner">
            Cannot reach the console API on :8000. Start it with <code>run-demo.bat</code>.
          </div>
        )}
        <Page status={status} refreshStatus={refresh} />
      </main>
    </div>
  )
}
