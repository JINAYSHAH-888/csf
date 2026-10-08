import { Badge, Card, Icon } from './ui'

const SEV = { critical: 'bad', warning: 'warn', info: 'neutral' }

function ago(ts) {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts))
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : `${Math.floor(s / 3600)}h ago`
}

export default function Alerts({ alerts, onAck }) {
  const open = alerts.filter((a) => !a.acknowledged)
  const closed = alerts.filter((a) => a.acknowledged).slice(0, 3)
  return (
    <Card title="Alerts" hint="Raised from the audit stream; acknowledge to clear"
      right={<Badge tone={open.length ? (open.some((a) => a.severity === 'critical') ? 'bad' : 'warn') : 'good'} dot>
        {open.length ? `${open.length} open` : 'All clear'}</Badge>}>
      {open.length === 0 && closed.length === 0 && (
        <div className="empty-inline">No alerts raised</div>
      )}
      <ul className="alert-list">
        {open.slice(0, 5).map((a) => (
          <li key={a.id} className={'al ' + (SEV[a.severity] || '')}>
            <span className="al-bar" />
            <div className="al-main">
              <div className="al-title">{a.title}<Badge tone={SEV[a.severity]}>{a.severity}</Badge></div>
              <div className="al-detail">{a.detail}</div>
            </div>
            <div className="al-side">
              <span>{ago(a.ts)}</span>
              <button className="btn sm" onClick={() => onAck(a.id)}><Icon name="check" size={13} /> Acknowledge</button>
            </div>
          </li>
        ))}
        {closed.map((a) => (
          <li key={a.id} className="al done">
            <span className="al-bar" />
            <div className="al-main"><div className="al-title">{a.title}</div><div className="al-detail">{a.detail}</div></div>
            <div className="al-side"><span>Acknowledged</span></div>
          </li>
        ))}
      </ul>
      {open.length > 5 && <div className="muted-c" style={{ marginTop: 8 }}>+ {open.length - 5} more open</div>}
    </Card>
  )
}
