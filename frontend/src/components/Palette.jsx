import { useEffect, useMemo, useRef, useState } from 'react'
import { Icon } from './ui'

// Ctrl/Cmd+K command palette: navigation and gateway actions.
export default function Palette({ open, onClose, commands }) {
  const [q, setQ] = useState('')
  const [i, setI] = useState(0)
  const input = useRef(null)

  const list = useMemo(
    () => commands.filter((c) => (c.label + ' ' + c.group).toLowerCase().includes(q.toLowerCase())),
    [commands, q])

  useEffect(() => { if (open) { setQ(''); setI(0); setTimeout(() => input.current?.focus(), 20) } }, [open])
  useEffect(() => { setI(0) }, [q])

  if (!open) return null
  const run = (c) => { onClose(); c.run() }
  const onKey = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setI((x) => Math.min(list.length - 1, x + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setI((x) => Math.max(0, x - 1)) }
    else if (e.key === 'Enter' && list[i]) run(list[i])
    else if (e.key === 'Escape') onClose()
  }
  return (
    <div className="pal-backdrop" onMouseDown={onClose}>
      <div className="pal" onMouseDown={(e) => e.stopPropagation()}>
        <input ref={input} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey}
          placeholder="Search pages and actions" />
        <ul>
          {list.map((c, n) => (
            <li key={c.label} className={n === i ? 'on' : ''} onMouseEnter={() => setI(n)} onClick={() => run(c)}>
              <Icon name={c.icon} size={16} />
              <span>{c.label}</span>
              <em>{c.group}</em>
            </li>
          ))}
          {!list.length && <li className="none">No results</li>}
        </ul>
        <div className="pal-foot"><span>↑↓ navigate</span><span>↵ select</span><span>esc close</span></div>
      </div>
    </div>
  )
}
