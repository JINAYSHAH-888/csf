export const API = import.meta.env.VITE_API || 'http://127.0.0.1:8000'

async function call(path, opts) {
  const r = await fetch(API + path, opts)
  if (!r.ok) throw new Error(`${path} -> ${r.status}`)
  return r.json()
}
const post = (path, body) =>
  call(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  })

export const api = {
  status: () => call('/api/status'),
  events: (since = 0) => call(`/api/events?since=${since}`),
  presets: () => call('/api/presets'),
  tokens: () => call('/api/tokens'),
  benchmarks: () => call('/api/benchmarks'),
  analyze: (spec) => post('/api/analyze', spec),
  send: (spec) => post('/api/send', spec),
  setMode: (mode) => post('/api/mode', { mode }),
  reset: () => post('/api/reset'),
}
