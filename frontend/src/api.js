// Default the console API to the SAME host the page is served from (port 8000).
// The session cookie is SameSite=Lax, so the page and the API must share a host
// for it to be sent — deriving the host here makes auth work whether the console
// is opened on localhost or 127.0.0.1. VITE_API overrides for other setups.
function defaultApi() {
  try {
    return `${location.protocol}//${location.hostname}:8000`
  } catch {
    return 'http://127.0.0.1:8000'
  }
}
export const API = import.meta.env.VITE_API || defaultApi()

export const EXPORT_URL = API + '/api/export/feedback.jsonl'

async function call(path, opts = {}) {
  const r = await fetch(API + path, {
    credentials: 'include',
    ...opts,
  })
  if (!r.ok) {
    const data = await r.json().catch(() => ({}))
    const err = new Error(data.error || `${path} -> ${r.status}`)
    err.status = r.status
    err.data = data
    throw err
  }
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
  alerts: () => call('/api/alerts'),
  ackAlert: (id) => post(`/api/alerts/${id}/ack`),
  exportSummary: () => call('/api/export/summary'),
  login: (creds) => post('/api/auth/login', creds),
  signup: (data) => post('/api/auth/signup', data),
  logout: () => post('/api/auth/logout'),
  me: () => call('/api/auth/me'),
}
