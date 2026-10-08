import { useEffect, useState } from 'react'
import { api } from '../api'
import { PageHeader, Card, Stat } from '../components/ui'

function Bars({ rows, max = 100, unit = '%' }) {
  return (
    <div className="bars">
      {rows.map((r) => (
        <div key={r.label} className="bar-row">
          <span className="bl">{r.label}</span>
          <div className="track"><div className={'fill ' + (r.tone || '')} style={{ width: `${Math.min(100, (r.value / max) * 100)}%` }} /></div>
          <span className="bv">{r.value.toFixed(1)}{unit}</span>
        </div>
      ))}
    </div>
  )
}

const NAMES = {
  'S1 full anomaly alone': 'Rules only (full score)',
  'S1 attack-only alone': 'Rules only (attack score)',
  'cascade: full anomaly OR S2': 'Cascade, full score',
  'cascade: attack-only OR S2': 'Cascade, attack score',
}

export default function Benchmarks() {
  const [b, setB] = useState(null)
  useEffect(() => { api.benchmarks().then(setB).catch(() => {}) }, [])
  if (!b) return <div className="page"><PageHeader title="Benchmarks">Loading measured results…</PageHeader></div>

  const hold = b['frozen-holdout']
  const cross = b['cross-corpus-attack-score']
  const adv = b['adversarial']
  const s2 = b['s2-semantic']

  return (
    <div className="page">
      <PageHeader title="Benchmarks">
        Measured results from the project repository (<code>docs/benchmarks</code>). These are real
        experiment outputs, not simulated. Recall means attacks caught; false-positive rate means
        normal users wrongly blocked.
      </PageHeader>

      <div className="grid g4">
        <Card><Stat label="Attacks caught (holdout)" value={hold.claimed_recall_pct + '%'} tone="good" sub={`${hold.n.toLocaleString()} requests tested`} /></Card>
        <Card><Stat label="Normal users blocked" value={hold.benign_fpr_pct + '%'} tone="good" sub="holdout set" /></Card>
        <Card><Stat label="Evasions found" value={adv.planes.find((p) => p.plane === 'full_gateway').evasions} tone="good" sub="mutation testing, full gateway" /></Card>
        <Card><Stat label="Median S2 latency" value={(s2.latency_us.p50 / 1000).toFixed(1) + ' ms'} sub={`p99 ${(s2.latency_us.p99 / 1000).toFixed(1)} ms`} /></Card>
      </div>

      <div className="grid g2">
        <Card title="Detection by attack type" hint="Frozen holdout, never tuned on">
          <Bars rows={['sqli', 'xss', 'cmdi'].map((k) => ({
            label: { sqli: 'SQL injection', xss: 'Cross-site scripting', cmdi: 'Command injection' }[k],
            value: hold.per_class[k].rate_pct, tone: 'good' }))} />
          <p className="note">{hold.per_class.sqli.blocked}/{hold.per_class.sqli.n} SQL injection, {hold.per_class.xss.blocked}/{hold.per_class.xss.n} XSS and {hold.per_class.cmdi.blocked}/{hold.per_class.cmdi.n} command injection requests blocked.</p>
        </Card>
        <Card title="On an unseen application" hint="Tuned on one dataset, tested on another">
          <Bars rows={cross.variants.map((v) => ({ label: (NAMES[v.variant] || v.variant) + ' · false positives', value: v.ecml_fpr, tone: 'bad' }))} />
          <p className="note">Scoring the rules on attack signatures only cut false positives from 67% to 4.7% while keeping 80% recall.</p>
        </Card>
      </div>

      <div className="grid g2">
        <Card title="Adversarial testing" hint="Obfuscated variants checked against a SQLite oracle">
          <table className="table">
            <thead><tr><th>Where tested</th><th className="r">Variants</th><th className="r">Evaded</th></tr></thead>
            <tbody>
              {adv.planes.map((p) => (
                <tr key={p.plane}><td>{{ s2_in_process: 'Semantic stage', s1_regex: 'Rule stage', full_gateway: 'Full gateway' }[p.plane] || p.plane}</td>
                  <td className="r">{p.surviving_variants}</td><td className="r"><b className="good-t">{p.evasions}</b></td></tr>
              ))}
            </tbody>
          </table>
        </Card>
        <Card title="Known limitations" hint="Documented by the team">
          <ul className="bullets">
            <li><b>Learned model (S3)</b> is off by default: accurate on its training data, unreliable on other applications.</li>
            <li><b>No universal threshold:</b> operators must calibrate on their own traffic, which is why Shadow mode exists.</li>
            <li><b>Not independently audited.</b> Out of scope: second-order injection, DOM-only XSS, business-logic flaws, volumetric DDoS.</li>
          </ul>
        </Card>
      </div>
    </div>
  )
}
