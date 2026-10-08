import { useEffect, useState } from 'react'
import { api } from '../api'

function Bars({ rows, max = 100, unit = '%' }) {
  return (
    <div className="bars">
      {rows.map((r) => (
        <div key={r.label} className="bar-row">
          <span className="bl">{r.label}</span>
          <div className="track">
            <div className={'fill ' + (r.tone || '')} style={{ width: `${Math.min(100, (r.value / max) * 100)}%` }} />
          </div>
          <span className="bv">{r.value.toFixed(1)}{unit}</span>
        </div>
      ))}
    </div>
  )
}

export default function Evidence() {
  const [b, setB] = useState(null)
  useEffect(() => { api.benchmarks().then(setB).catch(() => {}) }, [])
  if (!b) return <div className="page"><h1>Evidence</h1><p className="lead">Loading benchmarks…</p></div>

  const hold = b['frozen-holdout']
  const cross = b['cross-corpus-attack-score']
  const adv = b['adversarial']
  const s2 = b['s2-semantic']

  return (
    <div className="page">
      <h1>Evidence</h1>
      <p className="lead">
        Measured results from <code>docs/benchmarks/*.json</code> in the repository — nothing here is simulated.
        The team reports every number tuned on one corpus and tested on another.
      </p>

      <div className="kpis">
        <div className="kpi good"><div className="v">{hold.claimed_recall_pct}%</div><div className="l">Holdout recall (claimed classes)</div></div>
        <div className="kpi good"><div className="v">{hold.benign_fpr_pct}%</div><div className="l">Holdout false-positive rate</div></div>
        <div className="kpi"><div className="v">{hold.n}</div><div className="l">Holdout requests</div></div>
        <div className="kpi good"><div className="v">{adv.planes.find((p) => p.plane === 'full_gateway').evasion_rate_pct}%</div><div className="l">Adversarial evasion (full gateway)</div></div>
      </div>

      <div className="cols two">
        <div className="card">
          <h3>Frozen holdout — recall per attack class</h3>
          <Bars rows={['sqli', 'xss', 'cmdi'].map((k) => ({ label: k.toUpperCase(), value: hold.per_class[k].rate_pct, tone: 'good' }))} />
          <p className="hint">In-distribution (CSIC-derived), used once. {hold.per_class.sqli.blocked}/{hold.per_class.sqli.n} SQLi, {hold.per_class.xss.blocked}/{hold.per_class.xss.n} XSS, {hold.per_class.cmdi.blocked}/{hold.per_class.cmdi.n} cmdi blocked.</p>
        </div>
        <div className="card">
          <h3>Cross-application: recall vs false positives</h3>
          <Bars rows={cross.variants.flatMap((v) => [
            { label: v.variant + ' · recall', value: v.ecml_recall, tone: 'good' },
            { label: v.variant + ' · FPR', value: v.ecml_fpr, tone: 'bad' },
          ])} />
          <p className="hint">Tuned on CSIC, tested on unseen ECML/PKDD. Scoring S1 on attack rules only cut false positives from 67% to 4.7% while keeping 80% recall (ADR-0015).</p>
        </div>
      </div>

      <div className="cols two">
        <div className="card">
          <h3>S2 semantic stage latency</h3>
          <Bars unit=" ms" max={s2.latency_us.p99 / 1000} rows={[
            { label: 'p50', value: s2.latency_us.p50 / 1000 },
            { label: 'p95', value: s2.latency_us.p95 / 1000 },
            { label: 'p99', value: s2.latency_us.p99 / 1000 },
          ]} />
        </div>
        <div className="card">
          <h3>Adversarial mutation testing</h3>
          <table className="mini">
            <thead><tr><th>plane</th><th>variants</th><th>evasions</th></tr></thead>
            <tbody>
              {adv.planes.map((p) => (
                <tr key={p.plane}><td>{p.plane}</td><td>{p.surviving_variants}</td><td><b className="good-t">{p.evasions}</b></td></tr>
              ))}
            </tbody>
          </table>
          <p className="hint">Obfuscation mutations verified against a SQLite oracle. A parser-differential bypass found earlier was fixed (ADR-0012).</p>
        </div>
      </div>

      <div className="card honest">
        <h3>Honest limitations the team documents</h3>
        <ul>
          <li><b>S3 (learned model) is a negative result.</b> ROC-AUC 0.999 on the training corpus but 0.53–0.71 on an unseen application, so it is off by default and advisory-only (ADR-0017).</li>
          <li><b>No universal threshold exists.</b> Operators must calibrate on their own shadow-mode traffic before enforcing — which is why shadow mode is the default.</li>
          <li><b>Not independently security-audited.</b> Non-goals: second-order injection, DOM-only XSS, business-logic flaws, volumetric DDoS.</li>
        </ul>
      </div>
    </div>
  )
}
