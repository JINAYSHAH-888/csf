# Curated Build Resources — Ranked

Everything below was verified against live sources on 2026-10-01. Ranked by *usefulness to actually shipping this*, not by stars.

## Tier 1 — Study these first, they define the design

| Resource | Why it matters | Link |
|---|---|---|
| **open-appsec** | The closest thing to a production, open-source, ML-based (signature-free) WAF. Integrates with NGINX, Envoy, Kong, APISIX, Istio, Kubernetes. Read its architecture for operational patterns: contextual scoring, confidence handling, false-positive suppression. Apache-2.0. | https://github.com/openappsec/openappsec |
| **SafeLine (chaitin)** | Semantic-analysis detection engine is open source (GPL-3.0). This is the reference implementation for Stage S2 — SQL grammar / JS AST / shell parsing instead of regex. Reported ~0.07% FPR vs ModSecurity's ~17.6%. | https://github.com/chaitin/SafeLine |
| **OWASP Coraza** | Go-native, ModSecurity-seclang-compatible WAF engine. Embeds **in-process** in a Go proxy — no IPC hop. This is your S1. | https://github.com/corazawaf/coraza |
| **OWASP CRS v4** | The rule set. Use `blocking_paranoia_level` vs `detection_paranoia_level` split so high-PL rules feed your score without blocking. | https://github.com/coreruleset/coreruleset |
| **pralab/modsec-advlearn** | Code for learning CRS rule weights + adversarial training. +30% detection, +85% adversarial robustness, −50% rules. Directly applicable to optimising S1. | https://github.com/pralab/modsec-advlearn |
| **WAF-A-MoLE** | Black-box mutational fuzzer that evades WAFs. This is your red-team tool — your adversarial evaluation number comes from running this against your own gateway. | https://github.com/AvalZ/WAF-A-MoLE |

## Tier 2 — Reference implementations of the proxy+model topology

| Resource | What to take from it | Link |
|---|---|---|
| **dizel12/ai-sqli-waf** | Small but *complete and honest*: FastAPI blocking reverse proxy + separate inference service + vulnerable demo app + live log UI, Docker Compose. Ships a 3-model comparison (char n-gram / char-CNN / DistilBERT) and documents that **DistilBERT was ~89× slower and ~477× larger than the char-CNN for comparable adversarial detection**. That single data point is the strongest argument for your cascade — and for benchmarking a char-CNN at S3. | https://github.com/dizel12/ai-sqli-waf |
| **BBVA/waf-brain** | ML WAF with pluggable custom models. Useful for the model-serving interface design. | https://github.com/BBVA/waf-brain |
| **vladan-stojnic/ML-based-WAF** | Covers all four classes (SQLi, XSS, path traversal, command injection). Good for feature-engineering ideas and a cheap baseline. | https://github.com/vladan-stojnic/ML-based-WAF |
| **Envoy ext_proc demo (Go)** | If you go the Envoy route instead of a custom Go proxy, this is the gRPC external-processor pattern. | https://github.com/ekkinox/ext-proc-demo |
| **Envoy ext_proc docs** | The official filter config. Note: out-of-process = extra latency, measure it. | https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter |

## Tier 3 — Papers worth reading in full (not just the abstract)

| Paper | Take-away | Link |
|---|---|---|
| **WADBERT** — dual-channel BERT (URLBERT + SecBERT), hybrid granularity embedding, multi-head attention over unordered parameters. F1 99.63% CSIC2010 / 99.50% SR-BH2020. | Best single model design in the literature. Its key insight — model *parameters* individually with provenance, not flat request text — is what your S3 input representation should copy. | https://arxiv.org/abs/2601.21893 |
| **Musoke et al., BERT-GNN for SQLi** — 99.67% acc, 99.55% attack F1, dataset+models public. | Second strongest. Low perturbation sensitivity (0.0037) is a rare robustness datapoint. | https://arxiv.org/abs/2608.28882 |
| **Musoke et al., ML for SQLi in WAFs** (companion) | The one your problem statement cites (ID is 28889, not 28889→28882 — both exist, cite both). | https://arxiv.org/abs/2608.28889 |
| **ModSec-AdvLearn** | The adversarial-robustness methodology. | https://arxiv.org/abs/2308.04964 |
| **WAF-A-MoLE** paper | The attack you must defend against. | https://arxiv.org/abs/2001.01952 |
| **WAPP** — safe positive-security policy learning from live traffic | Poisoning resilience 90% vs 62% baseline; degradation at 0.2% poisoned traffic without filtering. Read before attempting any learn-from-traffic feature. | https://arxiv.org/abs/2609.06840 |
| **ADL-WAF** — adaptive dual-layer (DT → SVM) | Closest prior art to "cascade" framing. 99.88% acc / 100% precision claimed; no latency reported. Cite as related work and beat it on the evaluation protocol. | https://arxiv.org/abs/2511.12643 |
| **Generalisation of ML models for intrusion detection** | The cross-dataset problem, stated properly. Your justification for the cross-corpus gate. | https://arxiv.org/abs/2605.04407 |
| **SecureBERT / SecureBERT 2.0** | Security-domain pretrained encoder. Candidate backbone for S3; compare against DistilBERT. | https://arxiv.org/abs/2510.00240 · https://huggingface.co/ehsanaghaei/SecureBERT |

## Tier 3b — Added after the second literature sweep (all verified 2026-10-01)

| Paper | Why it changes something | Link |
|---|---|---|
| **GenSQLi** — Future Internet 17(1):8, 2025 | **The single most useful number you now have.** GPT-4o generated 514 SQLi payloads, 92.5% validated functional against MySQL, **89% bypassed ModSecurity with current rules**. Put this in your problem statement — it is far stronger evidence than "regexes can't catch zero-days." Also gives you a reusable evaluation methodology. | https://doi.org/10.3390/fi17010008 |
| **Cascaded NLP for SQLi** — arXiv:2312.13041 | ⚠ **Direct prior art for your cascade.** 99.86% acc, 20× faster than transformer-only, beats 35 baselines. You must cite and differentiate from this. Your differentiators: the grammar-parsing stage, JWT integration, calibrated escalation, and the evaluation protocol. | https://arxiv.org/abs/2312.13041 |
| **Musoke et al., DistilBERT + stacked ensemble** — arXiv:2608.28889 | DistilBERT embeddings → LR/XGBoost/SVM + neural meta-learner. 99.81%, FGSM-hardened, head ~140× faster than DistilBERT-SVM. **Caveat: the 140× is the classifier head only — the DistilBERT forward pass is shared and dominates.** Don't quote it as end-to-end speedup. | https://arxiv.org/abs/2608.28889 |
| **Seyyar et al.** — IEEE Access 10:68633–68644, 2022 | >99.98% success, >98.70% F1, **0.4 ms detection time**. The rare paper with a timing number. Correctly softens any claim that "nobody reports latency" — what's actually missing is p99 under concurrency. DOI 10.1109/ACCESS.2022.3185748 | https://doi.org/10.1109/ACCESS.2022.3185748 |
| **LLM-generated obfuscated XSS** — arXiv:2604.19526 | **Negative result you need.** LLM obfuscations mostly don't preserve runtime behaviour (0.15 → 0.22 match after fine-tuning), and adding generated payloads *did not improve* detection. Lesson: behaviour-verify generated payloads in a real browser or you're training on noise. | https://arxiv.org/abs/2604.19526 |
| **XAI for web threat detection: systematic review** — AI Review, 2026 | Best single read before writing your lit survey. Independently names your three gaps: dataset constraints, computational overhead, no real-world deployment. DOI 10.1007/s10462-026-11581-y | https://doi.org/10.1007/s10462-026-11581-y |
| **Applebaum, Gaber, Ahmed survey** — Procedia CS, 2021 | The canonical "signature vs ML vs hybrid" survey. Cite it for the claim that hybrid is the identified path. | https://doi.org/10.1016/j.procs.2021.05.105 |
| **Sensors layered WAF** — Sensors 23(4):2073, 2023 | Layered LSTM WAF: 97.57% DDoS layer, 89.34% XSS/SQLi layer. Useful precisely because the numbers are *lower* — layering alone doesn't save you. | https://doi.org/10.3390/s23042073 |
| **CNN+LSTM XSS/SQLi** — Sci Reports, 2024 | 99.84/99.23/99.77%. Pre-transformer baseline to beat. | https://doi.org/10.1038/s41598-023-48845-4 |
| **Command injection, CNN+BiLSTM+attention** — Sci Reports, 2024 | 99.3% acc, 98.2% recall. **The rare dedicated command-injection paper** — you claim that class, so cite it. | https://doi.org/10.1038/s41598-024-74350-3 |
| **Multiclass HTTP injection DL** — Mathematics 10(16):2914, 2022 | SQLi + XSS + cmd injection from URL and body features. Feature-engineering reference. | https://doi.org/10.3390/math10162914 |
| **CodeBERT for SQLi** — ETASR, 2025 | 99.90% acc. Your answer to "why BERT and not a code model?" — benchmark it as an S3 candidate. DOI 10.48084/etasr.13340 | — |
| **RFC 8725 — JWT Best Current Practices** | **Mandatory.** Not a paper; the normative source for alg=none, algorithm confusion, key confusion. Your JWT module should be traceable to it clause by clause. | https://www.rfc-editor.org/rfc/rfc8725.html |
| **JWKS penetration-testing assessment** — JUTIF 7(2), 2026 | Systematises RS256→HS256, alg=none, kid injection, claim manipulation as a test methodology. **Use this as the spec for your JWT attack suite.** DOI 10.52436/1.jutif.2026.7.2.5662 | — |
| **JWT + OAuth 2.0 in REST APIs** — Radiotekhnika, 2026 | Weak secrets, missing exp/iat, role-claim forgery. DOI 10.30837/rt.2026.2.225.05 | — |
| **LLM-WAF** — IJWMT 16(4), 2026 | 96.8% acc, 0.95 F1. ⚠ Low-tier venue — verify indexing before making it central. Interesting mainly because it scores *below* compact encoders. DOI 10.5815/ijwmt.2026.04.18 | — |
| **LLM-AE-MP** — Expert Systems w/ Applications, 2025 | LLM representations + autoencoder + MLP. DOI 10.1016/j.eswa.2025.126982 | — |
| **THAI (SSRN preprint)** | ⚠ **Could not independently locate it.** Claimed to be two-phase deterministic → LLM second opinion, i.e. closest prior art to your design. Find it and read it, or don't cite it. Either way, resolve this before you claim novelty. | SSRN |

## Tier 4 — Data

| Dataset | Size / content | Link |
|---|---|---|
| HTTP CSIC 2010 | ~36k benign, ~25k anomalous. Single app, auto-generated — **do not** make this your only test set. | widely mirrored on GitHub/Kaggle |
| ECML/PKDD 2007 | Disjoint generator — this is your **cross-corpus** test set. | widely mirrored |
| SR-BH 2020 | 13-class multi-label; used in WADBERT. | per WADBERT paper |
| HTTPParams (Kaggle) | 19,304 benign / 11,763 anomalous — SQLi 10,852, XSS 532, cmd-inj 89, path traversal 290. Built from CSIC2010 benign + sqlmap + xssya + Vega + FuzzDB. Note the brutal class imbalance. | https://www.kaggle.com/datasets/evg3n1j/httpparamsdataset |
| SQL Injection Dataset (Kaggle) | 30,919 instances, 63.2% benign. The corpus behind the "99.90% CodeBERT" figure — use it for a like-for-like comparison. | https://www.kaggle.com/datasets/sajid576/sql-injection-dataset |
| Web Application Payloads Dataset | Mixed-class payloads. | https://www.kaggle.com/datasets/cyberprince/web-application-payloads-dataset |
| PayloadsAllTheThings | Attack payload corpus for augmentation. | https://github.com/swisskyrepo/PayloadsAllTheThings |
| FuzzDB / payloadbox | More payloads. | https://github.com/fuzzdb-project/fuzzdb · https://github.com/payloadbox |
| Your own captured benign traffic | **Non-negotiable.** FPR numbers from a benchmark are meaningless. Capture from DVWA / Juice Shop / your own API under a synthetic user load. | — |

## Tier 5 — Serving / performance references

| Resource | Numbers to anchor on | Link |
|---|---|---|
| Static quantization with HF Optimum | DistilBERT SST-2, ONNX INT8: p50 18.8 ms / p99 19.2 ms, ~4.06× speedup, 256 MB → 65 MB. | https://www.philschmid.de/static-quantization-optimum |
| inference-lab benchmark | ONNX FP32 1.58× faster than eager PyTorch (5.66 ms vs 8.95 ms p50, Banking77). **INT8 was 8% *slower* than FP32 on Apple Silicon** — architecture matters, benchmark on your target hardware. | https://github.com/SaiArrow/inference-lab |
| Fast DistilBERT on CPUs (Intel, NeurIPS ENLSP 2022) | Sub-10 ms CPU latency with AVX-512 VNNI. | https://neurips2022-enlsp.github.io/papers/paper_22.pdf |

## Immediate next steps

1. **Week 1:** stand up the Docker Compose skeleton — Go proxy + Coraza/CRS + vulnerable app (Juice Shop) + traffic generator + metrics. Get a baseline CRS PL1/PL2 detection-vs-FPR curve on your own traffic. Nothing else matters until that number exists.
2. **Week 1, parallel:** build the JWT verification module and its attack test suite (alg:none, RS256→HS256, jku/x5u injection, kid path traversal, kid SQLi, expired, wrong aud/iss). This is a self-contained, demo-ready, 100%-passable deliverable — get an early win.
3. **Week 2:** assemble and deduplicate the corpus with leakage-safe splitting (split by source application/generator, never random rows). Freeze a cross-corpus holdout you do not touch until the final evaluation.
4. **Week 3:** measure the S1 escalation rate on real benign traffic. If S1 alone cannot resolve ≥80%, the cascade thesis needs revision — find out now, not in week 10.
