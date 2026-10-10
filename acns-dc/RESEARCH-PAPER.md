# Cascaded Semantic Firewalling: A Latency-Budgeted Hybrid Gateway Combining Deterministic Rules, Grammar-Aware Semantic Analysis, Cryptographic Token Verification, and a Distilled Transformer for Injection-Attack Detection

**Team CyberTruck** — Sardar Patel Institute of Technology, Mumbai
Applied Cryptography and Network Security Design Challenge (ACNS-DC) 2026–27
Subject: Cryptography and Network Security (CE305/CS305)

Vansh Shah (2024300218) · Rudra Patel (2024300163) · Aryan Nirav Shah (2024300213) · Dhruvin Shah (2024300224) · Jinay Shah (2024300222) · Pranav Sawant (2024300209) · Ruhi Shah (2024300219) · Shlok Shah (2024300227) · Riya Shah (2024300216) · Bhavya Sangani (2024300202)

---

## Abstract

Signature-based Web Application Firewalls (WAFs) remain the dominant deployed defence against SQL injection (SQLi), cross-site scripting (XSS), and command injection, yet they fail in two directions simultaneously: they miss obfuscated and novel payloads, and at the paranoia levels required for high recall they produce false-positive rates that make them operationally unusable. Published measurements of ModSecurity with the OWASP Core Rule Set show roughly 70–82% detection at a 17–18% false-positive rate at paranoia level 1, rising to ~95% detection only at a ~52% false-positive rate at paranoia level 4 [13]. The GenSQLi study is more damning still: of 514 LLM-generated SQLi payloads, 92.5% were validated as functional against a live MySQL backend and **89% bypassed ModSecurity running the latest rule set** [21]. In parallel, transformer-based request classifiers report F1 scores of 99.5–99.7% on the CSIC 2010 and SR-BH 2020 benchmarks [4], [5], but are evaluated almost exclusively offline, on single-domain corpora, without tail-latency budgets under concurrency, without adversarial stress, and without any integration into the authentication path that real gateways must also enforce.

Cascading a cheap model into an expensive one is itself established — cascaded NLP for SQLi reports 99.86% accuracy at 20× the speed of a transformer-only pipeline [22], and ADL-WAF applies a two-layer DT→SVM scheme [19]. We therefore do **not** claim the cascade as our contribution. We propose **CSF (Cascaded Semantic Firewall)**: an inline reverse-proxy gateway that decomposes request adjudication into four stages ordered by increasing cost — (S0) cryptographic token verification with strict algorithm pinning, (S1) deterministic OWASP CRS rule evaluation producing an anomaly score rather than a binary verdict, (S2) grammar-aware semantic analysis that parses candidate values as SQL, JavaScript, and shell fragments and asks whether the parse tree has attack shape, and (S3) a distilled transformer classifier invoked only on the residual ambiguous band. The central design claims are threefold: that a **grammar-aware semantic stage** — absent from every BERT-WAF paper we found, yet responsible for the best false-positive numbers in any deployed open-source WAF — belongs between the regex and the transformer; that **cryptographic token verification belongs inside the same adjudication pipeline**, because a forged admin token makes every downstream detection stage irrelevant; and that **calibrated escalation under a measured latency budget**, not raw classifier accuracy, is the engineering substance.

We additionally argue that the standard evaluation protocol in this literature is broken, and specify a replacement: cross-corpus evaluation (train on one dataset, test on a disjoint one), adversarial evaluation against the WAF-A-MoLE mutational fuzzer [11], benign-heavy evaluation at realistic class priors to make false-positive rates meaningful, and reporting of recall at a fixed operating FPR (R@FPR=0.1%) rather than a headline F1 on a balanced split. We present a staged implementation and measurement plan, an explicit threat model including adversaries who target the model itself, and a shadow-mode-first deployment path.

**Keywords:** web application firewall, injection attacks, cascaded inference, DistilBERT, OWASP CRS, JWT algorithm confusion, adversarial robustness, API gateway.

---

## 1. Introduction and Problem Framing

### 1.1 The attack surface

Every HTTP request arriving at a modern application traverses a reverse proxy or API gateway before reaching application code. That chokepoint is the last place a defender controls before untrusted input meets a SQL parser, a browser DOM, or a shell. Injection attacks exploit the gap between what the application *intends* an input to be (a product name, a page number, a username) and what a downstream interpreter *parses* it as (a SQL clause, a script tag, a shell command). OWASP has kept injection in its Top 10 continuously, currently as A03:2021 [1], for the straightforward reason that a single well-formed request can be sufficient for complete compromise.

The protected assets are concrete: backend database contents, credentials and session material, business logic exposed through REST and GraphQL endpoints, and the integrity of the authentication tokens themselves. The last of these is routinely treated as a separate problem from injection defence, which is precisely the mistake this work targets.

### 1.2 Why the deployed defence is inadequate

ModSecurity with the OWASP Core Rule Set is the reference open-source WAF [2]. Its detection model is pattern matching: a large corpus of hand-authored regular expressions, each matching a string shape known to be malicious, contributing to an anomaly score that is compared against a threshold. Two structural consequences follow.

**It cannot generalise.** A regex matches what its author anticipated. Obfuscation that preserves SQL semantics while destroying the lexical surface — URL and double-URL encoding, Unicode normalisation tricks, inline comment insertion (`SEL/**/ECT`), case alternation, whitespace substitution via `%0b`/`%a0`, string concatenation, hex literals, and nested encodings — defeats signature matching without defeating the database. Zero-day patterns, by definition, have no rule.

**Its detection/false-positive trade-off is a cliff, not a curve.** Public comparative testing places CRS at paranoia level 1 near 70–82% detection with a 17–18% false-positive rate; reaching ~95% detection requires paranoia level 4 and a ~52% false-positive rate [13]. A WAF that blocks half of legitimate traffic is not deployed in blocking mode. In practice teams run low paranoia levels and accept the false negatives, or they invest continuous engineering effort in per-application rule exclusions. CRS v4 improved this materially — notably by separating `blocking_paranoia_level` from `detection_paranoia_level`, so higher-level rules can be observed before being enforced [12] — but the underlying mechanism is unchanged.

**Generative models now mass-produce bypasses.** GenSQLi used GPT-4o with in-context learning to generate 514 SQLi payloads, validated 92.5% of them as functional against a live MySQL database, and found that **89% bypassed ModSecurity with current rules**; feeding the successful bypasses back through generative rule synthesis then blocked a large fraction of them [21]. Two conclusions follow. First, the signature layer's effective recall against *machine-generated* attack variants is far worse than benchmark numbers suggest — the 70–82% figure is against curated corpora, not an adaptive generator. Second, attack generation is now cheap and automatable, which permanently changes the economics: the defender's rule-authoring loop is human-paced, the attacker's is not.

**Rule-based WAFs are also directly attackable.** WAF-A-MoLE demonstrated black-box mutational fuzzing that iteratively mutates a SQLi payload, querying the target WAF, until it slips below the detection threshold while remaining semantically equivalent [11]. ModSec-AdvLearn later showed that learning CRS rule weights and applying adversarial training raises detection by up to 30% and adversarial robustness by up to 85%, while discarding up to 50% of CRS rules as redundant [10]. The implication is uncomfortable for the status quo: the default hand-tuned CRS configuration is not merely imperfect, it is demonstrably suboptimal even within its own hypothesis class.

### 1.3 Why the research alternative is not yet a system

A sizeable transformer-based literature reports near-ceiling accuracy. WADBERT uses a dual-channel architecture — hybrid granularity embedding feeding URLBERT and SecBERT channels, fused by multi-head attention to handle unordered parameters — reporting F1 of 99.63% on CSIC 2010 and 99.50% on SR-BH 2020 [4]. Musoke et al. report 99.67% accuracy and 99.55% attack-class F1 from BERT embeddings initialising GNN node features for SQLi classification [6], and in a companion paper reach 99.81% with DistilBERT embeddings feeding a stacked LR/XGBoost/SVM ensemble under a neural meta-learner, hardened with FGSM adversarial examples [5]. Seyyar et al. report >99.98% success and >98.70% F1 on HTTP request classification in IEEE Access [7], with a related conference version using CSIC 2010, FWAF and HTTPParams [8]. Salim and Oughdir [9] and fine-tuned CodeBERT on a 30,919-query SQLi corpus (99.90% accuracy) [23] report comparable figures. Beyond encoders, LLM-based inspection is emerging — LLM-AE-MP couples LLM representations with an autoencoder and MLP [24], and LLM-WAF reports 96.8% accuracy and 0.95 F1 on CSIC 2010 plus real traffic [25]. The latter is worth noting precisely because it is *lower* than the encoder results: a larger model is not automatically a better detector for this task.

These results do not transfer to a deployable gateway for four reasons:

1. **Benchmark monoculture.** CSIC 2010 is auto-generated traffic against a single e-commerce application from a single host, with a limited attack taxonomy. A model can score 99.6% on it by learning the generator's artefacts. Cross-dataset evaluation in intrusion detection remains rare, and models that excel within one corpus routinely degrade across corpora [18].
2. **Prior inversion.** Benchmarks are near-balanced; production traffic is overwhelmingly benign. At a 99.5% true-negative rate against 10⁶ benign requests per day, a system generates 5,000 false blocks per day. Headline F1 on a balanced split conceals this entirely.
3. **Latency is reported as a mean, if at all.** This is a narrower criticism than it first appears, and we state it precisely. Some papers *do* report timing: Seyyar et al. report 0.4 ms detection time [7], [8]; Musoke et al. report their ensemble classifying a full test set in 0.0136 s versus 1.896 s for DistilBERT-SVM, a ~140× gain [5]; cascaded NLP reports 20× over transformer-only [22]. What is absent is the number that governs deployability: **p99 and p99.9 added latency under concurrent load, in-process, with the body-parsing and normalisation cost included**. A mean inference time measured on a batched offline test set is not a tail latency measured on a live request path, and the 140× figure in [5] in particular isolates the *classifier head* while the DistilBERT forward pass — the dominant cost — is shared by both configurations. We flag this because it is the single easiest number in this literature to misread.
4. **No authentication integration.** The classifiers are standalone. A real gateway must also verify JWTs — and must do so correctly, which is its own failure-rich domain (§2.3).

A 2026 systematic review of explainable AI for web-application threat detection reaches a convergent conclusion from a different direction, identifying dataset constraints, computational overhead, and the absence of real-world deployment evidence as the field's principal open problems, and noting that cross-study performance comparison is unreliable because datasets, preprocessing, and evaluation protocols differ [20].

### 1.4 Positioning: what is and is not novel here

Honesty about prior art strengthens a claim rather than weakening it, and three recent works bound ours closely.

**Cascading is not novel.** "Advancing SQL Injection Detection for High-Speed Data Centers: A Novel Approach Using Cascaded NLP" [22] blends a classical model with a transformer in sequence, reporting 99.86% accuracy at 20× transformer-only speed on 30,000+ SQL statements, explicitly motivated by high-speed network deployment. ADL-WAF applies a two-layer Decision Tree → SVM scheme, reporting 99.88% accuracy and 100% precision [19]. A two-phase design in which an LLM acts as a second opinion on selected requests rather than inspecting all of them has also been proposed [26]. Any claim that CSF invents cost-ordered inference would be false.

**What is not yet composed.** Across everything surveyed, we found no system that places a **grammar-aware semantic stage** between rules and a learned model (the BERT-WAF literature goes regex → transformer, skipping parsing entirely, despite parsing being what produces the 0.07% FPR in deployed semantic WAFs [13]); no system that unifies that detection cascade with **correct cryptographic token verification** in one inline component; and no system evaluated under a protocol combining cross-corpus testing, adversarial fuzzing, generated-payload testing, and realistic class priors.

**The claim we make, phrased defensibly:**

> Existing research studies intelligent web-attack detection, cascaded inference, adaptive WAFs, and JWT security largely as separate components. This work investigates an integrated inline gateway combining deterministic rule scoring, grammar-aware semantic analysis, cryptographic JWT verification, and transformer-based semantic inspection within a single calibrated request-decision pipeline, evaluated under a deployment-realistic protocol.

We do not claim "nobody has done this." We claim this specific composition, and the evaluation protocol that tests it, are not established.

### 1.5 Contribution

This paper contributes: (a) a cascaded, latency-budgeted gateway architecture that treats escalation policy as the primary design object; (b) the insertion of a grammar-aware semantic stage between regex and transformer, which is absent from the BERT-WAF literature but is the mechanism behind the best false-positive numbers in deployed open-source WAFs; (c) unification of cryptographic token verification with injection detection in one adjudication pipeline, with an explicit ordering argument; (d) a corrected evaluation protocol with cross-corpus, adversarial, and prior-realistic components; and (e) a measurable engineering plan with pass/fail gates.

---

## 2. Background

### 2.1 The three injection families

**SQL injection** manipulates query structure. Classical union-based and error-based variants are lexically conspicuous; blind boolean and time-based variants (`AND SLEEP(5)`, `AND 1=IF(...)`) are far less so; second-order injection stores a payload benignly and triggers it in a later query, which is undetectable at the single-request boundary a WAF occupies — an honest scope limitation.

**Cross-site scripting** injects script into a rendering context. Reflected and stored XSS are visible in request or response bodies; DOM-based XSS executes entirely client-side via sinks like `innerHTML` and `eval`, often with the payload in the URL fragment, which is never transmitted to the server. A gateway WAF structurally cannot see fragment-only DOM XSS. Stating this explicitly is better engineering than claiming coverage.

**Command injection** escapes into a shell through metacharacters (`;`, `|`, `` ` ``, `$()`, newline) or argument injection. Blind variants exfiltrate via out-of-band DNS or HTTP and leave no in-response signal.

### 2.2 Defensive postures

*Negative security* enumerates badness (CRS). *Positive security* enumerates goodness: per-endpoint, per-parameter schemas of permitted type, length, charset, and shape. Positive security has strictly better zero-day properties — an unknown payload violating the schema is rejected without the defender ever having seen it — but has historically been unusable because authoring schemas by hand for a large API does not scale. Recent work closes that gap by learning the schema from live traffic, with the critical caveat that live traffic is poisoned: WAPP reports that naive learning degrades at 0.2% poisoned traffic and fails at 0.5%, and that trust filtering, deterministic rule synthesis, confidence scoring, and pre-enforcement validation raise poisoning resilience to 90% versus 62% for baselines [14]. This is directly relevant to our design and is the basis of an optional fifth stage (§3.7).

*Semantic analysis* is the third posture, and it is the one the BERT-WAF papers consistently omit. Rather than matching strings or learning embeddings, the engine parses the candidate value with an actual grammar — a SQL grammar for database-shaped parameters, a JavaScript AST for script-shaped content, a shell lexer for command-shaped content — and asks whether the resulting parse would *change the control flow of the interpreter*. A quotation mark is not suspicious; a value that parses into a tautological predicate appended to a WHERE clause is. SafeLine, which uses this approach, is reported at 71.65% detection with a **0.07% false-positive rate**, against ModSecurity PL1's 82.26% detection at 17.61% FPR [13]. Lower recall, but a false-positive rate two to three orders of magnitude better — which is the metric that determines whether blocking mode is politically survivable in production. Semantic analysis is also intrinsically obfuscation-resistant: decoding and normalisation happen before parsing, so encoding tricks that defeat regexes are neutralised by the parser's own lexer.

### 2.3 JWT verification as an injection-adjacent failure mode

JSON Web Tokens [3] carry a header declaring the signing algorithm. The spec's original sin is that this declaration is attacker-controlled. Two attack families follow:

- **`alg: none`** — implementations that honour the header's algorithm field accept an unsigned token. Still being assigned CVEs in 2025.
- **Algorithm confusion (RS256 → HS256)** — the attacker changes `alg` to HS256 and signs with the server's *public* RSA key; a library that passes the header algorithm into the verifier uses that public key as an HMAC secret and validates. The public key is, by construction, public.

Related vectors include `jku`/`x5u` header injection pointing at an attacker-hosted JWKS, `kid` parameter injection (path traversal to a predictable key file, or SQL injection into a key-lookup query — note that this is literally injection inside the authentication layer, which is why the two concerns belong in one component), weak HMAC secrets amenable to offline cracking, and missing `exp`/`aud`/`iss` claim validation.

These are not folklore. RFC 8725, *JSON Web Token Best Current Practices* [3], exists specifically because the base JWT/JWA specifications permit these configurations, and it enumerates `alg:none`, algorithm substitution, RSA/HMAC key confusion, and insufficient signature validation with normative mitigations. Recent penetration-testing studies of JWKS-based authentication systematise the same vectors — RS256→HS256 substitution, `alg=none`, `kid` injection, and claim manipulation — as a reproducible test methodology [39], and parallel work covers the JWT/OAuth 2.0 intersection including weak secrets, missing `exp`/`iat` validation, and role-claim forgery [36]. We adopt [39]'s methodology directly as our JWT test suite (§5.5), which is why that gate is specified at 100%: these are known, enumerated, deterministically testable failures, and partial credit is not meaningful.

The mitigation is simple and absolute: **the verifier's algorithm is configuration, never input**. The gateway pins an allowed algorithm set per issuer, rejects any token whose header algorithm is outside it before parsing further, resolves keys only from a pre-configured JWKS endpoint or a pinned key set, ignores `jku`/`x5u` entirely, treats `kid` as an opaque lookup key against an allowlist with no filesystem or database interpolation, and enforces `exp`, `nbf`, `iss`, and `aud` as mandatory. Implementing this correctly costs microseconds and is non-negotiable; getting it wrong renders every downstream detection stage irrelevant, because an attacker with a forged admin token does not need an injection payload.

---

## 3. Proposed System: CSF (Cascaded Semantic Firewall)

### 3.1 Design principle

The organising idea is **cost-ordered adjudication under a latency budget**. Each stage is characterised by its marginal cost and its *decisiveness* — the fraction of traffic it can resolve with confidence high enough to terminate the cascade. A stage is permitted to run only on the residual the previous stages could not resolve. The system's expected added latency is therefore

$$E[L] = \sum_{i} p_i \cdot c_i$$

where $c_i$ is stage $i$'s cost and $p_i$ is the fraction of traffic reaching it. The engineering goal is to drive $p_3$ (transformer escalation rate) to a few percent without sacrificing the recall the transformer provides — because the transformer is 2–3 orders of magnitude more expensive than everything above it.

This is a different claim from "add BERT to a WAF." It asserts that the escalation thresholds, the confidence calibration that produces them, and the measured residual rate are the engineering substance.

### 3.2 Stage S0 — Ingress, normalisation, and token verification

TLS termination; HTTP parsing with strict request smuggling defences (reject conflicting `Content-Length`/`Transfer-Encoding`, reject ambiguous chunking); extraction of **candidate values** rather than raw request text. Candidate extraction enumerates query parameters, form fields, JSON body leaves (recursively), multipart fields, cookies, selected headers, path segments, and GraphQL variables and query strings. Each candidate carries provenance: endpoint, location, parameter name, declared content type.

Normalisation is iterative and bounded: URL-decode, then decode again if the result differs, to a depth cap; HTML entity decode; Unicode NFKC; base64 decode when the value matches base64 shape and decodes to printable text; strip SQL and HTML comments for a *parallel* normalised view while retaining the original. Both views go downstream. **Normalisation depth is itself a DoS surface** — decode bombs and deeply nested JSON — so depth, size, and total work are hard-capped, and exceeding the cap is itself a signal.

Token verification runs here, before any detection stage, under the pinning rules of §2.3. Rationale for ordering: an invalid token means the request is rejected regardless of payload, so verifying first strictly reduces work; and a verified identity is an input to policy, letting the gateway apply tighter thresholds to anonymous or low-reputation principals.

*Cost: tens of microseconds for parsing and normalisation; ~50–200 µs for an ECDSA or RSA verification, amortised by a short-TTL cache keyed on token hash. Decisiveness: terminates all requests bearing invalid tokens.*

### 3.3 Stage S1 — Deterministic rule engine (anomaly scoring)

OWASP CRS v4 evaluated via Coraza, a Go-native, ModSecurity-compatible engine that embeds in-process and avoids an inter-process hop [2]. Critically, S1 is **not** used as a binary blocker. It emits the CRS anomaly score, which is a graded signal. We define two thresholds: $\tau_{hi}$ above which a request is blocked outright (unambiguous, high-confidence attacks), and $\tau_{lo}$ below which the request is forwarded (clean). The band $[\tau_{lo}, \tau_{hi}]$ is the ambiguity region that escalates. We additionally adopt CRS v4's split paranoia configuration: run detection at a high paranoia level for signal richness while blocking at a low one [12], so high-PL rules contribute to the score without unilaterally blocking. Following ModSec-AdvLearn [10], rule weights are candidates for learning rather than acceptance as shipped.

*Cost: ~0.5–10 ms for full CRS evaluation depending on rule count and body size — the dominant deterministic cost, and a real one. Rule subsetting per [10] is a direct latency lever. Decisiveness: targeted at 85–95% of traffic.*

### 3.4 Stage S2 — Grammar-aware semantic analysis

For each candidate value surviving S1's ambiguity band, run type-directed parsing:

- **SQL channel** — tokenise and attempt to parse the normalised value both standalone and injected into a synthetic template (`SELECT * FROM t WHERE c = '<value>'`). Compare the resulting parse tree against the tree produced by an inert placeholder. Structural divergence — a new predicate, an appended clause, a terminated-and-restarted statement, a comment truncating the remainder, a stacked query, a tautology, a UNION — is attack shape. Benign values do not change query structure, regardless of how many quotes they contain.
- **JavaScript channel** — parse as an expression and as a fragment in HTML attribute, element-text, and URL contexts. Flag emergence of executable constructs: script elements, event-handler attributes, `javascript:` schemes, calls to `eval`/`Function`/`setTimeout` with string arguments, and known sink assignments.
- **Shell channel** — lex for metacharacters that create new commands or redirections, and detect argument injection patterns.

Parse failures are informative, not errors: a value that cannot parse in any channel is just data, which is the common benign case and resolves quickly.

This stage is the paper's structural departure from the BERT-WAF literature. It is deterministic, explainable (the output is a parse-tree diff, which an analyst can read and a rule author can act on), extremely low false-positive, and robust to the encoding obfuscations that defeat S1 — because the parser lexes the decoded value rather than matching its surface.

*Cost: ~0.1–1 ms per candidate value. Decisiveness: targeted at 60–80% of the S1 residual.*

### 3.5 Stage S3 — Distilled transformer classifier

Only the residual reaches the model. Expected escalation rate: 2–5% of total traffic.

**Model.** A compact encoder — DistilBERT as the baseline, with SecureBERT [15], CodeBERT [23], and a security-domain-pretrained variant as comparators — fine-tuned for multi-class classification over {benign, SQLi, XSS, command injection, path traversal, other}. Multi-class rather than binary, because the predicted class drives the response policy and the audit log, and because class-conditional confidences are more interpretable than a single malice score.

**Input representation.** Not the raw request. The model sees a structured serialisation of the candidate value with its provenance: `[ENDPOINT] /api/search [LOC] query [PARAM] q [TYPE] string [VAL] <normalised value>`. Provenance matters: `1 OR 1=1` in a free-text search box is plausibly benign; in a parameter the learned schema says is always a small integer, it is not. WADBERT's finding that parameter-level modelling with attention over unordered parameters outperforms flat request text [4] supports this choice directly.

**Tokenisation.** Standard WordPiece fragments adversarial payloads badly. We evaluate (a) a domain-adapted subword vocabulary trained on payload corpora, and (b) a hybrid character-plus-subword scheme. This is an empirical question we commit to answering rather than assuming.

**Serving.** Export to ONNX, apply dynamic INT8 quantisation, serve via ONNX Runtime with dynamic batching under a tight queue deadline. Published figures for DistilBERT text classification: INT8 ONNX at p50 18.8 ms / p99 19.2 ms with ~4× speedup in one benchmark, and ~5.7 ms p50 for ONNX FP32 on short sequences in another, with model size falling from ~256 MB to ~65 MB [31], [32]. For short, truncated payload sequences (64–128 tokens) on AVX-512 VNNI hardware, single-digit-millisecond p50 is achievable; we will measure rather than assume, since reported INT8 speedups are architecture-dependent and in one Apple Silicon benchmark INT8 was *slower* than FP32 [32].

**Frozen-encoder variant.** Musoke et al. report that replacing a DistilBERT-SVM head with a stacked LR/XGBoost/SVM ensemble under a neural meta-learner retains 99.81% while classifying the test set ~140× faster [5]. We treat this as a strong candidate for the S3 head — but with a measurement caveat we will not repeat: that speedup is in the *classifier head only*, and the DistilBERT forward pass that produces the embeddings is common to both arms and dominates wall-clock cost. The honest version of this optimisation is "cheap head on a frozen encoder," and its benefit is real but bounded by the encoder. We will report encoder and head latency separately so the distinction cannot be lost.

**Fail-open/fail-closed.** If inference exceeds its deadline or the service is unavailable, the decision engine falls back to the S1+S2 verdict with a conservative threshold and emits a degradation metric. The failure mode is an explicit configuration choice per route, not an accident.

*Cost: 5–20 ms p99. Decisiveness: resolves the residual.*

### 3.6 Decision and policy engine

Inputs: S0 identity and verification result, S1 anomaly score, S2 per-channel parse verdicts, S3 class distribution, plus per-principal rate state. Output: ALLOW, BLOCK, CHALLENGE, RATE-LIMIT, or ALLOW-AND-FLAG.

Rather than hand-tuned weights, we fit a small calibrated combiner (logistic regression or gradient-boosted trees over the stage outputs) on held-out data, with isotonic or Platt calibration so the emitted score is an actual probability. Calibration is what makes thresholds meaningful: "block above 0.99" is a statement about the expected false-positive budget only if 0.99 means 0.99. Policy is expressed as a target false-positive rate per route, from which thresholds are derived, rather than as magic numbers.

Responses are differentiated: confident attacks are blocked; borderline requests on sensitive routes are challenged or rate-limited; borderline requests on low-risk routes are allowed and flagged. Monolithic block/allow is a false dichotomy that forces the threshold to be simultaneously too strict and too loose.

### 3.7 Optional Stage S2.5 — Learned positive-security schemas

Per-endpoint, per-parameter schemas (type, length bounds, charset class, cardinality, enum membership) learned from traffic using WAPP's safety machinery — trust filtering, deterministic synthesis, confidence scoring, validation before enforcement [14]. Schemas are proposed in observation mode, require a confidence threshold and a minimum sample count, and are human-approved before enforcement. Where a schema exists and is confident, it resolves requests cheaply and with excellent zero-day properties, sharply reducing the volume reaching S2 and S3. Treated as a stretch component because its failure mode — a poisoned or overfitted schema blocking legitimate traffic — is operationally severe.

### 3.8 Telemetry, audit, and the retraining loop

Every decision is logged with full provenance: request fingerprint, candidate values (with PII redaction via the learned schema's type information), every stage's output, final verdict, and per-stage latency. Logs serve three purposes: incident response, false-positive triage, and training-set growth.

The retraining loop is deliberately **not** automatic. Blocked payloads are mined, deduplicated by near-neighbour clustering, sampled for human labelling, and added to the corpus; models are retrained offline and promoted only after passing the full evaluation gate (§5), including a no-regression check on the frozen holdout. Automatically training on your own blocking decisions is a feedback loop that launders the current model's errors into ground truth, and is additionally a poisoning vector: an attacker who can predict what gets logged can shape the training distribution. Human-in-the-loop is a security control, not a convenience.

### 3.9 Request flow

```
                       ┌─────────────────────────────────────────┐
   Client ──TLS──▶     │  S0  Ingress · Normalise · JWT Verify    │
                       │      alg pinned · jku/x5u ignored        │
                       └───────────────┬─────────────────────────┘
                                       │ invalid token ──▶ 401
                                       ▼
                       ┌─────────────────────────────────────────┐
                       │  S1  Coraza + OWASP CRS v4               │
                       │      anomaly score (graded, not binary)  │
                       └───────┬──────────────┬──────────────────┘
                   score<τlo   │              │ score>τhi ──▶ 403
                   (~85-95%)   │              │
                       ◀───────┘              ▼  τlo ≤ score ≤ τhi
                       │              ┌─────────────────────────────┐
                       │              │  S2  Grammar-aware parsing  │
                       │              │  SQL AST · JS AST · shell   │
                       │              └───────┬──────────┬──────────┘
                       │          clean       │          │ attack shape ──▶ 403
                       ◀──────────────────────┘          │
                       │                                 ▼  still ambiguous (2-5%)
                       │                        ┌──────────────────────────┐
                       │                        │  S3  DistilBERT (ONNX    │
                       │                        │  INT8) multi-class       │
                       │                        └───────────┬──────────────┘
                       │                                    ▼
                       │                        ┌──────────────────────────┐
                       └───────────────────────▶│  Decision & Policy       │
                                                │  calibrated combiner     │
                                                │  ALLOW│BLOCK│CHALLENGE│  │
                                                │  RATE-LIMIT│FLAG         │
                                                └───────────┬──────────────┘
                                                            ▼
                                         Backend  ◀──┬──▶  Audit log ──▶ triage
                                                     │                    │
                                                     └── metrics          ▼
                                                                  human-labelled
                                                                  retraining corpus
```

---

## 4. Threat Model

**In scope.** Unauthenticated and authenticated remote attackers sending crafted HTTP/HTTPS requests; obfuscated variants of known injection classes; novel injection payloads within the SQLi/XSS/command-injection families; JWT forgery via algorithm confusion, `alg:none`, `jku`/`x5u`/`kid` manipulation, and weak secrets; adversaries with black-box query access to the gateway who iteratively mutate payloads to find the decision boundary [11]; and attempts to poison the retraining corpus by submitting payloads designed to be logged and mislabelled.

**Out of scope, stated explicitly.** Second-order injection where the payload is stored benignly and triggered later. DOM-based XSS confined to the URL fragment, which never reaches the server. Attacks over channels that bypass the gateway (direct database access, internal service-to-service traffic, SSH). Application logic flaws (IDOR, broken access control, business-logic abuse) — these are not pattern-detectable at the request boundary, and claiming otherwise would be dishonest. Supply-chain compromise of the gateway itself. Volumetric DDoS, which belongs upstream.

**Attacks on the defence.** The gateway is itself attack surface. Parser differentials between the gateway's HTTP/JSON parsing and the backend's are a bypass class (gateway sees one value, backend sees another) and demand parser-equivalence testing. Normalisation is a CPU-amplification DoS vector, bounded by hard caps. S3 is an asymmetric-cost DoS vector: an attacker who learns to craft cheap requests that reliably escalate can force expensive inference on every request. Mitigations: per-principal escalation budgets, a global escalation-rate circuit breaker that degrades to S1+S2 with tightened thresholds under load, and treating sustained high escalation rate from one source as a signal in itself.

---

## 5. Evaluation Protocol

We treat the evaluation design as a first-class contribution, because the prevailing protocol in this literature cannot distinguish a deployable system from an overfitted one.

### 5.1 Datasets

| Role | Dataset [38] | Notes |
|---|---|---|
| Train / in-corpus test | HTTP CSIC 2010 | ~36k benign, ~25k anomalous; single application, auto-generated. Standard but weak. |
| Train / multi-class | SR-BH 2020 | 13-class multi-label; used alongside CSIC in [4]. |
| Cross-corpus test | ECML/PKDD 2007 | Disjoint generator and application. |
| Payload-level | HTTPParams (Kaggle) | ~19.3k benign, ~11.8k anomalous; SQLi 10,852, XSS 532, cmd-injection 89, path traversal 290. Note the severe class imbalance across attack types. |
| Payload-level | Kaggle SQLi (30,919 instances, 63.2% benign) | Widely used; also the corpus behind the 99.90% CodeBERT figure, so useful for direct comparison. |
| Payload sources | PayloadsAllTheThings, FuzzDB, payloadbox | Raw attack payloads for augmentation. |
| Adversarial | WAF-A-MoLE-generated [11] | Mutated semantically-equivalent SQLi against our own gateway. |
| Generated | GenSQLi-style LLM-generated SQLi [21] | Generate payloads, validate each against a live MySQL backend (keep only functional ones — GenSQLi kept 92.5%), then measure bypass rate. This is the test that produced the 89%-against-ModSecurity figure, and it is the test our gateway must survive. |
| Generated (XSS) | LLM-obfuscated XSS, behaviour-filtered [27] | **With a caveat.** Gabbireddy and Saha find LLMs currently struggle to generate obfuscations that preserve observed runtime behaviour (match rate 0.15 untuned, 0.22 fine-tuned) and that adding generated payloads *did not improve* detection in their setting. We therefore use browser-runtime behaviour verification as a hard filter: an "XSS payload" that does not execute is not an XSS payload, and training on it teaches the model noise. |
| Benign realism | Captured traffic from our own deployed test applications | Essential for FPR that means anything. |

**Leakage discipline.** Deduplicate within and across corpora by normalised-form hashing and near-duplicate clustering before splitting. Split by *source application and generator*, not by random row — random splits over generated corpora leak the generator's templates across the split and are the single most likely explanation for 99.6% F1 figures.

### 5.2 Metrics

The headline metric is **recall at a fixed false-positive rate**, R@FPR = 0.1% and R@FPR = 0.01%, not F1. Also reported: full ROC and precision–recall curves, per-attack-class recall (so the 89 command-injection samples cannot hide behind SQLi's 10,852), calibration error (ECE and reliability diagrams), and **cross-corpus delta** — the drop from in-corpus to out-of-corpus R@FPR, which we treat as the single most informative number in the entire evaluation.

**Prior correction.** Report confusion matrices re-weighted to realistic base rates (we assume 1 attack per 10³–10⁵ requests as a sensitivity range), and translate FPR into absolute false blocks per million requests. A reviewer should be able to read off "this configuration blocks N legitimate users per day."

### 5.3 Performance metrics

Added latency p50 / p95 / p99 / p99.9, measured end-to-end at the proxy, decomposed per stage. Throughput (RPS) at fixed p99 budget. Escalation rate to S2 and to S3 under benign load, under attack load, and under adversarial load. Memory and CPU per instance. Behaviour under the S3 circuit breaker.

### 5.4 Baselines

(1) ModSecurity + CRS v4 at PL1 and PL2; (2) CRS alone at the PL that matches our FPR, for an apples-to-apples recall comparison; (3) a semantic-analysis-only configuration; (4) a transformer-only configuration applied to all traffic — this is the published-literature configuration, and comparing against it isolates exactly what the cascade costs in accuracy and saves in latency; (5) full CSF. An ablation removing each stage in turn quantifies marginal contribution.

### 5.5 Success criteria (pre-registered)

| Gate | Target |
|---|---|
| In-corpus R@FPR=0.1% | ≥ 0.95 |
| Cross-corpus R@FPR=0.1% | ≥ 0.85 (a cross-corpus drop under 10 points is the real result) |
| FPR on captured benign traffic | ≤ 0.1% |
| Adversarial (WAF-A-MoLE, 1k mutation budget) evasion rate | ≤ 15% |
| GenSQLi-style generated payloads (validated functional) bypass rate | ≤ 20% (ModSecurity baseline: 89% [21]) |
| Per-class recall, command injection | ≥ 0.90 — reported separately, so the 89-sample class cannot hide behind SQLi |
| p99 added latency, benign traffic | ≤ 10 ms |
| S3 escalation rate, benign traffic | ≤ 5% |
| JWT attack suite (alg:none, RS→HS confusion, jku/x5u/kid injection, expired, wrong aud/iss) | 100% blocked |

A result that misses a gate and is reported honestly is a better paper than a result that hits every gate because the split leaked.

---

## 6. Implementation Plan

**Stack.** Gateway in Go (Coraza is Go-native and embeds in-process, avoiding an IPC hop; Go's concurrency model suits a proxy). Inference service in Python with ONNX Runtime, or Go with onnxruntime-go to eliminate a network hop if the measurement justifies it. Grammar parsers: a SQL lexer/parser (`vitess/sqlparser` or `pg_query_go` depending on target dialect), a JS parser via an embedded engine or a Go ES parser, and a shell lexer. JWT via a library configured with explicit algorithm allowlists, never header-derived. Deployment: Docker Compose for development, Kubernetes with the gateway as a sidecar or ingress filter for the demo. Alternative integration path: Envoy `ext_proc` gRPC external processor [33], which is how production ML WAFs integrate (open-appsec integrates with NGINX, Envoy, Kong, APISIX and others this way [37]) — at the cost of an out-of-process hop that must be measured.

**Reference systems to study, not fork.** `open-appsec` (production ML WAF, contextual scoring, no signatures, Apache-2.0) is the closest production analogue and the right source of operational lessons [37]. An IEEE ICEI 2024 system places an XGBoost classifier directly in front of the web server for SQLi/XSS/LFI [34], and recent work on mining adversarial prompt patterns into WAF rules [35] is a template for automating the rule-synthesis half of our retraining loop. SafeLine's open-source semantic engine is the reference for S2. `pralab/modsec-advlearn` provides the adversarial training methodology and WAF-A-MoLE integration for S1 weight learning. `dizel12/ai-sqli-waf` is a useful small-scale reference for the proxy-plus-inference-service topology and explicitly documents the CNN-vs-DistilBERT trade (DistilBERT ~89× slower and ~477× larger than a character CNN for comparable adversarial detection) — a finding that directly motivates our cascade and also suggests a character-CNN candidate for S3 worth benchmarking against DistilBERT. `BBVA/waf-brain` and `coreruleset/coreruleset` round out the baseline set.

**Phases (10-person team).**

| Phase | Weeks | Deliverable | Owners |
|---|---|---|---|
| P0 Foundations | 1–2 | Repo, CI, threat model, vulnerable test app (DVWA/Juice Shop + custom API), traffic generator, metrics harness | 2 |
| P1 Gateway skeleton + S0 | 2–4 | Reverse proxy, candidate extraction, normalisation with caps, JWT verification + JWT attack test suite passing 100% | 2 |
| P2 S1 rules | 3–5 | Coraza + CRS v4, graded anomaly scoring, split paranoia config, baseline measurements | 2 |
| P3 Data pipeline | 3–6 | Corpus assembly, dedup, leakage-safe splitting, labelling tooling | 2 |
| P4 S3 model | 5–9 | Fine-tuning, tokeniser ablation, ONNX + INT8 export, latency benchmarking, calibration | 3 |
| P5 S2 semantic | 6–9 | SQL/JS/shell parsers, parse-tree-diff attack-shape detection | 2 |
| P6 Decision engine | 9–11 | Calibrated combiner, threshold derivation from FPR targets, differentiated responses, circuit breaker | 2 |
| P7 Evaluation | 10–13 | Full protocol §5, adversarial campaign, ablations, baselines | 4 |
| P8 Ops + demo | 12–14 | Dashboard, shadow mode, audit log, live demo, paper | 3 |

Phases overlap; P3/P4/P5 run in parallel after P2.

**Deployment discipline.** Shadow mode first — the gateway observes and scores but never blocks, for a sustained period, with every would-be block reviewed. Then blocking enabled per-route, lowest-risk routes first, with an instant kill switch. Then progressive rollout. No system in this class should go to blocking mode on day one; the false-positive distribution of real traffic is never what the benchmark predicted.

---

## 7. Risks and Honest Limitations

**The cascade may not deliver the predicted escalation rate.** If S1+S2 resolve only 70% of traffic rather than 95%, the latency budget collapses. Mitigation: the escalation rate is measured in P2/P5, before the architecture is committed; if it is bad, the fallback is a character-CNN at S3 (far cheaper, per the `ai-sqli-waf` measurements) with the transformer reserved for an asynchronous out-of-band tier that cannot block but can alert and feed triage.

**Cross-corpus degradation may be severe.** This is the most likely negative result, and it is also the most valuable one to report — the literature has largely not measured it.

**Semantic parsing has dialect coverage gaps.** A MySQL-grammar parser will mis-handle PostgreSQL-specific or MSSQL-specific constructs. Parse coverage per dialect must be measured, and gaps declared.

**Parser differential risk.** If the gateway's JSON/HTTP parsing differs from the backend's, bypasses exist. Differential fuzzing between gateway and backend parsers is a required test, not an optional one.

**Adversarial robustness is unlikely to be solved.** ModSec-AdvLearn improved robustness by up to 85% and did not eliminate the problem [10]. A determined adversary with query access will find the boundary. The honest claim is that the cascade raises the cost of evasion, because an evasion must simultaneously defeat a regex set, a grammar parser, and a learned classifier with different inductive biases — not that it is unevadable.

**Scope.** Second-order injection, fragment-only DOM XSS, and business-logic flaws are not addressed, by construction.

**Reference integrity.** The team's original problem statement cites arXiv:2608.28889 for Musoke et al.; a companion paper by the same authors at arXiv:2608.28882 covers the BERT-GNN architecture specifically. Both exist and both are cited separately here, as [5] and [6]. Three entries in the reference list are flagged ⚠ and must be resolved before submission: [26] (THAI) could not be independently located and may not exist as described — it matters because, if real, it is the nearest prior art to our architecture; [25] (LLM-WAF) is in a low-tier venue whose indexing status should be checked against institutional requirements; and [13] (SafeLine vs ModSecurity detection/FPR figures) comes from practitioner benchmark write-ups rather than peer-reviewed work, so those numbers should be reproduced in our own harness before being presented as established. All arXiv identifiers should be re-verified against the live listing.

**A note on the evidence base.** Several headline numbers in this paper — including the SafeLine FPR comparison and the 89% ModSecurity bypass rate — come from sources of differing rigour. They are directionally consistent with each other and with the peer-reviewed literature, and each is attributed, but the project's own measurements should replace them wherever we can produce them.

---

## 8. Related Work Summary

| # | Approach | Mechanism | Reported performance | Gap this work addresses |
|---|---|---|---|---|
| 1 | ModSecurity + CRS v4 [2], [12] | Hand-written regex signatures → anomaly score | PL1 ~70–82% detection @ ~17–18% FPR; PL4 ~95% @ ~52% FPR [13] | Cannot generalise; FPR/recall cliff; used here as a graded signal, not a verdict |
| 2 | Commercial/cloud WAFs | Managed signatures + reputation + rate limiting | Vendor-reported | Still pattern-based; opaque; bypassed by novel encoding |
| 3 | Semantic-analysis WAF (SafeLine) [13] | SQL/JS/shell grammar parsing of candidate values | ~71.65% detection @ **0.07% FPR** | Excellent FPR, moderate recall — adopted as S2 and composed with a learned stage |
| 4 | WADBERT [4] | Dual-channel URLBERT + SecBERT, hybrid granularity embedding, multi-head attention over parameters | F1 99.63% (CSIC 2010), 99.50% (SR-BH 2020) | Offline only; no latency, no adversarial eval, no cross-corpus, no auth integration |
| 5 | BERT-GNN SQLi [5], [6] | BERT embeddings initialise GNN node features; Optuna tuning | 99.67% acc, 99.55% attack F1, low perturbation sensitivity | SQLi only; offline; inference cost unreported |
| 6 | BERT web-attack detection [7], [8] | Fine-tuned BERT on HTTP requests | >99.98% success, >98.70% F1 reported | Single-corpus; standalone classifier |
| 7 | WAF-A-MoLE [11] | Black-box mutational fuzzer evading ML and rule WAFs | High evasion rates vs. baselines | Defines the adversarial threat; adopted as our red-team tool |
| 8 | ModSec-AdvLearn [10] | Learned CRS rule weights + adversarial training | +30% detection, +85% adversarial robustness, −50% rules | Rule layer only; adopted as S1 optimisation methodology |
| 9 | WAPP [14] | Safe positive-security policy learning from live traffic | 90% poisoning resilience vs 62% baseline | Orthogonal and complementary; adopted as optional S2.5 |
| 10 | open-appsec | Contextual ML scoring, signature-free, production-deployed | Blocked Log4Shell/Spring4Shell preemptively (vendor claim) | Closest production analogue; source of operational patterns, no cryptographic auth layer |
| 11 | **Cascaded NLP for SQLi** [22] | Classical model cascaded into a transformer, motivated by high-speed data centres | 99.86% acc, **20× faster** than transformer-only, 30k+ SQL statements, beats 35 baselines | **Direct prior art for the cascade.** SQLi-only, no semantic-parsing stage, no auth, no cross-corpus or adversarial eval |
| 12 | **ADL-WAF** [19] | Two-layer: Decision Tree anomaly detection → SVM threat classification | 99.88% acc, 100% precision across five benchmarks | Cascade prior art; no latency reported, no routing policy described, no auth layer |
| 13 | **DistilBERT + stacked ensemble** [5] | DistilBERT embeddings → LR/XGBoost/SVM under a neural meta-learner; FGSM hardening; Optuna | 99.81%; head ~140× faster than DistilBERT-SVM; FGSM-resilient | Strongest efficiency+robustness result; SQLi-only; speedup is head-only, encoder cost unaddressed |
| 14 | **Seyyar et al.** [7], [8] | BERT + deep learning on HTTP requests | >99.98% success, >98.70% F1; **0.4 ms** detection time; CSIC 2010, FWAF, HTTPParams | One of very few with a timing number — but mean, offline, not tail latency under load |
| 15 | **Sensors layered WAF** [17] | LSTM layered architecture: DDoS layer → XSS/SQLi layer | 97.57% (DDoS), 89.34% (XSS/SQLi) | Validates "cheap filter first" layering; notably *lower* accuracy, showing layering alone is not sufficient |
| 16 | **CNN+LSTM XSS/SQLi** [28]; **CNN+BiLSTM+attention cmd-injection** [29]; **multiclass HTTP injection DL** [30] | Pre-transformer deep learning across all three injection families | 99.84/99.23/99.77%; 99.3% acc, 98.2% recall; multiclass URL+body | Baselines the transformer must beat; [29] is the rare dedicated command-injection treatment |
| 17 | **GenSQLi** [21] | GPT-4o generates + validates SQLi payloads, tests against WAF, synthesises new rules | 514 payloads, 92.5% functional, **89% bypassed ModSecurity** | Defines the generated-attack threat and our evaluation methodology |
| 18 | **LLM-generated obfuscated XSS** [27] | LLM obfuscation + browser-runtime behaviour verification | Behaviour match 0.15 → 0.22 fine-tuned; generated payloads **did not** improve detection | Critical negative result: behaviour-filter generated data or it is noise |
| 19 | **LLM-WAF** [25]; **LLM-AE-MP** [24] | Full LLM semantic inspection of HTTP traffic | 96.8% acc, 0.95 F1 (CSIC 2010 + real traffic) | Lower than compact encoders — evidence against scaling the model as the answer |
| 20 | **Applebaum et al. survey** [16]; **XAI systematic review** [20] | Survey of signature vs ML vs hybrid WAFs; systematic review of XAI for web threat detection | Identifies hybrid as the path; names dataset constraints, computational overhead, missing deployment evidence as open problems | Independent confirmation of this paper's framing |

**The composite gap:** no existing system combines graded deterministic rules, grammar-aware semantic analysis, a learned semantic classifier, and correct cryptographic token verification in a single inline component with a measured latency budget and an evaluation protocol that includes cross-corpus and adversarial testing. That composition is what CSF proposes.

---

## 9. Conclusion

The injection-detection literature has converged on an answer (transformers classify malicious requests very accurately) to a question that is not the deployment bottleneck. The bottleneck is the joint constraint: high recall *and* a false-positive rate low enough to run in blocking mode *and* a tail latency that fits the request path *and* robustness to an adversary who can query you *and* an authentication layer that is not itself forgeable. Each of those has been solved in isolation. CSF's thesis is that they are solved *together* by a cost-ordered cascade with calibrated escalation, where each stage contributes a different inductive bias and the expensive stage is invoked rarely enough to be affordable.

The measurable claims are: cross-corpus recall at a fixed 0.1% FPR within 10 points of in-corpus; p99 added latency under 10 ms with an S3 escalation rate under 5%; WAF-A-MoLE evasion under 15%; and a 100% pass on the JWT attack suite. These are falsifiable, and the evaluation protocol in §5 is designed so that they cannot be met by accident.

---

## References

*All identifiers verified against live sources on 2026-10-01 except where marked. Entries marked ⚠ require independent verification before submission.*

**Foundations and standards**

[1] OWASP Foundation, "OWASP Top 10:2021 — A03:2021 Injection," 2021. https://owasp.org/Top10/A03_2021-Injection/

[2] OWASP Foundation, "OWASP Core Rule Set," coreruleset.org; OWASP Coraza WAF, coraza.io; "ModSecurity Reference Manual," github.com/owasp-modsecurity/ModSecurity.

[3] M. Jones, J. Bradley, and N. Sakimura, "RFC 7519: JSON Web Token (JWT)," IETF, 2015; M. Jones, "RFC 7518: JSON Web Algorithms (JWA)," IETF, 2015; Y. Sheffer, D. Hardt, and M. Jones, **"RFC 8725: JSON Web Token Best Current Practices,"** IETF, 2020. https://www.rfc-editor.org/rfc/rfc8725.html

**Transformer and LLM-based detection**

[4] K. Luo, Y. Xie, S. Zhao, and J. Pan, "WADBERT: Dual-channel Web Attack Detection Based on BERT Models," arXiv:2601.21893. https://arxiv.org/abs/2601.21893

[5] L. L. Musoke, A. Badii, and A. Ashlam, "Enhancing Web Application Firewalls with Machine Learning for SQL Injection Detection," Univ. of Reading, arXiv:2608.28889. *DistilBERT embeddings + stacked LR/XGBoost/SVM ensemble with neural meta-learner; 99.81%; ensemble head ~140× faster than DistilBERT-SVM (0.0136 s vs 1.896 s on the full test set); FGSM-hardened; Optuna-tuned.* https://arxiv.org/abs/2608.28889

[6] L. L. Musoke, A. Badii, and A. Ashlam, "Enhancing Web Application Firewalls with BERT-GNN for SQL Injection Detection," arXiv:2608.28882. *99.67% acc, 99.71% prec, 99.39% rec, 99.55% F1 (attack class); mean perturbation sensitivity 0.0037; dataset and models public.* https://arxiv.org/abs/2608.28882

[7] Y. E. Seyyar, A. G. Yavuz, and H. M. Ünver, "An Attack Detection Framework Based on BERT and Deep Learning," **IEEE Access, vol. 10, pp. 68633–68644, 2022.** DOI: 10.1109/ACCESS.2022.3185748. *>99.98% success, >98.70% F1; 0.4 ms detection time.*

[8] Y. E. Seyyar, A. G. Yavuz, and H. M. Ünver, "Detection of Web Attacks Using the BERT Model," Proc. 30th IEEE Signal Processing and Communications Applications Conf. (SIU), Safranbolu, Turkey, 2022. *CSIC 2010, FWAF, HTTPParams.*

[9] S. Salim and L. Oughdir, "A BERT-Enhanced Exploration of Web and Mobile Request Safety through Advanced NLP Models and Hybrid Architectures," IEEE Access, vol. 12, pp. 76180–76193, 2024.

[23] B. Ben Ammar and A. M. Alharbi, "SQL Injection Detection Using Fine-Tuned CodeBERT," Engineering, Technology & Applied Science Research, 2025. DOI: 10.48084/etasr.13340. *99.90% acc, 99.96% prec, 97.75% rec, 99.86% F1.*

[24] "LLM-AE-MP: Web Attack Detection Using a Large Language Model with Autoencoder and Multilayer Perceptron," Expert Systems with Applications, 2025. DOI: 10.1016/j.eswa.2025.126982

[25] Y. Khalaf (Zarqa Univ., College of Cyber Security), "LLM-WAF: An Intelligent Web Application Firewall Powered by Large Language Models for Advanced Threat Detection," Int. J. of Wireless and Microwave Technologies (IJWMT), vol. 16, no. 4, 2026. DOI: 10.5815/ijwmt.2026.04.18. *96.8% acc, 0.95 F1 on CSIC 2010 + real traffic.* ⚠ Low-tier venue — check indexing requirements before using as a central citation.

[26] K. K. Paul, "Two-Phase Hybrid Asynchronous Inspection (THAI): A Latency-Agnostic Framework for Intelligent Malicious HTTP Request Detection using Large Language Models," SSRN working paper, 2026. ⚠ **Not independently locatable in our searches.** SSRN preprint, not peer-reviewed. Verify it exists and read it before citing — if genuine it is the nearest prior art to our architecture and must be engaged with directly.

**Pre-transformer deep learning baselines**

[28] F. M. M. Mokbal et al. / authors per record, "Securing Web Applications Against XSS and SQLi Attacks Using a Novel Deep Learning Approach," Scientific Reports, 2024. DOI: 10.1038/s41598-023-48845-4. *CNN+LSTM; 99.84% / 99.23% / 99.77% on payload dataset, custom testbed, CSIC 2010.*

[29] "Detecting Command Injection Attacks in Web Applications Based on Novel Deep Learning Methods," Scientific Reports, 2024. DOI: 10.1038/s41598-024-74350-3. *CNN+BiLSTM+attention; 99.3% acc, 98.2% recall.*

[30] "Deep-Learning Based Injection Attacks Detection Method for HTTP," Mathematics, vol. 10, no. 16, 2914, 2022. DOI: 10.3390/math10162914. *Multiclass SQLi/XSS/command injection from URL and body features.*

**Hybrid, cascaded, and layered WAF architectures**

[16] S. Applebaum, T. Gaber, and A. Ahmed, "Signature-based and Machine-Learning-based Web Application Firewalls: A Short Survey," Procedia Computer Science, 2021. DOI: 10.1016/j.procs.2021.05.105

[17] B. R. Dawadi, B. Adhikari, and D. K. Srivastava, "Deep Learning Technique-Enabled Web Application Firewall for the Detection of Web Attacks," Sensors, vol. 23, no. 4, 2073, 2023. DOI: 10.3390/s23042073. *LSTM layered: 97.57% (DDoS layer), 89.34% (XSS/SQLi layer).*

[19] "Adaptive Dual-Layer Web Application Firewall (ADL-WAF) Leveraging Machine Learning for Enhanced Anomaly and Threat Detection," arXiv:2511.12643. *DT → SVM; 99.88% acc, 100% precision; no latency reported.* https://arxiv.org/abs/2511.12643

[22] "Advancing SQL Injection Detection for High-Speed Data Centers: A Novel Approach Using Cascaded NLP," arXiv:2312.13041. *Classical model cascaded into transformer; 99.86% acc, 20× faster than transformer-only; 30,000+ SQL statements; outperforms 35 baselines.* **Direct prior art for the cascade.** https://arxiv.org/abs/2312.13041

[34] "Machine Learning-Based Web Application Firewall for Real-Time Threat Detection," Proc. IEEE ICEI, 2024. DOI: 10.1109/ICEI64305.2024.10912239. *XGBoost inline in front of the web server; SQLi, XSS, LFI.*

**Adversarial, generative, and robustness**

[10] B. Montaruli et al., "ModSec-AdvLearn: Countering Adversarial SQL Injections with Robust Machine Learning," arXiv:2308.04964. *+30% detection, +85% adversarial robustness, −50% rules.* Code: https://github.com/pralab/modsec-advlearn

[11] L. Demetrio, A. Valenza, G. Costa, and G. Lagorio, "WAF-A-MoLE: Evading Web Application Firewalls through Adversarial Machine Learning," arXiv:2001.01952.

[21] "GenSQLi: A Generative Artificial Intelligence Framework for Automatically Securing Web Application Firewalls Against SQL Injection Attacks," Future Internet, vol. 17, no. 1, 8, 2025. DOI: 10.3390/fi17010008. *GPT-4o; 514 payloads generated, 92.5% validated against MySQL, **89% bypassed ModSecurity** with current rules; generative rule synthesis blocked a large fraction on re-test.*

[27] D. Gabbireddy and S. Saha, "Evaluating LLM-Generated Obfuscated XSS Payloads for Machine Learning-Based Detection," arXiv:2604.19526. *Runtime behaviour match 0.15 baseline → 0.22 fine-tuned; adding generated payloads did **not** improve detection; behaviour-filtered samples were neutral.* https://arxiv.org/abs/2604.19526

[35] "Automated WAF Rule Generation from Adversarial Prompt Pattern Mining for Perimeter-Level Protection of LLM Applications," Electronics, vol. 15, no. 19, 4416, 2026. DOI: 10.3390/electronics15194416

**Evaluation methodology, surveys, and positive security**

[18] "Assessing Generalisation Capability of Machine Learning Models for Intrusion Detection," arXiv:2605.04407. https://arxiv.org/abs/2605.04407

[20] "Explainable Artificial Intelligence for Web Application Threat Detection: A Systematic Review," Artificial Intelligence Review, 2026. DOI: 10.1007/s10462-026-11581-y. *Identifies dataset constraints, computational overhead, and absent real-world deployment evidence as the field's principal gaps; warns that cross-study comparison is unreliable.*

[14] "WAPP: Safe Learning of Positive Security WAF Policies from Live Traffic," arXiv:2609.06840. *90% poisoning resilience vs 62% baseline; unfiltered learning fails at 0.5% poisoned traffic.* https://arxiv.org/abs/2609.06840

[12] OWASP CRS Project, "Paranoia Levels" and "Working with Paranoia Levels." https://coreruleset.org/docs/2-how-crs-works/2-2-paranoia_levels/

[13] Comparative WAF evaluations of SafeLine, Cloudflare, and ModSecurity (detection rate vs. false-positive rate across paranoia levels 1–4). SafeLine semantic-analysis engine: https://github.com/chaitin/SafeLine ⚠ Figures are from practitioner benchmark write-ups, not a peer-reviewed study — reproduce them in our own harness before citing as fact.

**JWT and API authentication security**

[39] "Security Assessment of JWKS-Based Authentication: Mitigating JWT Attack Vectors Through Penetration Testing," Jurnal Teknik Informatika (JUTIF), vol. 7, no. 2, 2026. DOI: 10.52436/1.jutif.2026.7.2.5662. *RS256→HS256, alg=none, kid injection, claim manipulation.*

[36] "Analysis and Mitigation of JWT and OAuth 2.0 Vulnerabilities in REST APIs," Radiotekhnika, 2026. DOI: 10.30837/rt.2026.2.225.05

**Models, serving, and infrastructure**

[15] E. Aghaei et al., "SecureBERT: A Domain-Specific Language Model for Cybersecurity"; "SecureBERT 2.0," arXiv:2510.00240. https://huggingface.co/ehsanaghaei/SecureBERT

[31] P. Schmid, "Static Quantization with Hugging Face Optimum for ~3x Latency Improvements." *DistilBERT SST-2 INT8 ONNX: p50 18.8 ms / p99 19.2 ms, 4.06× speedup, 256 MB → 65 MB.* https://www.philschmid.de/static-quantization-optimum

[32] Transformer inference latency benchmark: PyTorch vs TorchScript vs ONNX Runtime vs INT8. *ONNX FP32 5.66 ms p50 vs eager 8.95 ms; INT8 8% slower than FP32 on Apple Silicon.* https://github.com/SaiArrow/inference-lab

[33] Envoy Proxy, "External Processing Filter (ext_proc)." https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter

[37] open-appsec, "Open-source ML-based WAF." https://www.openappsec.io/ · https://github.com/openappsec

[38] Datasets: HTTP CSIC 2010; ECML/PKDD 2007; SR-BH 2020; FWAF; HTTPParams (Kaggle); SQL Injection Dataset, 30,919 instances (Kaggle); PayloadsAllTheThings; FuzzDB.
