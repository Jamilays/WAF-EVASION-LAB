# TODO — parked work

Items that would improve the lab but take more than a quick session. Listed
in rough priority order (top = most valuable-per-hour, bottom = largest).

---

## Near-term (half-day each)

### 1. Split `allowed_with_marker` vs `allowed_sanitized`

Current verdict `ALLOWED` lumps together:
- WAF passed the request, payload triggered at the sink (real bypass), AND
- WAF passed the request, but the response didn't carry the expected marker
  (silent transform — e.g. removed `<script>`, stripped quotes).

**What's needed:**
- Bundle 2's classifier already has the logic (checks WAF-side marker),
  but emits `BLOCKED` for the sanitized case. Split into new verdict
  `BLOCKED_SILENT` so the analyzer can show this as a third category.
- Dashboard heatmap: three colours (block / silent-block / bypass).

---

## Medium-term (1–2 days each)

### 2. Adaptive / genetic mutator

Current mutators emit fixed variants. An `adaptive.py` mutator would:
- Observe which transforms bypass per WAF
- Iterate: swap + compose successful transforms into new variants
- Stop when bypass rate plateaus or max-iterations hit

Cleanly pluggable under the existing `@register` contract. This is
paper-grade "WAFs can't keep up with evolving attackers" material.

**Scope:** mutator class + small offline learner (scikit-learn's
`DecisionTreeClassifier` on bypass features is enough to start).

---

### 3. Paranoia-level ablation on all 4 WAFs

We already have `--profile paranoia-high` and a PL1 vs PL4 comparison. The
natural extension: PL1 / PL2 / PL3 / PL4 ablation with same corpus,
reported as a single table. Tells a reader "the false-positive / bypass
trade-off at each level". Also useful material for the `analyzer/` to
present the trade-off as a Pareto curve.

**What's needed:**
- Compose profiles for PL2 + PL3 (currently we have PL1 default and PL4)
- Three extra runs (~20 min each at current MAX_CONCURRENCY=4)
- Reporter: new "paranoia-tradeoff" figure

---

### 4. Commercial WAF comparison

The comparison every reviewer asks for: AWS WAF, Cloudflare managed rules,
Azure WAF. Needs cloud accounts + paid-tier rulesets.

**Blockers:**
- Requires AWS / Azure / Cloudflare accounts with WAF enabled.
- Cost: ~$5-20/month per WAF in lowest tier. Budget.
- Each has a completely different config model; wrapping them behind the
  same `Host: <waf>-<target>.local` contract needs per-provider adapters.

Non-starter for a local lab, but worth planning for the cloud-hosted
companion paper.

---

### 5. Benign-traffic corpus for true FPR / ROC curves

The open-appsec confidence-ladder ablation came out flat (bypass rate
≈constant across `critical → high → medium → low`) because every payload
in the current corpus is an attack. To measure the real trade-off — each
level's bypass rate *against its false-positive rate* — we need a benign
payload source.

**What's needed:**
- A second YAML corpus under `engine/src/wafeval/payloads/` holding benign
  traffic shaped like the real sinks (login form posts, product search
  terms, path components, typical JSON API bodies)
- Engine wiring so a run can operate over "benign" mode (same routes,
  verdict flipped: `ALLOWED` is success, `BLOCKED` is a false positive)
- `wafeval ladder --fpr-run <benign-run-id>` second axis so the line
  chart becomes bypass-rate (from attacks) vs FPR (from benign). With
  this, the open-appsec ladder should produce a recognisable ROC shape.

Cleanly pluggable into the existing aggregator — no schema changes to
the raw record format.

---

### 6. Replicate the original 40-payload subset

The paper used 20 SQLi + 20 XSS, specific entries. Running JUST those in
our engine (ignoring the 161 we added) gives an apples-to-apples
reproduction number for the Discussion section.

**What's needed:**
- Curate the paper's exact payloads into `payloads/paper_subset.yaml`
- CLI flag `--corpus paper_subset` (already have `--classes`; just a new
  loader arg)
- Dedicated phase acceptance script.

---

## Long-term / aspirational

### 7. Publish replication paper

We have enough data for a short replication report:
- Abstract + Intro can cite our numbers vs the paper's
- Methodology is already in `report.md` (auto-generated)
- Results section writes itself from the CSVs
- Discussion: where modern CRS has closed gaps, where they persist

**Scope:** ~a week to draft, another week to iterate with reviewers.

---

### 8. Real shadowd integrity + whitelist experiments

Shadow Daemon has three engines: blacklist (what we use), integrity
(hash-based), whitelist (allow-list). The lab currently only exercises
blacklist. The other two are radically different WAF architectures —
whitelist in particular has different bypass mechanics (can you sneak
through the allowed input shape?).

**Scope:** requires learning-mode warmup on each target, populating
whitelist rules from legit traffic, then running the corpus.

---

### 9. Response-side fingerprinting

Currently we record the WAF's response status + a snippet of the body.
Richer fingerprinting (WAF name via `Server` header, rule IDs if
ModSecurity logs them, latency distributions) would let the dashboard
show *why* each WAF blocked. CRS logs rule IDs — we just need to parse
them from the `debug` logs or lift them from the response body when the
WAF echoes them.
