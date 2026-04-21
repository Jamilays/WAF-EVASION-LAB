# TODO — parked work

Items that would improve the lab but take more than a quick session. Listed
in rough priority order (top = most valuable-per-hour, bottom = largest).

---

## Immediate follow-ups from the open-appsec integration

### Consolidated 4-WAF research report

We now have three separate run_ids that together form the complete
4-WAF × 2-target × 12-class comparison the prompt originally asked for:

- `research-20260421T141410Z` — ModSec PL1, Coraza PL1, Shadow Daemon
- `paranoia-high-20260421T151636Z` — ModSec PL4, Coraza PL4
- `openappsec-20260421T162710Z` — open-appsec (minimum-confidence=critical)

The reporter currently writes one report per run. For a publishable
comparison we need a **cross-run aggregator** that:

- Accepts multiple `--run-id` arguments, merges their `bypass_rates.csv`
  into a single table (waf × mutator × target)
- Produces a headline Table 1 with columns `modsec / coraza / shadowd /
  openappsec / modsec-ph / coraza-ph`
- Emits `report-combined.md` + `report-combined.tex` suitable for the
  paper's Results section
- New endpoint `/runs/combined?ids=a,b,c` so the dashboard can surface
  this without the user eyeballing three tables

**Effort:** ~half a day. Mostly analyzer plumbing; data already exists.

**Key finding to capture in the write-up** (openappsec-20260421T162710Z):
- open-appsec × DVWA → **0% bypass** across every class (2217 attacks,
  all caught by the ML classifier)
- open-appsec × Juice Shop → **40–74% bypass** on nearly every WAF-view
  class (crlf 65%, ssrf 74%, nosql 59%, ldap 51%, jndi 45%); SQLi stays
  at 2.6%. The ML model is evidently well-trained on DVWA-style PHP
  attack patterns but under-weights SQLite-dialect / JSON-operator /
  scheme-based payloads on the JSON API.

---

### open-appsec minimum-confidence ladder ablation

`wafs/openappsec/localconfig/local_policy.yaml` currently sets
`minimum-confidence: critical` (strictest — fewest FPs, most missed
attacks). Drop through `high` → `medium` → `low`, rerun each time,
plot the bypass-rate vs false-positive-rate curve. This is the **ML
equivalent of the CRS paranoia ablation** ([TODO #4 below](#4-paranoia-level-ablation-on-all-4-wafs))
and would make the paper's Discussion section.

**Effort:** ~30 min per confidence level (4 rerun × ~8 min plus policy
reload); total ≤ 2 hours.

---

### Dashboard heatmap: surface all 4 WAFs side-by-side

Dashboard Results tab currently shows one run at a time. Add a "Cross-WAF"
view that picks the latest run per WAF and renders a 4-column heatmap.
Needs the cross-run API endpoint above plus a new tab component. Tie it
to the consolidated report so every published figure has a dashboard
equivalent.

**Effort:** ~2 hours after the cross-run aggregator is in.

---

## Near-term (half-day each)

### 1. Restore WebGoat with real lesson endpoints

Current state: WebGoat is booted but has no endpoints wired in
`targets.yaml` because hitting `/WebGoat/login` didn't trigger any real
sink. The paper matrix is 4 WAFs × 3 targets; we're at 4 × 2.

**What's needed:**
- Seed a WebGoat account + cookie bootstrapper (similar to the DVWA one)
- Call `POST /WebGoat/service/restartlesson.mvc` to activate a lesson
- Add endpoints for SqlInjection/assignment5a (SQLi), CrossSiteScripting/attack5a (XSS)
- Verify triggers: WebGoat returns JSON with `lessonCompleted: true` on success
- Extend `load_dvwa_session` → a `load_webgoat_session` sibling

**Effort:** ~half a day, mostly figuring out the WebGoat lesson API.

---

### 2. Split `allowed_with_marker` vs `allowed_sanitized`

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

---

## Medium-term (1–2 days each)

### 3. Adaptive / genetic mutator

Current mutators emit fixed variants. An `adaptive.py` mutator would:
- Observe which transforms bypass per WAF
- Iterate: swap + compose successful transforms into new variants
- Stop when bypass rate plateaus or max-iterations hit

Cleanly pluggable under the existing `@register` contract. This is
paper-grade "WAFs can't keep up with evolving attackers" material.

**Scope:** mutator class + small offline learner (scikit-learn's
`DecisionTreeClassifier` on bypass features is enough to start).

---

### 4. Paranoia-level ablation on all 4 WAFs

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

### 5. Commercial WAF comparison

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

### 6. Replicate the paper's original 40-payload subset

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
