# TODO

Research roadmap. Items grouped by priority band; within each band, roughly
ordered by impact-per-hour. **After a task is resolved, delete its entry from
this file in the same commit that lands the change** — TODO.md should always
reflect the current queue, not a history of completed work (git log is for
history).

---

## Resolved this session (2026-04-29) — kept here for one cycle, then delete

The 2026-04-29 work landed four significant items at once:

- **AZTU 2026 conference deliverables** — the paper folder moved from
  `results/reports/paper-yusifova-2026/` to
  [`RESEARCH/paper-yusifova-2026/`](RESEARCH/paper-yusifova-2026/) and
  picked up a 19-slide [presentation.pptx](RESEARCH/paper-yusifova-2026/presentation.pptx)
  + matching PDF export, plus a 5-minute speaker script
  ([speech.md](RESEARCH/paper-yusifova-2026/speech.md)). Both artefacts
  reproduce from inline source in [RESEARCH/build/build.js](RESEARCH/build/build.js)
  via a `pptxgenjs` toolchain (`node build.js` + `soffice --convert-to pdf`).
  Every visual on the main deck — architecture diagram, headline heatmap,
  mutator example panel, compositional bar chart, recommendation
  quadrants — is drawn shape-by-shape in a custom cream / burgundy / gold
  palette, no matplotlib screenshots. The 9 appendix slides keep the
  matplotlib figures as Q&A back-up.


- **P0.1 (FPR as first-class column)** — the new consolidated headline
  reporter (`wafeval report-headline`, `engine/src/wafeval/reporter/consolidated.py`)
  emits a per-WAF *Attack vs FPR* table fusing the attack run with a
  paired benign run (`--benign-run-id`). The right-most column is
  `block-attack ÷ block-benign`, which is the operationally usable
  trade-off proxy. Open follow-up: the canonical ROC scatter (FPR×bypass
  per (WAF × paranoia)) is *not* yet in the consolidated report, only
  the table; and the benign corpus is still 15 entries — expand to ~100
  for tighter Wilson CIs on FPR.
- **P0.2 (fresh 4-WAF combined run)** — superseded by the consolidated
  headline run set (`headline-v2-20260429`) which fuses
  `attack-v2-20260429T030310Z` + `adaptive-v2-20260429T032000Z` +
  `benign-v2-20260429T032003Z` and produces a richer 11-section report
  than the older `report-combined`. The Coraza rule-ID headers are
  captured on every blocked record automatically (no reporter work
  needed; they live on `VerdictRecord.waf_route.waf_headers`).
- **P1.3 (modern bypass techniques)** — partially addressed via the
  corpus expansion. Eight thin classes (CRLF, SSRF, LDAP, NoSQL, JNDI,
  GraphQL, SSTI, XXE) went from 10–15 entries each to 25 entries each;
  total corpus 201 → 297. The new payloads cover modern dialects:
  cloud-metadata bypasses (decimal/hex/octal/IPv6 IP; AWS/GCP/Azure/DO/Alibaba),
  Log4Shell obfuscations (env / sys / date / marker lookups, base64 +
  URL-encoded variants, JNDI-Exploit-Kit gadgets), GraphQL alias-overload /
  fragment-cycle / nested-injection chains, MongoDB 4.4+ `$function` and
  mapReduce, AD-specific LDAP (extensibleMatch, OID matching rules),
  CSP/CORS/cache-poisoning CRLF chains, Pug / Mako / Handlebars / Spring
  SpEL SSTI gadgets, OOB / SVG / OOXML / UTF-7/16 XXE. Still open:
  HTTP/2 request smuggling, path-normalisation differentials,
  Content-Type confusion, chunked-encoding edges, prototype pollution
  on Juice Shop (Node). These warrant their own dedicated `smuggling.yaml`
  and a transport-layer rework (Traefik h2c entrypoint).

---

## P0 — highest impact, small-to-medium scope

*(items 1 + 2 resolved above this cycle)*

---

## P1 — high impact, medium scope

*(item 3 partially resolved above this cycle — the corpus expansion
covered the dialect breadth; transport-layer items remain open as
their own future ticket.)*

### 4. Statistical rigor for write-up

Currently we emit Wilson CIs and nothing else. For a publishable paper:

- Bootstrap CIs on per-payload bypass rates (compare with Wilson —
  they disagree at small N).
- McNemar's test on matched `(payload, WAF_A, WAF_B)` triples to say
  "WAF_A is significantly stronger than WAF_B on this corpus" with a
  p-value.
- Per-(vuln_class × mutator) interaction plot with Bonferroni or BH
  correction for the ~60 pairwise tests.
- Report effect sizes (Cohen's h for proportions), not just p-values.

Analyzer module: `engine/src/wafeval/analyzer/stats.py`. Reporter
appendix: Appendix C — Statistical tests.

### 5. Payload templating / bytecode fuzzing

Current corpus is fixed strings. Introduce templates with holes:

```yaml
- id: sqli-template-union-N
  template: "1' UNION SELECT {col1},{col2} -- -"
  slots: { col1: [null, version(), user(), "0x41"], col2: [...] }
```

Loader expands to all combinations. Easy 10x coverage without
handwriting new payloads. Also ships the primitive for an AFL-style
byte-level mutator that does random splicing within an attack-safe
envelope.

### 6. Genetic / reinforcement-learning mutator

The adaptive mutator's seed-ranked pairs are a step 1. A proper GA:

- Fitness = (bypass_rate × (1 − latency_penalty)).
- Each generation produces N new variants from top-K parents.
- Crossover: splice body halves from two parents.
- Mutation: random char insertion / deletion / encoding flip.
- Stop when bypass plateaus for K generations.

Publishable territory — "we found a novel bypass for CRS 942100 via
GA, confirmed across modsec + coraza". Module:
`engine/src/wafeval/mutators/genetic.py`; needs a seed-fitness feedback
loop that the current `RunConfig` doesn't expose.

---

## P2 — medium impact, medium scope

### 7. Per-payload drilldown in dashboard

Payload Explorer currently filters + drills into one record. Missing:

- "Show full request pair" — we currently show response snippet but
  not the exact request bytes we sent (important for reproducing
  manually via curl).
- "Show every variant of this payload" in one pane.
- "Show every WAF's response for this variant" side-by-side (4-WAF
  cross-comparison at the record level).

### 8. Rule-ID aggregation dashboard tab

Coraza now emits rule IDs on every block. The dashboard should
aggregate:

- Histogram "which CRS rules fire the most" across all blocked
  records in a run.
- Clickable: filter the Payload Explorer to records blocked by rule X.
- Per-rule bypass-vs-catch breakdown (payloads that matched the same
  rule but one was allowed vs. blocked — surfaces rule-logic gaps).

### 9. Request/response timeline chart

Scatter plot: x = variant, y = latency, colour = verdict. Surfaces
timing-side-channel patterns at a glance. Lives on a new dashboard
tab or as a figure in the Markdown report.

### 10. Response-phase exploits

- Timing oracle: build a latency-harness that measures response ms
  across a pool of timing-based SQLi payloads, distinguishes
  conditional delay (blind SQLi working) from baseline noise.
- Error-based DB fingerprinting: craft payloads that extract backend
  version strings, verify they round-trip through each WAF.
- Out-of-band (OOB) DNS exfil: stand up a DNS listener in the lab
  network, seed payloads that dial out, count requests received.

---

## P3 — larger scope / research extensions

### 11. More WAFs

- **NAXSI** — nginx module, signature-based but with allowlist mode.
  Architecturally distinct from CRS; interesting foil.
- **BunkerWeb** — nginx + CRS + custom plugin stack. Defence-in-depth
  comparator.
- **SafeLine WAF (Chaitin)** — open-source, semantic analysis engine,
  rising popularity. Needs a new reverse-proxy setup.
- **Wallarm "Node" open parts** — investigate scope.
- Commercial trials via API (different legal footing, separate tier):
  Cloudflare free tier, AWS WAF free rules.

### 12. Longitudinal regression study

Run the full corpus quarterly against pinned WAF image tags. Plot
bypass rate over CRS versions (4.0 → 4.5 → 4.10 → 4.25 → …). Needs:

- `make run-with-tag WAF_TAG=<image:tag>` target that swaps the
  coraza-crs / modsec-crs image for a run.
- `results/longitudinal/` tree tracked by DVC.
- A new analyzer module that plots bypass rate vs. CRS release date.

### 13. Coraza rule-ID parity via audit-log for ModSec

Coraza emits rule IDs via the custom `X-Coraza-Rules-Matched` header.
ModSec's upstream nginx image doesn't expose equivalent metadata. To
reach parity:

- Mount the ModSec container's `SecAuditLog` directory as a volume.
- Configure JSON audit-log format + a request-id correlation header.
- Engine tails the audit log post-run, joins rule IDs onto records by
  request-id. Surfaces under `waf_headers['x-modsec-rules-matched']`
  for uniform dashboard rendering.
- Alternative: fork the modsecurity-crs image to emit rule IDs
  directly in response headers (bigger blast radius).

### 14. Coraza response-phase (CRS phase 3/4) processing

`wrapWAFWithRuleIDs` in `wafs/coraza/main.go` currently skips the
response-phase interceptor that upstream `corazahttp.WrapHandler`
provides. This means outbound-rule blocks (data-leakage detections,
CRS 950xxx family) are silently not exercised. Port the response
interceptor across or rethink: most CRS attack-rules are request-side,
so this is cosmetic today, but it's a correctness gap in the
"Coraza matches ModSec behaviour" story.

### 15. Shadowd canonical-baseline whitelist from learning-mode

`tests/shadowd_whitelist.sh` uses hand-crafted whitelist rules for one
DVWA endpoint. Broaden:

- Script that drives legit traffic through every target for K minutes
  in MODE_LEARNING.
- Promotion step: `INSERT INTO whitelist_rules SELECT ... FROM
  parameters ...` deriving rules from observed typical-input shapes
  and length distributions.
- Run the full corpus against the learned ruleset; compare bypass rate
  against hand-crafted ruleset and against pure-blacklist.

### 16. Research-ergonomics: results/canonical/ under DVC

Headline runs that back the paper deserve versioning.
`results/raw/` stays untracked (big); but the 3-4 runs that underpin
Table 1 belong in `results/canonical/` under DVC so the paper is
bit-reproducible.

---

## P4 — developer experience

### 17. Dashboard export-to-CSV

Buttons on Results / Hall of Fame / Cross-WAF tabs to download the
current view as CSV. Enables reviewers to load the data into their own
tools without learning the API.

### 18. Engine-image-rebuild reminder

Already called out in README ("⚠ Rebuild the engine image after
editing `targets.yaml` or any payload YAML") but not enforced. Simple
pre-run check in `docker compose --profile engine run`: compare the
image's build time vs. the mtime of `engine/src/wafeval/targets.yaml`
+ `payloads/*.yaml`, warn if stale.
