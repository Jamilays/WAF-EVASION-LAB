# TODO — parked work

Items that would improve the lab but take more than a quick session. Listed
in rough priority order (top = most valuable-per-hour, bottom = largest).

---

## Medium-term (1–2 days each)

### 1. Replicate the original 40-payload subset

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

### 2. Publish replication paper

We have enough data for a short replication report:
- Abstract + Intro can cite our numbers vs the paper's
- Methodology is already in `report.md` (auto-generated)
- Results section writes itself from the CSVs
- Discussion: where modern CRS has closed gaps, where they persist

**Scope:** ~a week to draft, another week to iterate with reviewers.

---

### 3. Real shadowd integrity + whitelist experiments

Shadow Daemon has three engines: blacklist (what we use), integrity
(hash-based), whitelist (allow-list). The lab currently only exercises
blacklist. The other two are radically different WAF architectures —
whitelist in particular has different bypass mechanics (can you sneak
through the allowed input shape?).

**Scope:** requires learning-mode warmup on each target, populating
whitelist rules from legit traffic, then running the corpus.

---

### 4. Response-side fingerprinting

Currently we record the WAF's response status + a snippet of the body.
Richer fingerprinting (WAF name via `Server` header, rule IDs if
ModSecurity logs them, latency distributions) would let the dashboard
show *why* each WAF blocked. CRS logs rule IDs — we just need to parse
them from the `debug` logs or lift them from the response body when the
WAF echoes them.
