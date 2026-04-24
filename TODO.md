# TODO

Items that would improve the lab but take more than a quick session. Listed
in rough priority order (top = most valuable-per-hour, bottom = largest).

---

### 1. Real shadowd integrity + whitelist experiments

Shadow Daemon has three engines: blacklist (what we use), integrity
(hash-based), whitelist (allow-list). The lab currently only exercises
blacklist. The other two are radically different WAF architectures —
whitelist in particular has different bypass mechanics (can you sneak
through the allowed input shape?).

**Scope:** requires learning-mode warmup on each target, populating
whitelist rules from legit traffic, then running the corpus.

---

### 2. Response-side fingerprinting

Currently we record the WAF's response status + a snippet of the body.
Richer fingerprinting (WAF name via `Server` header, rule IDs if
ModSecurity logs them, latency distributions) would let the dashboard
show *why* each WAF blocked. CRS logs rule IDs — we just need to parse
them from the `debug` logs or lift them from the response body when the
WAF echoes them.

---

### 3. `make report-host` doesn't auto-reexec under nix-shell

[tests/_lib.sh:9](tests/_lib.sh#L9) self-reexecs phase scripts under
`nix-shell -p stdenv.cc.cc.lib zlib` so the venv's numpy/pandas C
extensions can find `libstdc++.so.6` and `libz`. The Makefile targets
that run the same venv directly (`report-host`, and any other
host-venv target) skip this and crash with:

```
ImportError: libstdc++.so.6: cannot open shared object file
```

Workaround that works today:

```
nix-shell -p gnumake stdenv.cc.cc.lib zlib --run '
  LD_LIBRARY_PATH=$(nix-build --no-out-link "<nixpkgs>" -A stdenv.cc.cc.lib)/lib:$(nix-build --no-out-link "<nixpkgs>" -A zlib)/lib:$LD_LIBRARY_PATH \
  make report-host RUN_ID=...'
```

**Scope:** factor the reexec out of `tests/_lib.sh` into a small
wrapper (e.g. `scripts/with-nix-libs`) and have the Makefile's
host-venv targets invoke the venv through it. One-time fix; removes
the NixOS papercut for `make report-host` / `make test-engine`.
