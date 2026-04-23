"""Adaptive (compositional) mutator.

Stacks pairs of the three string-body base mutators (``lexical``,
``encoding``, ``structural``) to produce variants no single category can
reach. The core research hypothesis (TODO.md #1 "adaptive / genetic
mutator"): a WAF tuned to catch, say, single-layer URL encoding can still
be defeated by lexical casing *applied on top of* encoded output — and the
lab should be able to systematically produce those stacks.

Two modes, both invoked via the standard ``Mutator`` contract
(``mutate(payload) -> list[MutatedPayload]``). The engine instantiates
mutators with no args, so parameters come in through env vars.

* **Default (no seed)** — emit every ordered (A, B) pair where A != B,
  capped by ``ADAPTIVE_TOP_K`` (default 6 = all pairs). Variant count per
  payload is bounded by ``_A_PER_PAIR`` × ``_B_PER_PAIR`` × number of
  pairs. With defaults: 6 × 3 × 2 = 36 variants max, deduplicated to
  usually ~20 after overlap.
* **Seed-ranked (``ADAPTIVE_SEED_RUN=<run_id>``)** — load that run's
  per-mutator bypass rate (``k/n`` from the analyzer), rank the pairs by
  the product ``rate(A) × rate(B)``, then emit the top-K. Pairs whose
  component mutators didn't appear in the seed run get rate 0 and rank
  last. This is the "observe, then compose the winners" story from TODO.

Skipped: ``context_displacement`` and ``multi_request`` — their
``request_overrides`` chains carry RequestStep lists that are not simply
re-inputable as ``payload.payload`` strings. Composing those with string
mutators would require a new cross-mutator interface and is out of scope
for this iteration.
"""
from __future__ import annotations

import os
from functools import cache
from pathlib import Path
from typing import ClassVar

from wafeval.models import MutatedPayload, Payload
from wafeval.mutators.base import REGISTRY, Mutator, register


# Only the string-body mutators compose cleanly (see module docstring).
_COMPOSABLE_BASES: tuple[str, ...] = ("lexical", "encoding", "structural")

# Per-pair caps keep the combinatorial explosion bounded.
# 6 pairs × _A_PER_PAIR × _B_PER_PAIR is the upper bound per payload.
_A_PER_PAIR = 3
_B_PER_PAIR = 2


def _parse_env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


@cache
def _rank_pairs(seed_run: str | None, results_root: str) -> list[tuple[str, str]]:
    """Return ordered (A, B) pairs, ranked by observed bypass likelihood.

    Cached on (seed_run, results_root) so repeated instantiations of
    ``AdaptiveMutator`` during one engine run only load the seed data
    once. Falls back to a fixed alphabetical ordering when no seed is
    available, so variant streams are deterministic across runs.
    """
    pairs = [(a, b) for a in _COMPOSABLE_BASES for b in _COMPOSABLE_BASES if a != b]

    if not seed_run:
        return pairs

    # Late import so mutator module load doesn't drag pandas in unless
    # ranking is actually requested.
    try:
        from wafeval.analyzer.aggregate import load_run
        from wafeval.analyzer.bypass import compute_rates
    except Exception:  # pragma: no cover — optional dep path
        return pairs

    try:
        df = load_run(Path(results_root), seed_run)
    except (FileNotFoundError, ValueError):
        return pairs

    if df.empty:
        return pairs

    # Per-mutator bypass rate on non-baseline routes, waf_view lens —
    # matches the denominator we'd care about when stacking transforms.
    waf_only = df[df["waf"] != "baseline"]
    rates = compute_rates(waf_only, ["mutator"], lens="waf_view")
    rate_by_mutator = {row["mutator"]: row["rate"] for _, row in rates.iterrows()}

    def score(pair: tuple[str, str]) -> float:
        return rate_by_mutator.get(pair[0], 0.0) * rate_by_mutator.get(pair[1], 0.0)

    # Sort descending by score; ties keep the fixed-order fallback so the
    # output is deterministic run-to-run.
    return sorted(pairs, key=lambda p: (-score(p), p))


@register
class AdaptiveMutator(Mutator):
    """Compose two string-body base mutators; optionally rank by seed run."""

    category: ClassVar[str] = "adaptive"
    complexity_rank: ClassVar[int] = 6

    def __init__(self) -> None:
        self._seed_run = os.environ.get("ADAPTIVE_SEED_RUN") or None
        self._results_root = os.environ.get("RESULTS_ROOT", "results/raw")
        self._top_k = _parse_env_int("ADAPTIVE_TOP_K", len(_COMPOSABLE_BASES) * (len(_COMPOSABLE_BASES) - 1))

    def mutate(self, payload: Payload) -> list[MutatedPayload]:
        pairs = _rank_pairs(self._seed_run, self._results_root)[: max(1, self._top_k)]

        out: list[MutatedPayload] = []
        seen_bodies: set[str] = {payload.payload}

        for a_name, b_name in pairs:
            a = REGISTRY[a_name]()
            b = REGISTRY[b_name]()

            # Skip any A-variant that carries request_overrides; composing
            # on a RequestStep chain doesn't round-trip through the second
            # mutator's payload.payload-only interface.
            a_variants = [v for v in a.mutate(payload) if v.request_overrides is None][:_A_PER_PAIR]

            for av in a_variants:
                intermediate = payload.model_copy(update={"payload": av.body})
                b_variants = [v for v in b.mutate(intermediate) if v.request_overrides is None][:_B_PER_PAIR]

                for bv in b_variants:
                    if bv.body in seen_bodies:
                        continue
                    seen_bodies.add(bv.body)
                    out.append(MutatedPayload(
                        source_id=payload.id,
                        variant=f"{a_name}>{av.variant}|{b_name}>{bv.variant}",
                        mutator=self.category,
                        complexity_rank=self.complexity_rank,
                        body=bv.body,
                    ))

        return out
