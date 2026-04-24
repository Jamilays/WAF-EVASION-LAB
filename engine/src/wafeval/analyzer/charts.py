"""Chart generation (prompt.md §9).

All charts emit BOTH a 300 dpi PNG and an SVG so the reporter can inline
whichever the consumer wants (Markdown prefers PNG; LaTeX happier with PDF
but we keep SVG as a lossless source for downstream conversion).

Chart set:
  1. heatmap_mutator_waf  — mutator × waf, cell = true-bypass rate, DVWA
  2. bar_table1           — grouped bars: mutator (x) × waf (hue), height =
                            true-bypass rate, errorbars = Wilson 95% CI. Matches
                            prompt.md §15 / paper Table 1.
  3. line_complexity      — complexity_rank (x) × waf (colour), monotone
                            trend per paper finding.
  4. facet_vuln_class     — small-multiples: one subplot per vuln class,
                            mutator × waf heatmap inside each.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")   # no display
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from wafeval.analyzer.bypass import compute_rates

_MUTATOR_ORDER = ["lexical", "encoding", "structural", "context_displacement", "multi_request"]
_WAF_ORDER = ["modsec", "coraza", "shadowd"]


def _save(fig: plt.Figure, out_dir: Path, stem: str) -> list[Path]:
    """Save a figure as PNG (300 dpi) and SVG. Returns [png, svg] paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for ext, kwargs in [("png", {"dpi": 300}), ("svg", {})]:
        p = out_dir / f"{stem}.{ext}"
        fig.savefig(p, bbox_inches="tight", **kwargs)
        paths.append(p)
    plt.close(fig)
    return paths


def heatmap_mutator_waf(df: pd.DataFrame, out_dir: Path, target: str = "dvwa") -> list[Path]:
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["mutator", "waf"], lens="true_bypass",
    )
    if rates.empty:
        return []
    pivot = rates.pivot(index="mutator", columns="waf", values="rate").reindex(
        index=_MUTATOR_ORDER, columns=_WAF_ORDER
    )
    fig, ax = plt.subplots(figsize=(6, 4))
    sns.heatmap(pivot, annot=True, fmt=".2f", cmap="RdYlGn_r",
                vmin=0, vmax=1, cbar_kws={"label": "true-bypass rate"}, ax=ax)
    ax.set_title(f"True-bypass rate — mutator × WAF ({target})")
    ax.set_xlabel("WAF")
    ax.set_ylabel("mutator")
    return _save(fig, out_dir, "heatmap_mutator_waf")


def bar_table1(df: pd.DataFrame, out_dir: Path, target: str = "dvwa") -> list[Path]:
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["mutator", "waf"], lens="true_bypass",
    )
    if rates.empty:
        return []
    # Wilson centre ≠ sample mean, so `ci_lo ≤ rate ≤ ci_hi` isn't guaranteed
    # — the intervals are symmetric around the *score-corrected* centre. For
    # the matplotlib errorbar we need non-negative distances, so clamp.
    rates = rates.assign(
        err_lo=(rates["rate"] - rates["ci_lo"]).clip(lower=0.0),
        err_hi=(rates["ci_hi"] - rates["rate"]).clip(lower=0.0),
    )
    fig, ax = plt.subplots(figsize=(9, 5))
    sns.barplot(
        data=rates, x="mutator", y="rate", hue="waf",
        order=_MUTATOR_ORDER, hue_order=_WAF_ORDER, ax=ax,
    )
    # Seaborn's built-in errorbars don't support our pre-computed Wilson
    # intervals; draw them manually on the midpoints of each bar group.
    widths = 0.8 / max(1, len(_WAF_ORDER))
    for i, mut in enumerate(_MUTATOR_ORDER):
        for j, waf in enumerate(_WAF_ORDER):
            row = rates[(rates["mutator"] == mut) & (rates["waf"] == waf)]
            if row.empty:
                continue
            x = i - 0.4 + (j + 0.5) * widths
            y = float(row["rate"].iloc[0])
            ax.errorbar(
                x, y,
                yerr=[[float(row["err_lo"].iloc[0])], [float(row["err_hi"].iloc[0])]],
                fmt="none", ecolor="black", elinewidth=1, capsize=3,
            )
    ax.set_ylim(0, 1)
    ax.set_ylabel("true-bypass rate (95% Wilson CI)")
    ax.set_xlabel("mutator (complexity rank 1 → 5)")
    ax.set_title(f"Bypass rate by mutator × WAF ({target}) — paper Table 1 analogue")
    return _save(fig, out_dir, "bar_table1")


def line_complexity(df: pd.DataFrame, out_dir: Path, target: str = "dvwa") -> list[Path]:
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["complexity_rank", "waf"], lens="true_bypass",
    )
    if rates.empty:
        return []
    fig, ax = plt.subplots(figsize=(7, 4.5))
    sns.lineplot(
        data=rates, x="complexity_rank", y="rate",
        hue="waf", hue_order=_WAF_ORDER, marker="o", ax=ax,
    )
    for (waf,), sub in rates.groupby(["waf"]):
        ax.fill_between(sub["complexity_rank"], sub["ci_lo"], sub["ci_hi"], alpha=0.10)
    ax.set_ylim(0, 1)
    # Axis covers every registered mutator's complexity_rank. The base
    # five mutators are 1-5; the adaptive (compositional) mutator is 6.
    # Covers every registered mutator's complexity_rank — base five
    # (1-5), adaptive pair (6), adaptive triple (7). Range is
    # [1, 8) so ticks land on 1..7.
    ax.set_xticks(range(1, 8))
    ax.set_xlabel("complexity rank")
    ax.set_ylabel("true-bypass rate")
    ax.set_title(f"Bypass rate vs obfuscation complexity ({target})")
    return _save(fig, out_dir, "line_complexity")


def facet_vuln_class(df: pd.DataFrame, out_dir: Path, target: str = "dvwa") -> list[Path]:
    rates = compute_rates(
        df[(df["target"] == target) & (df["waf"] != "baseline")],
        ["vuln_class", "mutator", "waf"], lens="true_bypass",
    )
    if rates.empty:
        return []
    classes = sorted(rates["vuln_class"].unique())
    n = len(classes)
    cols = min(3, n)
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4.5 * cols, 3.5 * rows), squeeze=False)

    for idx, cls in enumerate(classes):
        ax = axes[idx // cols][idx % cols]
        sub = rates[rates["vuln_class"] == cls]
        pivot = sub.pivot(index="mutator", columns="waf", values="rate").reindex(
            index=_MUTATOR_ORDER, columns=_WAF_ORDER
        )
        sns.heatmap(pivot, annot=True, fmt=".2f", cmap="RdYlGn_r",
                    vmin=0, vmax=1, cbar=False, ax=ax)
        ax.set_title(cls)
        ax.set_xlabel("")
        ax.set_ylabel("")
    # blank any unused axes
    for j in range(n, rows * cols):
        axes[j // cols][j % cols].axis("off")
    fig.suptitle(f"Per-vuln-class bypass rate × mutator × WAF ({target})", y=1.02)
    return _save(fig, out_dir, "facet_vuln_class")


def render_all(df: pd.DataFrame, out_dir: Path, target: str = "dvwa") -> list[Path]:
    """Emit every chart. Returns the flat list of output paths."""
    sns.set_theme(style="whitegrid", context="paper")
    paths: list[Path] = []
    paths += heatmap_mutator_waf(df, out_dir, target)
    paths += bar_table1(df, out_dir, target)
    paths += line_complexity(df, out_dir, target)
    paths += facet_vuln_class(df, out_dir, target)
    return paths
