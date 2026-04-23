"""Ladder / ablation analyzer — one bypass-rate sample per (label, mutator).

The headline use case is the open-appsec minimum-confidence ablation
(`critical` → `high` → `medium` → `low`): one run per setting, plotted as
a line curve showing how bypass rate moves as the ML threshold loosens.
The same machinery works for any ordered ablation (CRS paranoia 1→4, the
open-appsec confidence ladder, anything else the researcher reruns with
one knob turned).

The module stays corpus-agnostic: it doesn't know *why* a run differs
from its neighbour, only that the caller ordered them. Downstream
reporting picks the WAF column from each run (after filtering
``waf != "baseline"``) and groups by ``mutator``. If the caller merged
multiple WAFs into one run, the ladder is computed per WAF separately
and the rendered figure has one line per (waf, mutator) pair.

False-positive-rate measurement would bolt on here later once we ship a
benign-traffic corpus — each run would also produce a FPR datapoint, and
the plot would become an ROC-ish curve per mutator. For now the Y-axis
is plain bypass rate.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from wafeval.analyzer.aggregate import load_run
from wafeval.analyzer.bypass import compute_rates


_MUTATOR_ORDER = ["lexical", "encoding", "structural", "context_displacement", "multi_request"]


def build_ladder_table(
    results_root: Path,
    steps: list[tuple[str, str]],
    target: str,
    lens: str = "waf_view",
) -> pd.DataFrame:
    """Return a long-format table one row per (step_label, waf, mutator).

    Columns: ``step, waf, mutator, rate, ci_lo, ci_hi, n, k, target``. Rows
    with ``n < 5`` are kept (the reporter dims them) because the reader
    wants to see the empty cells to understand coverage; a silent drop
    would be misleading for a small-ablation use case.
    """
    rows: list[pd.DataFrame] = []
    for step_label, run_id in steps:
        df = load_run(Path(results_root), run_id)
        if df.empty:
            continue
        # Filter to the anchor target *and* exclude the baseline — we want
        # "what does this WAF do at this setting", not "what was the trigger
        # healthy enough to fire".
        sub = df[(df["target"] == target) & (df["waf"] != "baseline")]
        if sub.empty:
            continue
        rates = compute_rates(sub, ["waf", "mutator"], lens=lens)
        rates = rates.assign(step=step_label, target=target)
        rows.append(rates)
    if not rows:
        return pd.DataFrame(columns=["step", "waf", "mutator", "rate",
                                      "ci_lo", "ci_hi", "n", "k", "target"])
    return pd.concat(rows, ignore_index=True)


def render_ladder_chart(
    table: pd.DataFrame,
    steps: list[tuple[str, str]],
    out_dir: Path,
    stem: str = "ladder",
    title: str = "Bypass rate vs ablation step",
) -> list[Path]:
    """Render a line chart: x = step (categorical, left→right), y = rate.

    One line per (waf, mutator). Seaborn's ``lineplot`` can't read a pair of
    dimensions as hue + style cleanly when the categorical x-axis has no
    numeric order, so we plot one line at a time and handle the legend
    manually. Returns [png, svg] paths.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    if table.empty:
        return []

    sns.set_theme(style="whitegrid", context="paper")
    step_order = [s for s, _ in steps]
    table = table.copy()
    table["step_idx"] = table["step"].map({s: i for i, s in enumerate(step_order)})

    wafs = sorted(table["waf"].unique())
    mutators = [m for m in _MUTATOR_ORDER if m in table["mutator"].unique()]

    fig, ax = plt.subplots(figsize=(7, 4.5))
    palette = sns.color_palette("tab10", n_colors=len(mutators))
    linestyles = ["-", "--", ":", "-."]
    for wi, waf in enumerate(wafs):
        for mi, mut in enumerate(mutators):
            sub = (table[(table["waf"] == waf) & (table["mutator"] == mut)]
                   .sort_values("step_idx"))
            if sub.empty:
                continue
            ax.plot(
                sub["step_idx"], sub["rate"],
                marker="o",
                linestyle=linestyles[wi % len(linestyles)],
                color=palette[mi],
                label=f"{waf} · {mut}" if len(wafs) > 1 else mut,
            )
            ax.fill_between(sub["step_idx"], sub["ci_lo"], sub["ci_hi"],
                            color=palette[mi], alpha=0.10)

    ax.set_xticks(range(len(step_order)))
    ax.set_xticklabels(step_order, rotation=0)
    ax.set_xlabel("ablation step (ordered by caller)")
    ax.set_ylabel("bypass rate (95 % Wilson CI)")
    ax.set_ylim(0, 1)
    ax.set_title(title)
    ax.legend(loc="best", fontsize="x-small", ncols=2)

    paths = []
    for ext, kw in [("png", {"dpi": 300}), ("svg", {})]:
        p = out_dir / f"{stem}.{ext}"
        fig.savefig(p, bbox_inches="tight", **kw)
        paths.append(p)
    plt.close(fig)
    return paths


def render_ladder_markdown(
    table: pd.DataFrame,
    steps: list[tuple[str, str]],
    out_path: Path,
    figures: list[Path],
    title: str = "Ladder ablation",
) -> Path:
    """Emit a small Markdown report: provenance + pivot + inlined figures."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [f"# {title}", ""]
    lines.append("## Provenance")
    lines.append("")
    lines.append("| Step | Source run_id |")
    lines.append("|---|---|")
    for step_label, rid in steps:
        lines.append(f"| `{step_label}` | `{rid}` |")
    lines.append("")

    if table.empty:
        lines.append("*(no data — ran out of rows after filtering)*")
        out_path.write_text("\n".join(lines) + "\n")
        return out_path

    step_order = [s for s, _ in steps]
    for waf, sub in table.groupby("waf"):
        lines.append(f"## {waf}")
        lines.append("")
        pivot = sub.pivot(index="mutator", columns="step", values="rate")
        pivot = pivot.reindex(
            index=[m for m in _MUTATOR_ORDER if m in pivot.index],
            columns=[s for s in step_order if s in pivot.columns],
        )
        header = "| mutator | " + " | ".join(pivot.columns) + " |"
        sep = "|---|" + "|".join(["---:"] * len(pivot.columns)) + "|"
        lines.append(header)
        lines.append(sep)
        for mut, row in pivot.iterrows():
            cells = [f"{v*100:.1f}%" if pd.notna(v) else "—" for v in row.values]
            lines.append(f"| `{mut}` | " + " | ".join(cells) + " |")
        lines.append("")

    pngs = [p for p in figures if p.suffix == ".png"]
    if pngs:
        lines.append("## Figures")
        lines.append("")
        for p in pngs:
            try:
                rel = p.resolve().relative_to(out_path.parent.resolve())
            except ValueError:
                rel = p
            lines.append(f"![{p.stem}]({rel})")
        lines.append("")

    out_path.write_text("\n".join(lines) + "\n")
    return out_path
