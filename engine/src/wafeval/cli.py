"""wafeval CLI — ``python -m wafeval`` / ``wafeval``."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import anyio
import structlog

from wafeval import __version__
from wafeval.models import VulnClass
from wafeval.runner import RunConfig, run
from wafeval.analyzer.aggregate import latest_run_id, load_run
from wafeval.analyzer.charts import render_all as render_charts
from wafeval.analyzer.export import write_csvs
from wafeval.reporter import render_latex, render_markdown


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wafeval", description="WAF Evasion Lab engine")
    p.add_argument("--version", action="version", version=f"wafeval {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="Execute one test run end-to-end")
    r.add_argument("--traefik-url", default=os.environ.get("TRAEFIK_URL", "http://127.0.0.1:8000"))
    r.add_argument(
        "--mutators", default="lexical",
        help="comma-separated mutator categories (registered in wafeval.mutators)",
    )
    r.add_argument(
        "--classes", default="sqli,xss",
        help="comma-separated vuln classes to load from the corpus",
    )
    r.add_argument("--wafs", default=None, help="comma-separated WAFs (default: all)")
    r.add_argument("--targets", default=None, help="comma-separated targets (default: all)")
    r.add_argument("--max-concurrency", type=int, default=int(os.environ.get("MAX_CONCURRENCY", "10")))
    r.add_argument("--timeout", type=float, default=15.0)
    r.add_argument("--results-root", type=Path, default=Path(os.environ.get("RESULTS_ROOT", "results/raw")))
    r.add_argument("--run-id", default=None)

    rep = sub.add_parser("report", help="Regenerate analyzer outputs + Markdown/LaTeX report")
    rep.add_argument("--run-id", default=None, help="run id under results/raw (default: latest)")
    rep.add_argument("--results-root", type=Path, default=Path(os.environ.get("RESULTS_ROOT", "results/raw")))
    rep.add_argument("--processed-dir", type=Path, default=Path("results/processed"))
    rep.add_argument("--figures-dir", type=Path, default=Path("results/figures"))
    rep.add_argument("--reports-dir", type=Path, default=Path("results/reports"))
    rep.add_argument("--anchor-target", default="dvwa",
                     help="target whose baseline triggers anchor the true-bypass table")
    return p


def _configure_logging():
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO
    )


def main(argv: list[str] | None = None) -> int:
    _configure_logging()
    args = _build_parser().parse_args(argv)

    if args.cmd == "run":
        classes = [VulnClass(c.strip()) for c in args.classes.split(",") if c.strip()]
        mutators = [m.strip() for m in args.mutators.split(",") if m.strip()]
        wafs = [w.strip() for w in args.wafs.split(",")] if args.wafs else None
        targets = [t.strip() for t in args.targets.split(",")] if args.targets else None

        cfg = RunConfig(
            traefik_url=args.traefik_url,
            mutators=mutators,
            classes=classes,
            wafs=wafs,
            targets=targets,
            max_concurrency=args.max_concurrency,
            request_timeout_s=args.timeout,
            results_root=args.results_root,
            run_id=args.run_id,
        )
        run_id = anyio.run(run, cfg)
        print(f"run_id={run_id} results={args.results_root / run_id}")
        return 0

    if args.cmd == "report":
        import json as _json
        run_id = args.run_id or latest_run_id(args.results_root)
        df = load_run(args.results_root, run_id)
        if df.empty:
            print(f"[report] no datapoints under {args.results_root / run_id}", file=sys.stderr)
            return 1

        processed_dir = args.processed_dir / run_id
        figures_dir = args.figures_dir / run_id
        report_dir = args.reports_dir / run_id

        csvs = write_csvs(df, processed_dir, anchor_target=args.anchor_target)
        figures = render_charts(df, figures_dir, target=args.anchor_target)

        manifest_path = args.results_root / run_id / "manifest.json"
        manifest = _json.loads(manifest_path.read_text()) if manifest_path.exists() else {}

        md = render_markdown(
            df, report_dir / "report.md", run_id, figures,
            manifest=manifest, anchor_target=args.anchor_target,
        )
        tex = render_latex(
            df, report_dir / "report.tex", run_id, figures,
            manifest=manifest, anchor_target=args.anchor_target,
        )
        print(f"run_id={run_id}")
        for name, path in csvs.items():
            print(f"  csv.{name}: {path}")
        print(f"  figures: {len(figures)} files under {figures_dir}")
        print(f"  report.md: {md}")
        print(f"  report.tex: {tex}")
        return 0

    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
