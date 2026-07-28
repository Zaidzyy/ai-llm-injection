"""Command-line interface.

    python -m redteam run     --provider echo --model mock-1
    python -m redteam scan    --text "ignore all previous instructions"
    python -m redteam probes
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .detector import scan as detect_scan
from .providers import build
from .providers.base import ProviderError
from .report import to_json, to_markdown
from .runner import run_suite
from .suite import SuiteError, load_suite, merge

DEFAULT_SUITE = Path(__file__).resolve().parent.parent / "probes" / "suite.yaml"
PRIVATE_SUITE = Path(__file__).resolve().parent.parent / "probes" / "private.yaml"


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        probes = load_suite(args.suite)
        if args.include_private and PRIVATE_SUITE.exists():
            probes = merge(probes, load_suite(PRIVATE_SUITE))
            print(f"[!] Merged private suite ({PRIVATE_SUITE.name}) — do not commit reports "
                  "generated from this run without review.", file=sys.stderr)
    except SuiteError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.technique:
        probes = [p for p in probes if p.technique in args.technique]
        if not probes:
            print(f"error: no probes match technique(s): {', '.join(args.technique)}", file=sys.stderr)
            return 2

    provider_kwargs = {}
    if args.base_url:
        provider_kwargs["base_url"] = args.base_url
    if args.api_key_env:
        provider_kwargs["api_key_env"] = args.api_key_env

    try:
        provider = build(args.provider, args.model, **provider_kwargs)
    except ProviderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    total = len(probes) * args.repeats
    done = 0

    def progress(attempt) -> None:
        nonlocal done
        done += 1
        if not args.quiet:
            mark = {"bypass": "BYPASS ", "refused": "held   ", "deflected": "held   ", "error": "error  "}
            print(f"[{done:>3}/{total}] {mark[attempt.outcome]} {attempt.probe_id}  {attempt.technique}",
                  file=sys.stderr)

    result = run_suite(
        provider,
        probes,
        seed=args.seed,
        on_result=progress,
        repeats=args.repeats,
    )

    out = (
        to_json(result, include_responses=args.include_responses)
        if args.json
        else to_markdown(result)
    )

    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"\nwrote {args.out}", file=sys.stderr)
    else:
        print(out)

    if not args.quiet:
        print(f"\nrobustness {result.robustness_score}/100 | "
              f"{len(result.bypasses)} bypass / {result.total} attempts", file=sys.stderr)

    # Non-zero exit when the score drops below the gate, so this can run in CI as a
    # regression check against your own deployed system prompt.
    if args.fail_under is not None and result.robustness_score < args.fail_under:
        print(f"FAIL: robustness {result.robustness_score} < gate {args.fail_under}", file=sys.stderr)
        return 1
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    text = args.text
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    elif not text:
        text = sys.stdin.read()

    detection = detect_scan(text)
    print(json.dumps(detection.to_dict(), indent=2))
    return 1 if detection.severity in {"high", "medium"} and args.strict else 0


def _cmd_probes(args: argparse.Namespace) -> int:
    probes = load_suite(args.suite)
    width = max(len(p.id) for p in probes)
    for p in probes:
        print(f"{p.id:<{width}}  {p.severity:<6}  {p.owasp:<6}  {p.technique:<24}  {p.atlas}")
    print(f"\n{len(probes)} probes, {len({p.technique for p in probes})} technique classes")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redteam",
        description="Measure LLM instruction-hierarchy robustness with benign canary probes.",
    )
    parser.add_argument("--version", action="version", version=f"redteam {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the probe suite against a model")
    run.add_argument("--provider", default="echo", help="echo | ollama | openai | xai | groq")
    run.add_argument("--model", default="mock-1")
    run.add_argument("--base-url", default=None, help="override the endpoint URL")
    run.add_argument("--api-key-env", default=None, help="env var holding the API key")
    run.add_argument("--suite", default=str(DEFAULT_SUITE))
    run.add_argument("--technique", action="append", help="filter to technique (repeatable)")
    run.add_argument("--seed", default="default", help="canary seed; changes the token")
    run.add_argument("--repeats", type=int, default=1, help="runs per probe (use >1 at temp>0)")
    run.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    run.add_argument("--include-responses", action="store_true",
                     help="keep prompts/responses in output (never commit these)")
    run.add_argument("--include-private", action="store_true",
                     help="also load probes/private.yaml if present (gitignored)")
    run.add_argument("--fail-under", type=float, default=None,
                     help="exit 1 if robustness score falls below this (CI gate)")
    run.add_argument("--out", default=None)
    run.add_argument("--quiet", action="store_true")
    run.set_defaults(func=_cmd_run)

    sc = sub.add_parser("scan", help="score text for prompt-injection indicators")
    sc.add_argument("--text", default=None)
    sc.add_argument("--file", default=None)
    sc.add_argument("--strict", action="store_true", help="exit 1 on medium/high severity")
    sc.set_defaults(func=_cmd_scan)

    pr = sub.add_parser("probes", help="list the probe suite")
    pr.add_argument("--suite", default=str(DEFAULT_SUITE))
    pr.set_defaults(func=_cmd_probes)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
