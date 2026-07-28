"""Report rendering — JSON for machines, Markdown for humans and for the repo."""

from __future__ import annotations

import json

from .models import RunResult

_OUTCOME_LABEL = {
    "bypass": "BYPASS",
    "refused": "held (refused)",
    "deflected": "held (deflected)",
    "error": "error",
}


def to_json(result: RunResult, *, include_responses: bool = False, indent: int = 2) -> str:
    payload = result.to_dict()
    if not include_responses:
        # Model responses can contain the canary and reproduce the probe verbatim.
        # Default to stripping them so a committed report is safe by construction.
        for attempt in payload["attempts"]:
            attempt.pop("response", None)
            attempt.pop("prompt", None)
    return json.dumps(payload, indent=indent, sort_keys=True)


def to_markdown(result: RunResult) -> str:
    meta = result.meta
    sev = meta.get("severity", {})
    owasp = meta.get("owasp", {})

    lines: list[str] = []
    lines.append("# Instruction-hierarchy robustness report")
    lines.append("")
    lines.append(f"- **Target model:** `{result.model}` via `{result.provider}`")
    lines.append(f"- **Probes:** {meta.get('probe_count', '?')}  ")
    lines.append(f"- **Repeats per probe:** {meta.get('repeats', 1)}")
    lines.append(f"- **Robustness score:** **{result.robustness_score}/100** "
                 "(severity-weighted; higher is better)")
    lines.append(f"- **Bypass rate:** {result.bypass_rate:.1%} "
                 f"({len(result.bypasses)}/{result.total} attempts)")
    lines.append("")
    lines.append("> Scores measure resistance to benign canary extraction only. "
                 "See `docs/methodology.md` for what this does and does not evidence.")
    lines.append("")

    lines.append("## By technique")
    lines.append("")
    lines.append("| Technique | OWASP | Severity | Bypass | Held | Error |")
    lines.append("|---|---|---|---|---|---|")
    first_probe: dict[str, str] = {}
    for attempt in result.attempts:
        first_probe.setdefault(attempt.technique, attempt.probe_id)
    for technique, counts in sorted(result.by_technique().items()):
        pid = first_probe.get(technique, "")
        held = counts["refused"] + counts["deflected"]
        lines.append(
            f"| `{technique}` | {owasp.get(pid, '-')} | {sev.get(pid, '-')} | "
            f"{counts['bypass']} | {held} | {counts['error']} |"
        )
    lines.append("")

    lines.append("## Per-probe outcomes")
    lines.append("")
    lines.append("| Probe | Technique | Outcome |")
    lines.append("|---|---|---|")
    for attempt in result.attempts:
        lines.append(
            f"| `{attempt.probe_id}` | `{attempt.technique}` | "
            f"{_OUTCOME_LABEL.get(attempt.outcome, attempt.outcome)} |"
        )
    lines.append("")

    if result.bypasses:
        lines.append("## Bypasses requiring attention")
        lines.append("")
        for attempt in result.bypasses:
            lines.append(
                f"- `{attempt.probe_id}` (`{attempt.technique}`, "
                f"severity {sev.get(attempt.probe_id, '?')}) — canary recovered."
            )
        lines.append("")
        lines.append("Prompt and response bodies are withheld from committed reports. "
                     "Re-run locally with `--include-responses` to inspect.")
    else:
        lines.append("No bypasses recorded in this run.")
    lines.append("")
    return "\n".join(lines)
