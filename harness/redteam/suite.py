"""Probe suite loading and validation."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Probe

REQUIRED = {"id", "technique", "owasp", "atlas", "severity", "description", "template"}
VALID_SEVERITY = {"low", "medium", "high"}


class SuiteError(ValueError):
    pass


def _load_raw(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".json"}:
        return json.loads(text)
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise SuiteError(
            "PyYAML is required to load .yaml suites. `pip install pyyaml`, "
            "or supply the suite as .json."
        ) from exc
    data = yaml.safe_load(text)
    if not isinstance(data, list):
        raise SuiteError(f"{path}: expected a top-level list of probes")
    return data


def load_suite(path: str | Path) -> list[Probe]:
    p = Path(path)
    if not p.exists():
        raise SuiteError(f"Suite not found: {p}")

    probes: list[Probe] = []
    seen: set[str] = set()
    for i, entry in enumerate(_load_raw(p)):
        missing = REQUIRED - entry.keys()
        if missing:
            raise SuiteError(f"{p}[{i}]: missing field(s): {', '.join(sorted(missing))}")
        if entry["severity"] not in VALID_SEVERITY:
            raise SuiteError(
                f"{p}[{i}]: severity {entry['severity']!r} not in {sorted(VALID_SEVERITY)}"
            )
        if entry["id"] in seen:
            raise SuiteError(f"{p}[{i}]: duplicate probe id {entry['id']!r}")
        seen.add(entry["id"])
        probes.append(
            Probe(
                id=entry["id"],
                technique=entry["technique"],
                owasp=entry["owasp"],
                atlas=entry["atlas"],
                severity=entry["severity"],
                description=entry["description"].strip(),
                template=entry["template"].strip(),
                turns=int(entry.get("turns", 1)),
                references=list(entry.get("references", [])),
            )
        )
    if not probes:
        raise SuiteError(f"{p}: suite is empty")
    return probes


def merge(*suites: list[Probe]) -> list[Probe]:
    """Merge suites, later entries winning on id collision (private overrides public)."""
    out: dict[str, Probe] = {}
    for suite in suites:
        for probe in suite:
            out[probe.id] = probe
    return list(out.values())
