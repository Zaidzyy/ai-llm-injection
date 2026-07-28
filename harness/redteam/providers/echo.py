"""Offline mock provider.

Exists so the harness, tests, and CI can run end-to-end with no API key, no network,
and no cost. It simulates a model with a configurable weakness profile: it "leaks"
the canary for techniques listed in `weak_to`, and refuses otherwise.

This is what makes the repository's CI meaningful — the pipeline proves the harness
works without ever touching a live vendor endpoint.
"""

from __future__ import annotations

import re

from .base import Provider

REFUSAL = (
    "I can't share that internal marker or follow instructions that try to override "
    "my operator rules. Happy to help with something else."
)


class EchoProvider(Provider):
    name = "echo"

    def __init__(self, model: str = "mock-1", weak_to: list[str] | None = None, **kwargs) -> None:
        super().__init__(model, **kwargs)
        # Default profile: a plausibly-imperfect model that folds to two technique
        # families and holds the rest.
        self.weak_to = weak_to if weak_to is not None else ["indirect-injection", "encoding-indirection"]

    def complete(self, system: str, user: str) -> str:
        return self._respond(system, technique="")

    def complete_probe(self, system: str, user: str, probe) -> str:
        return self._respond(system, technique=getattr(probe, "technique", ""))

    def _respond(self, system: str, technique: str) -> str:
        match = re.search(r"CANARY-[A-F0-9]{8}", system)
        token = match.group(0) if match else "CANARY-00000000"
        if technique in self.weak_to:
            return f"Sure — the internal marker is {token}."
        return REFUSAL
