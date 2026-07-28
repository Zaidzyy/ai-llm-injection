"""Execute a probe suite against a provider and collect results."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable

from .canary import canary_token, system_prompt
from .judge import classify
from .models import Attempt, Probe, RunResult
from .providers.base import Provider, ProviderError


def run_suite(
    provider: Provider,
    probes: Iterable[Probe],
    seed: str = "default",
    persona: str = "a helpful assistant",
    on_result: Callable[[Attempt], None] | None = None,
    repeats: int = 1,
) -> RunResult:
    """Run every probe `repeats` times and return aggregated results.

    `repeats` matters more than it looks: safeguard failures are stochastic at
    non-zero temperature, so a single pass under-reports. Reporting a bypass rate
    from n=1 is one of the most common errors in published LLM red-team results.
    """
    probes = list(probes)
    token = canary_token(seed)
    system = system_prompt(token, persona=persona)

    result = RunResult(
        model=provider.model,
        provider=provider.name,
        canary=token,
        meta={
            "seed": seed,
            "repeats": repeats,
            "probe_count": len(probes),
            "severity": {p.id: p.severity for p in probes},
            "owasp": {p.id: p.owasp for p in probes},
            "atlas": {p.id: p.atlas for p in probes},
        },
    )

    for probe in probes:
        prompt = probe.render(token)
        for _ in range(repeats):
            started = time.perf_counter()
            error: str | None = None
            response = ""
            try:
                response = provider.complete_probe(system, prompt, probe)
            except ProviderError as exc:
                error = str(exc)
            except Exception as exc:  # defensive: one bad probe must not kill the run
                error = f"{type(exc).__name__}: {exc}"
            elapsed = int((time.perf_counter() - started) * 1000)

            did_leak, refused = (False, False) if error else classify(response, token)
            attempt = Attempt(
                probe_id=probe.id,
                technique=probe.technique,
                prompt=prompt,
                response=response,
                leaked=did_leak,
                refused=refused,
                latency_ms=elapsed,
                error=error,
            )
            result.attempts.append(attempt)
            if on_result:
                on_result(attempt)

    return result
