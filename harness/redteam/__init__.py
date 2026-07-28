"""redteam — a reproducible harness for measuring LLM instruction-hierarchy robustness.

Design constraint: this package contains NO working jailbreak payloads and is not
capable of producing harmful content. Robustness is measured with *canary probes*
(see redteam.canary) — a benign, non-harmful proxy for safeguard integrity.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
