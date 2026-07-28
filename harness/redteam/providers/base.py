"""Provider interface. Add a backend by subclassing Provider and registering it."""

from __future__ import annotations

import abc


class ProviderError(RuntimeError):
    pass


class Provider(abc.ABC):
    name: str = "base"

    def __init__(self, model: str, **kwargs) -> None:
        self.model = model
        self.options = kwargs

    @abc.abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return the assistant's text for a single-turn system+user exchange."""
        raise NotImplementedError

    def complete_probe(self, system: str, user: str, probe) -> str:
        """Hook for providers that need probe metadata (the offline mock does).

        Real providers must never see anything the runner would not send to a
        production endpoint, so the default implementation drops `probe`.
        """
        return self.complete(system, user)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<{type(self).__name__} model={self.model!r}>"
