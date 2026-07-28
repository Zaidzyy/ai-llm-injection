"""Local Ollama provider — useful for testing hardening changes without vendor cost."""

from __future__ import annotations

import json
import urllib.request

from .base import Provider, ProviderError


class OllamaProvider(Provider):
    name = "ollama"

    def __init__(self, model: str = "llama3", host: str = "http://localhost:11434", timeout: int = 120, **kwargs) -> None:
        super().__init__(model, **kwargs)
        self.host = host.rstrip("/")
        self.timeout = timeout

    def complete(self, system: str, user: str) -> str:
        payload = json.dumps(
            {
                "model": self.model,
                "stream": False,
                "options": {"temperature": 0.0},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode())
        except Exception as exc:  # pragma: no cover - network
            raise ProviderError(f"Ollama request failed: {exc}") from exc
        return body.get("message", {}).get("content", "")
