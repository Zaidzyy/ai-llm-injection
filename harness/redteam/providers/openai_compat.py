"""OpenAI-compatible chat-completions provider.

Works unmodified against any endpoint that speaks the /v1/chat/completions schema:
xAI (api.x.ai), OpenAI, Groq, Together, OpenRouter, vLLM, LM Studio.

Uses urllib from the stdlib so the harness has no hard runtime dependency on an
SDK that might drift.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .base import Provider, ProviderError

DEFAULT_ENDPOINTS = {
    "xai": "https://api.x.ai/v1/chat/completions",
    "openai": "https://api.openai.com/v1/chat/completions",
    "groq": "https://api.groq.com/openai/v1/chat/completions",
}


class OpenAICompatProvider(Provider):
    name = "openai-compat"

    def __init__(
        self,
        model: str,
        base_url: str | None = None,
        api_key_env: str = "REDTEAM_API_KEY",
        temperature: float = 0.0,
        max_tokens: int = 512,
        timeout: int = 60,
        **kwargs,
    ) -> None:
        super().__init__(model, **kwargs)
        self.base_url = base_url or DEFAULT_ENDPOINTS["openai"]
        self.api_key = os.environ.get(api_key_env, "")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        if not self.api_key:
            raise ProviderError(
                f"No API key found in ${api_key_env}. Export it, or use --provider echo "
                "for an offline dry run."
            )

    def complete(self, system: str, user: str) -> str:
        payload = json.dumps(
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
            }
        ).encode()

        req = urllib.request.Request(
            self.base_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:  # pragma: no cover - network
            raise ProviderError(f"HTTP {exc.code}: {exc.read().decode()[:300]}") from exc
        except Exception as exc:  # pragma: no cover - network
            raise ProviderError(str(exc)) from exc

        try:
            return body["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:  # pragma: no cover
            raise ProviderError(f"Unexpected response shape: {str(body)[:300]}") from exc
