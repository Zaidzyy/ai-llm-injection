from __future__ import annotations

from .base import Provider, ProviderError
from .echo import EchoProvider
from .ollama import OllamaProvider
from .openai_compat import DEFAULT_ENDPOINTS, OpenAICompatProvider

REGISTRY = {
    "echo": EchoProvider,
    "ollama": OllamaProvider,
    "openai": OpenAICompatProvider,
    "xai": OpenAICompatProvider,
    "groq": OpenAICompatProvider,
}


def build(provider: str, model: str, **kwargs) -> Provider:
    try:
        cls = REGISTRY[provider]
    except KeyError:
        raise ProviderError(
            f"Unknown provider {provider!r}. Available: {', '.join(sorted(REGISTRY))}"
        ) from None

    if cls is OpenAICompatProvider and "base_url" not in kwargs:
        kwargs["base_url"] = DEFAULT_ENDPOINTS.get(provider, DEFAULT_ENDPOINTS["openai"])
    return cls(model, **kwargs)


__all__ = [
    "Provider",
    "ProviderError",
    "EchoProvider",
    "OllamaProvider",
    "OpenAICompatProvider",
    "REGISTRY",
    "build",
]
