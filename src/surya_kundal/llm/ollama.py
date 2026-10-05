"""A small, strict client for a local Ollama server.

Design rules for using a language model next to a honeypot:

* Everything an attacker typed is untrusted and may try to instruct the model
  (prompt injection). The model is therefore only ever asked to describe data, its
  output is validated and treated as untrusted text too, and it is never given tools
  or any way to act.
* It is optional. If Ollama is down, callers get ``LLMError`` and carry on.
* It runs offline against your own machine; nothing is sent to a third party.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

from surya_kundal.textsafe import printable

# Generation on a laptop CPU or small GPU is slow; connecting should still fail fast.
DEFAULT_TIMEOUT = httpx.Timeout(300.0, connect=5.0)
MAX_RESPONSE_CHARS = 20_000
DEFAULT_MODEL = "qwen2.5-coder:7b"  # about 5x faster than the 14b on a 6 GB GPU


class LLMError(Exception):
    """The model server could not be used. Messages never contain prompt text."""


@dataclass(frozen=True)
class Generation:
    text: str
    seconds: float
    output_tokens: int | None
    tokens_per_second: float | None


def _clean_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise LLMError("OLLAMA_URL must start with http:// or https://")
    return url


def _reason(response: httpx.Response) -> str:
    """The server's own explanation (Ollama sends {"error": "..."}), made safe to print."""
    try:
        detail = response.json().get("error")
    except (ValueError, AttributeError):
        return ""
    return f": {printable(detail, limit=300)}" if isinstance(detail, str) and detail else ""


class OllamaClient:
    def __init__(self, base_url: str, *, client: httpx.Client | None = None) -> None:
        self.base_url = _clean_url(base_url)
        self._client = client or httpx.Client(timeout=DEFAULT_TIMEOUT)

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self._client.request(method, self.base_url + path, **kwargs)
        except httpx.ConnectTimeout as exc:
            raise LLMError(
                "no answer from the model server (connection timed out): is Ollama running, "
                "listening on this address (OLLAMA_HOST=0.0.0.0), and not blocked by a firewall?"
            ) from exc
        except httpx.TimeoutException as exc:
            raise LLMError("the model server timed out while generating") from exc
        except httpx.TransportError as exc:
            raise LLMError(f"cannot reach the model server ({type(exc).__name__})") from exc
        if response.status_code == 404:
            raise LLMError("model not found; check the name with `ollama list`")
        if response.status_code >= 400:
            raise LLMError(
                f"the model server returned HTTP {response.status_code}" + _reason(response)
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise LLMError("the model server sent something that is not JSON") from exc
        if not isinstance(body, dict):
            raise LLMError("unexpected reply from the model server")
        return body

    def models(self) -> list[str]:
        """Names of the models installed on the server."""
        # Listing models is instant on a healthy server, so do not wait minutes for it.
        body = self._request("GET", "/api/tags", timeout=httpx.Timeout(10.0, connect=5.0))
        items = body.get("models")
        if not isinstance(items, list):
            raise LLMError("unexpected reply from the model server")
        return sorted(
            str(m.get("name", "")) for m in items if isinstance(m, dict) and m.get("name")
        )

    def generate(
        self,
        model: str,
        prompt: str,
        *,
        system: str | None = None,
        json_mode: bool = False,
        temperature: float = 0.1,
        max_tokens: int = 400,
    ) -> Generation:
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if system:
            payload["system"] = system
        if json_mode:
            payload["format"] = "json"
        started = time.monotonic()
        body = self._request("POST", "/api/generate", json=payload)
        seconds = time.monotonic() - started
        text = body.get("response")
        if not isinstance(text, str):
            raise LLMError("the model returned no text")
        tokens = body.get("eval_count")
        duration_ns = body.get("eval_duration")
        speed = None
        if isinstance(tokens, int) and isinstance(duration_ns, int) and duration_ns > 0:
            speed = tokens / (duration_ns / 1e9)
        return Generation(
            text=text[:MAX_RESPONSE_CHARS],
            seconds=seconds,
            output_tokens=tokens if isinstance(tokens, int) else None,
            tokens_per_second=speed,
        )


CHECK_SYSTEM = "You are a terse assistant. Reply with JSON only."
CHECK_PROMPT = (
    'Reply with a JSON object {"tool": "<name>", "purpose": "<one short sentence>"} '
    "describing what the Linux command `uname -a` does."
)


def check_model(client: OllamaClient, model: str) -> tuple[Generation, bool]:
    """Run a fixed tiny task; report the speed and whether the JSON came back valid."""
    result = client.generate(
        model, CHECK_PROMPT, system=CHECK_SYSTEM, json_mode=True, max_tokens=80
    )
    try:
        parsed = json.loads(result.text)
        valid = isinstance(parsed, dict) and {"tool", "purpose"} <= parsed.keys()
    except ValueError:
        valid = False
    return result, valid
