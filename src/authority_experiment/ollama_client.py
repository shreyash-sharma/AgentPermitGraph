from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class OllamaClient:
    def __init__(self, host: str = "http://127.0.0.1:11434", timeout: int = 300) -> None:
        self.host = host.rstrip("/")
        self.timeout = timeout

    def _request(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.host}{path}", data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

    def list_models(self) -> list[str]:
        return [model["name"] for model in self._request("/api/tags").get("models", [])]

    def runtime_provenance(self, model_name: str) -> dict[str, Any]:
        """Capture immutable-ish local runtime/model details with every matrix."""
        version = self._request("/api/version").get("version")
        models = self._request("/api/tags").get("models", [])
        descriptor = next(
            (model for model in models if model.get("name") == model_name or model.get("model") == model_name),
            {},
        )
        return {
            "ollama_version": version,
            "model_name": model_name,
            "model_digest": descriptor.get("digest"),
            "model_size": descriptor.get("size"),
            "model_modified_at": descriptor.get("modified_at"),
            "model_details": descriptor.get("details", {}),
        }

    def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        options: dict[str, Any],
    ) -> dict[str, Any]:
        payload = {
            "model": model,
            "messages": messages,
            "tools": tools,
            "stream": False,
            "options": options,
            "think": False,
        }
        return self._request("/api/chat", payload)
