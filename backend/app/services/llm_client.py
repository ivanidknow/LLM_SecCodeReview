"""
OllamaClient — Async LLM client for local Ollama instance.

Streams responses chunk-by-chunk for real-time terminal display.
Supports model discovery and dynamic model selection.
"""

import json
import logging
from typing import AsyncGenerator

import httpx

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3"


class OllamaClient:
    """Async client for the Ollama local LLM API."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL):
        self.base_url = base_url.rstrip("/")

    async def health_check(self) -> bool:
        """Check if Ollama is running."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException):
            return False

    async def get_local_models(self) -> list[str]:
        """
        Fetch the list of locally available models from Ollama.

        Returns:
            List of model names (e.g. ["llama3:latest", "mistral:7b"]).
            Empty list if Ollama is offline.
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                if resp.status_code != 200:
                    return []
                data = resp.json()
                models = data.get("models", [])
                return [m["name"] for m in models if "name" in m]
        except (httpx.ConnectError, httpx.TimeoutException):
            logger.warning("Ollama offline — cannot fetch models")
            return []
        except Exception as e:
            logger.exception("Error fetching Ollama models: %s", e)
            return []

    async def generate_response(
        self,
        prompt: str,
        system: str = "",
        model: str = DEFAULT_MODEL,
    ) -> AsyncGenerator[str, None]:
        """
        Stream a response from Ollama's /api/generate endpoint.

        Args:
            prompt: The user's query.
            system: System message (e.g., .cursorrules content).
            model: Ollama model name.

        Yields:
            Text chunks as they arrive from the model.
        """
        payload = {
            "model": model,
            "prompt": prompt,
            "system": system,
            "stream": True,
            "options": {
                "temperature": 0.1,
                "num_predict": 4096,
                "top_p": 0.9,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(
                connect=10.0, read=120.0, write=10.0, pool=10.0,
            )) as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/api/generate",
                    json=payload,
                ) as response:
                    if response.status_code != 200:
                        error_body = await response.aread()
                        yield f"\n[ERROR] Ollama returned {response.status_code}: {error_body.decode()}"
                        return

                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                            text = chunk.get("response", "")
                            if text:
                                yield text
                            if chunk.get("done", False):
                                return
                        except json.JSONDecodeError:
                            continue

        except httpx.ConnectError:
            logger.error("Ollama is not running at %s", self.base_url)
            yield "\n[OLLAMA_OFFLINE] Cannot connect to Ollama. Start with: ollama serve"

        except httpx.TimeoutException:
            logger.error("Ollama request timed out")
            yield "\n[TIMEOUT] Ollama response timed out. Try a smaller model or shorter prompt."

        except Exception as e:
            logger.exception("Unexpected Ollama error")
            yield f"\n[ERROR] {e}"


# Singleton
ollama = OllamaClient()
