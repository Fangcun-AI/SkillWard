"""
Classification model service — Qwen3Guard-Gen-8B

Provides fast content safety classification (Layer 1).
Connects to vLLM via OpenAI-compatible API.
"""
import httpx
import math
import time
from typing import List, Tuple, Optional
from config import settings
from utils.logger import setup_logger


logger = setup_logger()


class ModelServiceError(Exception):
    """Raised when the model service is unavailable or returns an error."""
    pass


class CircuitBreaker:
    """Simple circuit breaker: after N consecutive failures, open the circuit
    and fail fast for a cooldown period before allowing a retry."""

    def __init__(self, failure_threshold: int = 5, cooldown_seconds: float = 30.0):
        self._failure_threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._state = "closed"

    def record_success(self):
        self._failure_count = 0
        self._state = "closed"

    def record_failure(self):
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._failure_count >= self._failure_threshold:
            self._state = "open"
            logger.warning(
                f"Circuit breaker OPEN after {self._failure_count} consecutive failures. "
                f"Requests will fail fast for {self._cooldown}s."
            )

    def allow_request(self) -> bool:
        if self._state == "closed":
            return True
        if self._state == "open":
            if time.time() - self._last_failure_time >= self._cooldown:
                self._state = "half_open"
                logger.info("Circuit breaker half-open: allowing probe request")
                return True
            return False
        return True

    @property
    def is_open(self) -> bool:
        return self._state == "open" and (time.time() - self._last_failure_time < self._cooldown)


class ModelService:
    """Classification model service (Qwen3Guard-Gen-8B)"""

    def __init__(self):
        self._circuit_breaker = CircuitBreaker(failure_threshold=5, cooldown_seconds=30.0)

        timeout = httpx.Timeout(30.0, connect=5.0)
        limits = httpx.Limits(max_keepalive_connections=100, max_connections=200)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            http2=False
        )
        self._headers = {
            "Authorization": f"Bearer {settings.guardrails_model_api_key}",
            "Content-Type": "application/json"
        }
        self._api_url = f"{settings.guardrails_model_api_url}/chat/completions"

    def _check_circuit_breaker(self):
        if not self._circuit_breaker.allow_request():
            raise ModelServiceError(
                "Circuit breaker OPEN: model service has failed repeatedly. "
                "Requests are being rejected to prevent cascade failure."
            )

    async def check_messages_with_scanner_definitions(
        self,
        messages: List[dict],
        scanner_definitions: List[str],
    ) -> Tuple[str, Optional[float]]:
        """
        Check content safety using Qwen3Guard-Gen-8B.

        Args:
            messages: List of message dicts with 'role' and 'content'.
            scanner_definitions: List of scanner definition strings (unused for Qwen3Guard).

        Returns:
            Tuple of (model_response, sensitivity_score)
            Model response format: "Safety: Safe/Unsafe\nCategories: ..."
        """
        self._check_circuit_breaker()
        try:
            # Qwen3Guard-Gen-8B: send raw messages directly.
            # vLLM applies the model's built-in chat template.
            prepared_messages = []
            for msg in messages:
                content = msg.get("content", "")
                if isinstance(content, list):
                    text_parts = []
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            text_parts.append(part.get("text", ""))
                    content = " ".join(text_parts)
                prepared_messages.append({
                    "role": msg.get("role", "user"),
                    "content": content
                })

            payload = {
                "model": settings.guardrails_model_name,
                "messages": prepared_messages,
                "temperature": 0.0,
                "logprobs": True,
                "max_tokens": 128
            }

            response = await self._client.post(
                self._api_url,
                json=payload,
                headers=self._headers
            )

            if response.status_code == 200:
                result_data = response.json()
                result = result_data["choices"][0]["message"]["content"].strip()

                # Extract sensitivity score from logprobs
                sensitivity_score = None
                choice = result_data["choices"][0]
                if "logprobs" in choice and choice["logprobs"]:
                    logprobs_data = choice["logprobs"]
                    if "content" in logprobs_data and logprobs_data["content"]:
                        first_token_logprob = logprobs_data["content"][0]["logprob"]
                        sensitivity_score = math.exp(first_token_logprob)

                logger.info(f"Classification result: {result}, sensitivity: {sensitivity_score}")
                self._circuit_breaker.record_success()
                return result, sensitivity_score
            else:
                raise Exception(f"API call failed with status {response.status_code}: {response.text}")

        except Exception as e:
            self._circuit_breaker.record_failure()
            logger.error(f"Model service error: {e}")
            raise ModelServiceError(f"Model service unavailable: {e}") from e

    async def close(self):
        if self._client:
            await self._client.aclose()


# Global instance
model_service = ModelService()
