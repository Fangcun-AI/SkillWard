"""
General-purpose LLM service — Qwen3-8B

Provides semantic analysis for Layer 2 skill audit.
Connects to vLLM via OpenAI-compatible API.
"""
import httpx
import time
from typing import List
from config import settings
from utils.logger import setup_logger


logger = setup_logger()


class GeneralLLMServiceError(Exception):
    """Raised when the general LLM service is unavailable or returns an error."""
    pass


class CircuitBreaker:
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
                f"General LLM circuit breaker OPEN after {self._failure_count} "
                f"consecutive failures. Failing fast for {self._cooldown}s."
            )

    def allow_request(self) -> bool:
        if self._state == "closed":
            return True
        if self._state == "open":
            if time.time() - self._last_failure_time >= self._cooldown:
                self._state = "half_open"
                return True
            return False
        return True


class GeneralLLMService:
    """General-purpose LLM service (Qwen3-8B) for semantic analysis."""

    def __init__(self):
        self._circuit_breaker = CircuitBreaker(failure_threshold=5, cooldown_seconds=30.0)

        timeout = httpx.Timeout(60.0, connect=5.0)
        limits = httpx.Limits(max_keepalive_connections=50, max_connections=100)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            http2=False
        )
        self._headers = {
            "Authorization": f"Bearer {settings.general_llm_api_key}",
            "Content-Type": "application/json"
        }
        self._api_url = f"{settings.general_llm_api_url}/chat/completions"
        self._model_name = settings.general_llm_model_name

    def _check_circuit_breaker(self):
        if not self._circuit_breaker.allow_request():
            raise GeneralLLMServiceError(
                "Circuit breaker OPEN: general LLM service has failed repeatedly."
            )

    async def chat(self, messages: List[dict], temperature: float = 0.0) -> str:
        """Send messages to LLM and return response text."""
        self._check_circuit_breaker()
        try:
            payload = {
                "model": self._model_name,
                "messages": messages,
                "temperature": temperature
            }
            response = await self._client.post(
                self._api_url,
                json=payload,
                headers=self._headers
            )
            if response.status_code == 200:
                result = response.json()["choices"][0]["message"]["content"].strip()
                self._circuit_breaker.record_success()
                return result
            else:
                raise Exception(f"API call failed with status {response.status_code}")
        except Exception as e:
            self._circuit_breaker.record_failure()
            logger.error(f"General LLM service error: {e}")
            raise GeneralLLMServiceError(f"General LLM service unavailable: {e}") from e

    async def close(self):
        if self._client:
            await self._client.aclose()


# Global instance
general_llm_service = GeneralLLMService()
