"""
Guardian API Configuration — Settings management with persistent storage.

Priority: ~/.guardian/settings.json > environment variables > defaults
"""

import json
import os
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# Auto-load .env from guardian-api/ (next to this file).
# If .env is missing, do NOT fall back to .env.example — required settings
# must come from a real .env or already-exported environment variables.
from dotenv import load_dotenv
_env_path = Path(__file__).resolve().parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path, override=False)

SETTINGS_DIR = Path.home() / ".guardian"
SETTINGS_FILE = SETTINGS_DIR / "settings.json"

# Sentinel: if a masked key is submitted back, keep existing value
_MASK_PREFIX = "****"


@dataclass
class GuardianSettings:
    # LLM Provider for Stage 1 scoring (via litellm)
    llm_provider: str = "openai"          # azure, openai, local_vllm, custom (UI hint only)
    llm_model: str = ""                   # filled by LLM_PROVIDER + LLM_ID via PROVIDER_TABLE
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_api_version: str = ""             # Azure-specific; filled by LLM_API_VERSION

    # Docker sandbox settings
    docker_image: str = "fangcunai/skillward:amd64"
    docker_model: str = ""                 # model used inside Docker container
    docker_api_url: str = ""               # API base URL passed into Docker
    docker_api_key: str = ""               # API key passed into Docker
    docker_api_version: str = ""           # API version passed into Docker (Azure only, e.g. 2025-04-01-preview)

    # Safety thresholds
    safety_threshold: float = 0.3      # below this → UNSAFE (skip sandbox)
    sandbox_threshold: float = 0.9     # at/above this → clearly SAFE (skip sandbox)

    # Timeouts (seconds)
    phase1_timeout: int = 240
    phase2_timeout: int = 300
    max_retries: int = 2
    retry_delay: int = 10

    # FangcunGuard skill-audit API (optional, for 3-layer audit on host)
    fangcun_api_url: str = ""
    fangcun_api_key: str = ""

    # Guard plugin inside Docker container (runtime interception)
    guard_plugin_api_url: str = ""   # Override container's FANGCUN_GUARD_API_URL
    guard_plugin_api_key: str = ""   # Replace hardcoded key in container plugin

    def to_dict(self, mask_keys: bool = False) -> dict:
        d = asdict(self)
        if mask_keys:
            for k in ("llm_api_key", "docker_api_key", "fangcun_api_key", "guard_plugin_api_key"):
                v = d.get(k, "")
                if v and len(v) > 4:
                    d[k] = _MASK_PREFIX + v[-4:]
                elif v:
                    d[k] = _MASK_PREFIX
        return d


_settings: Optional[GuardianSettings] = None

# ──────────────────────────────────────────────────────────────────────
# Provider translation table — maps a single user-facing GUARDIAN_PROVIDER
# shorthand to the model-string formats expected by both
#   • litellm (Stage 1, host-side LLM safety scoring), and
#   • OpenClaw agent (Stage 2, in-container sandbox runtime).
#
# Add a new provider here in one place and both sides start working.
# Fields:
#   litellm_prefix      — provider prefix used by litellm (e.g. "azure", "openai", "deepseek")
#   openclaw_provider   — provider id baked into the OpenClaw bundle
#   default_base        — default API base URL (omit for Azure: per-tenant)
#   docker_base_suffix  — suffix appended to base for the Docker side only (Azure needs "/openai")
#   needs_version       — True if api_version is required (Azure)
# ──────────────────────────────────────────────────────────────────────
PROVIDER_TABLE = {
    "azure": {
        "litellm_prefix": "azure",
        "openclaw_provider": "azure-openai-responses",
        "docker_base_suffix": "/openai",
        "needs_version": True,
    },
    "openai": {
        "litellm_prefix": "openai",
        "openclaw_provider": "openai-responses",
        "default_base": "https://api.openai.com/v1",
    },
    "anthropic": {
        "litellm_prefix": "anthropic",
        "openclaw_provider": "anthropic",
        "default_base": "https://api.anthropic.com",
    },
    "gemini": {
        "litellm_prefix": "gemini",
        "openclaw_provider": "gemini",
        "default_base": "https://generativelanguage.googleapis.com",
    },
    "zhipu": {
        "litellm_prefix": "openai",          # litellm uses OpenAI-compat shim
        "openclaw_provider": "zai",
        "default_base": "https://open.bigmodel.cn/api/paas/v4",
    },
    "minimax": {
        "litellm_prefix": "openai",
        "openclaw_provider": "minimax-cn",
        "default_base": "https://api.minimaxi.com/v1",
    },
    "moonshot": {
        "litellm_prefix": "openai",
        "openclaw_provider": "moonshot",
        "default_base": "https://api.moonshot.cn/v1",
    },
    "qwen": {
        "litellm_prefix": "openai",
        "openclaw_provider": "qwen",
        "default_base": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    },
    "deepseek": {
        "litellm_prefix": "deepseek",
        "openclaw_provider": "openai",       # OpenClaw has no native deepseek; ride OpenAI shim
        "default_base": "https://api.deepseek.com/v1",
    },
    "doubao": {
        "litellm_prefix": "openai",
        "openclaw_provider": "doubao",
        "default_base": "https://ark.cn-beijing.volces.com/api/v3",
    },
    "xai": {
        "litellm_prefix": "xai",
        "openclaw_provider": "xai",
        "default_base": "https://api.x.ai/v1",
    },
    "groq": {
        "litellm_prefix": "groq",
        "openclaw_provider": "groq",
        "default_base": "https://api.groq.com/openai/v1",
    },
    "openrouter": {
        "litellm_prefix": "openrouter",
        "openclaw_provider": "openrouter",
        "default_base": "https://openrouter.ai/api/v1",
    },
    "mistral": {
        "litellm_prefix": "mistral",
        "openclaw_provider": "mistral",
        "default_base": "https://api.mistral.ai/v1",
    },
    "ollama": {
        "litellm_prefix": "ollama",
        "openclaw_provider": "ollama",
        "default_base": "http://localhost:11434",
    },
}

# Provider name aliases — let users type the name they're familiar with
PROVIDER_ALIASES = {
    "zai":          "zhipu",
    "glm":          "zhipu",
    "kimi":         "moonshot",
    "dashscope":    "qwen",
    "tongyi":       "qwen",
    "ark":          "doubao",
    "volcengine":   "doubao",
    "grok":         "xai",
    "minimax-cn":   "minimax",
    "minimaxi":     "minimax",
}


# Mapping: env var -> settings field
_ENV_MAP = {
    "GUARDIAN_DOCKER_IMAGE": "docker_image",
    "GUARDIAN_SAFETY_THRESHOLD": "safety_threshold",
    "GUARDIAN_SANDBOX_THRESHOLD": "sandbox_threshold",
    "GUARDIAN_PHASE1_TIMEOUT": "phase1_timeout",
    "GUARDIAN_PHASE2_TIMEOUT": "phase2_timeout",
    "GUARDIAN_MAX_RETRIES": "max_retries",
    "GUARDIAN_RETRY_DELAY": "retry_delay",
    "GUARDIAN_FANGCUN_API_URL": "fangcun_api_url",
    "GUARDIAN_FANGCUN_API_KEY": "fangcun_api_key",
    "GUARDIAN_GUARD_PLUGIN_API_URL": "guard_plugin_api_url",
    "GUARDIAN_GUARD_PLUGIN_API_KEY": "guard_plugin_api_key",
}


def load_settings() -> GuardianSettings:
    """Load settings from JSON file, then overlay environment variables."""
    s = GuardianSettings()
    file_keys = set()

    # 1. Load from persistent file
    if SETTINGS_FILE.exists():
        try:
            data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            for k, v in data.items():
                if hasattr(s, k):
                    file_keys.add(k)
                    expected_type = type(getattr(s, k))
                    try:
                        setattr(s, k, expected_type(v))
                    except (ValueError, TypeError):
                        setattr(s, k, v)
        except (json.JSONDecodeError, OSError):
            pass

    # 2. Override with environment variables (only if not already set from settings.json)
    for env_key, field_name in _ENV_MAP.items():
        val = os.environ.get(env_key)
        if val is not None and hasattr(s, field_name):
            # Skip env override if settings.json already has a non-empty value for this field
            current = getattr(s, field_name)
            if current and field_name in file_keys:
                continue
            if isinstance(current, float):
                setattr(s, field_name, float(val))
            elif isinstance(current, int):
                setattr(s, field_name, int(val))
            else:
                setattr(s, field_name, val)

    # 3. Unified API key / version fallbacks.
    #    AGENT_* takes priority for docker_*; LLM_* fills in as fallback.
    agent_key = os.environ.get("AGENT_API_KEY")
    shared_key = os.environ.get("LLM_API_KEY")
    if agent_key:
        if not s.docker_api_key:
            s.docker_api_key = agent_key
    if shared_key:
        if not s.llm_api_key:
            s.llm_api_key = shared_key
        if not s.docker_api_key:
            s.docker_api_key = shared_key

    agent_ver = os.environ.get("AGENT_API_VERSION")
    shared_ver = os.environ.get("LLM_API_VERSION")
    if agent_ver:
        if not s.docker_api_version:
            s.docker_api_version = agent_ver
    if shared_ver:
        if not s.llm_api_version:
            s.llm_api_version = shared_ver
        if not s.docker_api_version:
            s.docker_api_version = shared_ver

    # 4. Provider-table derivation.
    #    LLM_PROVIDER + LLM_ID   → derive llm_model / llm_base_url  (Stage A+B)
    #    AGENT_PROVIDER + AGENT_ID → derive docker_model / docker_api_url (Stage C)
    #    If AGENT_* is not set, LLM_* is used as fallback for Stage C as well.
    provider = (os.environ.get("LLM_PROVIDER") or "").strip().lower()
    model_id = (os.environ.get("LLM_ID") or "").strip()
    api_base = (os.environ.get("LLM_API_BASE") or "").strip()

    agent_provider = (os.environ.get("AGENT_PROVIDER") or "").strip().lower()
    agent_model_id = (os.environ.get("AGENT_ID") or "").strip()
    agent_api_base = (os.environ.get("AGENT_API_BASE") or "").strip()

    # If AGENT_* not set, fall back to LLM_* for Stage C
    if not agent_provider:
        agent_provider = provider
        agent_model_id = agent_model_id or model_id
        agent_api_base = agent_api_base or api_base

    def _resolve_provider(name, env_label):
        """Normalize alias and look up in PROVIDER_TABLE."""
        name = PROVIDER_ALIASES.get(name, name)
        spec = PROVIDER_TABLE.get(name)
        if spec is None:
            known = ", ".join(sorted(PROVIDER_TABLE.keys()))
            raise RuntimeError(
                f"Unknown {env_label}={name!r}. Known providers: {known}."
            )
        return name, spec

    # Stage A+B derivation
    if provider:
        provider, spec = _resolve_provider(provider, "LLM_PROVIDER")
        base = api_base or spec.get("default_base", "")

        if model_id and not s.llm_model:
            s.llm_model = f"{spec['litellm_prefix']}/{model_id}"
        if base and not s.llm_base_url:
            s.llm_base_url = base

        if spec.get("needs_version") and not s.llm_api_version:
            raise RuntimeError(
                f"Provider {provider!r} requires an API version. "
                f"Set LLM_API_VERSION (e.g. 2025-04-01-preview)."
            )

    # Stage C derivation
    if agent_provider:
        agent_provider, agent_spec = _resolve_provider(agent_provider, "AGENT_PROVIDER")
        agent_base = agent_api_base or agent_spec.get("default_base", "")
        profile = agent_provider

        if agent_model_id and not s.docker_model:
            s.docker_model = f"{agent_spec['openclaw_provider']}/{agent_model_id}@{profile}"
        if agent_base and not s.docker_api_url:
            s.docker_api_url = agent_base + agent_spec.get("docker_base_suffix", "")

        if agent_spec.get("needs_version") and not s.docker_api_version:
            raise RuntimeError(
                f"Provider {agent_provider!r} requires an API version. "
                f"Set AGENT_API_VERSION (e.g. 2025-04-01-preview)."
            )

    return s


def save_settings(s: GuardianSettings) -> None:
    """Atomically write settings to ~/.guardian/settings.json."""
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    data = s.to_dict(mask_keys=False)
    # Atomic write: temp file + rename
    fd, tmp_path = tempfile.mkstemp(dir=str(SETTINGS_DIR), suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, str(SETTINGS_FILE))
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


_REQUIRED_FIELDS = {
    "docker_image":   "GUARDIAN_DOCKER_IMAGE",
    "docker_model":   "AGENT_PROVIDER + AGENT_ID",
    "docker_api_url": "AGENT_PROVIDER (or LLM_PROVIDER)",
    "docker_api_key": "AGENT_API_KEY (or LLM_API_KEY)",
}


def _validate_required(s: GuardianSettings) -> None:
    missing = [env for field, env in _REQUIRED_FIELDS.items() if not getattr(s, field, "")]
    if missing:
        raise RuntimeError(
            "Missing required configuration: "
            + ", ".join(missing)
            + ". Set them in guardian-api/.env or as environment variables."
        )


def get_settings() -> GuardianSettings:
    """Singleton accessor — loads once, returns cached."""
    global _settings
    if _settings is None:
        _settings = load_settings()
        _validate_required(_settings)
    return _settings


def update_settings(partial: dict) -> GuardianSettings:
    """Partial update: merge new values into current settings, persist."""
    global _settings
    s = get_settings()

    for k, v in partial.items():
        if not hasattr(s, k):
            continue
        # Skip masked keys (user didn't change them)
        if isinstance(v, str) and v.startswith(_MASK_PREFIX):
            continue
        expected_type = type(getattr(s, k))
        try:
            setattr(s, k, expected_type(v))
        except (ValueError, TypeError):
            setattr(s, k, v)

    save_settings(s)
    _settings = s
    return s


def reset_settings() -> GuardianSettings:
    """Reset to defaults + env vars (deletes JSON file)."""
    global _settings
    if SETTINGS_FILE.exists():
        SETTINGS_FILE.unlink()
    _settings = load_settings()
    return _settings
