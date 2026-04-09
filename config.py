from typing import Optional
from pydantic_settings import BaseSettings
from pathlib import Path
import os


class Settings(BaseSettings):
    # Application
    app_name: str = "FangcunGuard-SkillsScanner"
    app_version: str = "1.0.0"
    debug: bool = False

    # Classification model (Layer 1): Qwen3Guard-Gen-8B
    guardrails_model_api_url: str = "http://localhost:58002/v1"
    guardrails_model_api_key: str = "your-guardrails-model-api-key"
    guardrails_model_name: str = "Qwen3Guard-Gen-8B"

    # Semantic model (Layer 2): Qwen3-8B
    general_llm_api_url: str = "http://localhost:58008/v1"
    general_llm_api_key: str = "your-general-llm-api-key"
    general_llm_model_name: str = "Qwen/Qwen3-8B"

    # Server
    host: str = "0.0.0.0"
    port: int = 5001
    workers: int = 4

    # Logging
    log_level: str = "INFO"
    data_dir: str = "./data"

    @property
    def log_dir(self) -> str:
        return f"{self.data_dir}/logs"

    # API key authentication (optional, leave empty to disable)
    api_secret_key: str = ""

    class Config:
        env_file = str(Path(__file__).with_name('.env'))
        case_sensitive = False
        extra = "allow"


settings = Settings()
