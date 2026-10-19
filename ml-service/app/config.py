from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    model_dir: Path = Path("models")
    api_key: str | None = None  # when set, every endpoint except /health requires the X-API-Key header
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(model_dir=Path(os.environ.get("MODEL_DIR", "models")), api_key=os.environ.get("ML_API_KEY") or None, log_level=os.environ.get("LOG_LEVEL", "info").upper())
