from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    tinydb_path: Path = PROJECT_ROOT / "data" / "db.json"
    secret_key: str = Field(
        default="development-only-secret-change-before-deploy",
        min_length=32,
        validate_default=True,
    )
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    cookie_secure: bool = False

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings() # instancia







