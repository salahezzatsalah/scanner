"""Runtime configuration, loaded from environment and ``.env``.

Defaults are deliberately conservative: ReconX should never be the reason a
target degrades. Raise the rate limits only as far as the program you are
testing permits.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RECONX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- storage ----------------------------------------------------------
    database_url: str = "sqlite+aiosqlite:///./data/reconx.db"
    data_dir: Path = Path("./data")

    # --- politeness -------------------------------------------------------
    requests_per_second_per_host: float = Field(default=5.0, gt=0)
    max_concurrent_requests: int = Field(default=20, ge=1)
    max_concurrent_hosts: int = Field(default=10, ge=1)
    http_timeout_seconds: float = Field(default=15.0, gt=0)
    dns_timeout_seconds: float = Field(default=5.0, gt=0)
    user_agent: str = "ReconX/0.1 (authorized security research)"
    max_retries: int = Field(default=2, ge=0)

    # --- verification engine ---------------------------------------------
    reproduce_attempts: int = Field(default=3, ge=1)
    reproduce_required: int = Field(default=3, ge=1)
    min_report_confidence: int = Field(default=50, ge=0, le=100)
    headless_xss_confirm: bool = True
    # Explicit Chromium path for XSS execution confirmation. Usually
    # unnecessary; set it when Playwright's bundled browser does not match the
    # one installed on the machine.
    chromium_path: str = ""
    # --- out-of-band callbacks -------------------------------------------
    # The SSRF collaborator is off by default. When enabled it binds loopback and
    # never contacts a third-party interaction service, because doing so would
    # publish the target's hostnames to someone outside the program.
    enable_oob_collaborator: bool = False
    oob_bind_host: str = "127.0.0.1"
    oob_bind_port: int = Field(default=0, ge=0, le=65535)
    # An address the *target* can reach, for testing a remote host. Setting this
    # is the operator's decision to expose a listener; the bind address above is
    # what actually opens a port.
    oob_public_base_url: str = ""
    oob_callback_timeout_seconds: float = Field(default=8.0, gt=0)

    # Number of random labels used to probe for wildcard DNS
    wildcard_probe_count: int = Field(default=3, ge=1)
    # Number of random paths used to learn a soft-404 fingerprint
    soft404_probe_count: int = Field(default=3, ge=1)

    # --- notifications ----------------------------------------------------
    discord_webhook: str = ""
    slack_webhook: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    generic_webhook: str = ""

    # --- api --------------------------------------------------------------
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    # Required before the API may bind to anything but loopback, because it
    # serves findings. See reconx.api.app.assert_safe_binding.
    api_token: str = ""

    # --- optional passive-source api keys ---------------------------------
    shodan_api_key: str = ""
    securitytrails_api_key: str = ""
    virustotal_api_key: str = ""
    github_token: str = ""

    @field_validator("reproduce_required")
    @classmethod
    def _required_not_above_attempts(cls, v: int, info) -> int:
        attempts = info.data.get("reproduce_attempts", 3)
        if v > attempts:
            raise ValueError(
                f"reproduce_required ({v}) cannot exceed reproduce_attempts ({attempts})"
            )
        return v

    @property
    def wordlist_dir(self) -> Path:
        return self.data_dir / "wordlists"

    @property
    def report_dir(self) -> Path:
        return self.data_dir / "reports"

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.wordlist_dir, self.report_dir):
            path.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return Settings()


def reset_settings_cache() -> None:
    """Drop the cached settings. Used by tests."""
    get_settings.cache_clear()
