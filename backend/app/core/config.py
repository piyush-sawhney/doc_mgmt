"""Typed configuration loaded once at the process boundary.

The file is TOML, holds no secrets, and is validated before anything else
starts. Unknown keys are rejected on purpose: a typo in ``vault.root`` should
not silently fall back to a default.
"""

from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.core.errors import DocVaultError

ENV_CONFIG = "DOCVAULT_CONFIG"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"})


def default_config_path() -> Path:
    """Return the OS-standard configuration path."""
    if os.name == "nt":  # pragma: no cover - exercised on Windows
        base = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        return base / "DocVault" / "docvault.toml"
    return Path("/etc/docvault/docvault.toml")


def _absolute_path(value: Path | None) -> Path | None:
    if value is None:
        return None
    if not value.is_absolute():
        raise ValueError("must be an absolute path")
    return value


class ServerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bind: str = "127.0.0.1"
    port: int = Field(default=8443, ge=1, le=65535)


class VaultSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root: Path | None = None
    auto_unlock: bool = False

    @field_validator("root", mode="before")
    @classmethod
    def empty_root_is_none(cls, value: object) -> object:
        if value == "":
            return None
        return value

    @field_validator("root")
    @classmethod
    def root_is_absolute(cls, value: Path | None) -> Path | None:
        return _absolute_path(value)


class DatabaseSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dsn: str
    pg_bin_dir: Path
    # The default is loopback-only. An operator may opt out explicitly.
    allow_remote: bool = False

    @field_validator("dsn")
    @classmethod
    def dsn_scheme(cls, value: str) -> str:
        if not value.startswith(("postgresql://", "postgres://")):
            raise ValueError("must be a postgresql:// DSN")
        return value

    @field_validator("pg_bin_dir")
    @classmethod
    def bin_dir_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("must be an absolute path")
        return value

    @model_validator(mode="after")
    def loopback_only(self) -> DatabaseSettings:
        if self.allow_remote:
            return self
        parts = urlsplit(self.dsn)
        host = parts.hostname
        if host is None:
            socket_host = parse_qs(parts.query).get("host", [""])[0]
            if socket_host.startswith("/"):
                return self
            raise ValueError("DSN must name a loopback host or a Unix socket")
        if host not in LOOPBACK_HOSTS:
            raise ValueError(f"database host {host!r} is not loopback")
        return self


class BackupSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Ordinary dumps kept on rotation. Pre-migration dumps are never removed.
    keep: int = Field(default=7, ge=1, le=365)


class LimitSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_file_bytes: int = Field(default=100 * 1024 * 1024, gt=0)


class RenderSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cache_bytes: int = Field(default=5 * 1024 * 1024 * 1024, ge=0)


class OfficeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    convert_exe: Path | None = None

    @field_validator("convert_exe", mode="before")
    @classmethod
    def empty_exe_is_none(cls, value: object) -> object:
        if value == "":
            return None
        return value


class LogSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: Literal["debug", "info", "warning", "error"] = "info"


class Settings(BaseModel):
    """The whole validated configuration."""

    model_config = ConfigDict(extra="forbid")

    environment: Literal["development", "production"] = "production"
    server: ServerSettings = Field(default_factory=ServerSettings)
    vault: VaultSettings = Field(default_factory=VaultSettings)
    database: DatabaseSettings
    backup: BackupSettings = Field(default_factory=BackupSettings)
    limits: LimitSettings = Field(default_factory=LimitSettings)
    render: RenderSettings = Field(default_factory=RenderSettings)
    office: OfficeSettings = Field(default_factory=OfficeSettings)
    log: LogSettings = Field(default_factory=LogSettings)

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    def require_vault_root(self) -> Path:
        if self.vault.root is None:
            raise DocVaultError(
                "CONFIG_INVALID",
                detail="vault.root is empty.",
                remediation="Set vault.root or run docvault init --vault <path>.",
            )
        return self.vault.root


class LoadedSettings(BaseModel):
    """Settings plus the file they came from, for diagnostics and writes."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    settings: Settings
    path: Path | None = None


def load_settings(path: Path | None = None) -> LoadedSettings:
    """Read and validate the TOML configuration.

    Raises:
        DocVaultError: ``CONFIG_MISSING`` or ``CONFIG_INVALID``.
    """
    config_path = path or Path(os.environ.get(ENV_CONFIG, default_config_path()))
    config_path = config_path.expanduser()
    if not config_path.is_file():
        raise DocVaultError(
            "CONFIG_MISSING",
            detail=f"No configuration file at {config_path}.",
        )
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise DocVaultError("CONFIG_INVALID", detail=f"Cannot read {config_path}: {exc}") from exc

    try:
        settings = Settings.model_validate(raw)
    except ValidationError as exc:
        fields = [
            {
                "field": ".".join(str(part) for part in error["loc"]),
                "code": str(error["type"]),
                "message": str(error["msg"]),
            }
            for error in exc.errors()
        ]
        raise DocVaultError(
            "CONFIG_INVALID",
            detail=f"{config_path} has invalid values.",
            fields=fields,
        ) from exc

    return LoadedSettings(settings=settings, path=config_path)


def write_vault_root(config_path: Path, root: Path) -> None:
    """Point an existing TOML file at a vault without disturbing comments.

    ``init`` and ``restore`` use this. Only the ``root`` key under ``[vault]``
    is replaced; everything else is left as the operator wrote it.
    """
    if not root.is_absolute():
        raise DocVaultError("CONFIG_INVALID", detail="The vault root must be absolute.")
    lines = config_path.read_text(encoding="utf-8").splitlines()
    rendered = f"root = {json.dumps(str(root))}"
    in_vault = False
    replaced = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_vault = stripped == "[vault]"
            continue
        if in_vault and stripped.startswith("root") and "=" in stripped:
            lines[index] = rendered
            replaced = True
            break
    if not replaced:
        if not any(line.strip() == "[vault]" for line in lines):
            lines.extend(["", "[vault]"])
        lines.append(rendered)
    config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
