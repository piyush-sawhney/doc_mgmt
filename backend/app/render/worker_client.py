"""Run untrusted document operations in a networkless, filesystem-confined process."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from app.core.errors import DocVaultError

MAX_WORKER_OUTPUT = 128 * 1024 * 1024


def _sandbox_command(converter: Path | None) -> tuple[list[str], str | None]:
    if sys.platform != "linux":
        raise DocVaultError(
            "NOT_READY",
            detail="The isolated render worker is not configured for this operating system.",
        )
    bubblewrap = shutil.which("bwrap")
    if bubblewrap is None:
        raise DocVaultError(
            "NOT_READY",
            detail="bubblewrap is required to run the isolated document worker.",
        )
    worker_package = Path(__file__).resolve().parents[2] / "worker"
    venv_root = Path(sys.prefix).resolve()
    command = [
        bubblewrap,
        "--unshare-net",
        "--die-with-parent",
        "--new-session",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--symlink",
        "usr/bin",
        "/bin",
        "--ro-bind",
        "/etc",
        "/etc",
        "--ro-bind",
        str(venv_root),
        "/venv",
        "--dir",
        "/worker",
        "--ro-bind",
        str(worker_package),
        "/worker/worker",
        "--tmpfs",
        "/tmp",  # noqa: S108
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--chdir",
        "/tmp",  # noqa: S108
    ]
    converter_in_sandbox = None
    if converter is not None:
        converter = converter.resolve()
        if not converter.is_file() or not os.access(converter, os.X_OK):
            raise DocVaultError(
                "UNSUPPORTED_MEDIA_TYPE",
                detail=(
                    "Office conversion is unavailable because the configured converter is missing."
                ),
            )
        try:
            converter.relative_to(Path("/usr"))
            converter_in_sandbox = str(converter)
        except ValueError:
            command.extend(["--dir", "/converter", "--ro-bind", str(converter), "/converter/bin"])
            converter_in_sandbox = "/converter/bin"
    command.extend(
        [
            "/venv/bin/python",
            "-m",
            "worker.main",
        ]
    )
    return command, converter_in_sandbox


def run_worker(
    payload: dict[str, Any],
    *,
    timeout_seconds: int = 60,
    converter: Path | None = None,
) -> dict[str, Any]:
    command, converter_sandbox_path = _sandbox_command(converter)
    request = dict(payload)
    if converter is not None:
        request["converter"] = converter_sandbox_path
    request_json = json.dumps(request, separators=(",", ":")).encode("utf-8")
    environment = {
        "HOME": "/tmp",  # noqa: S108
        "PATH": os.defpath,
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": "/worker",
    }
    try:
        completed = subprocess.run(
            command,
            input=request_json,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise DocVaultError(
            "TIMEOUT", detail="Document processing exceeded its time limit."
        ) from exc
    except OSError as exc:
        raise DocVaultError(
            "NOT_READY", detail="The isolated document worker could not be started."
        ) from exc
    if completed.returncode != 0:
        raise DocVaultError(
            "BLOB_INVALID",
            detail="The isolated document worker rejected or could not process the input.",
        )
    if len(completed.stdout) > MAX_WORKER_OUTPUT:
        raise DocVaultError("STORAGE_FULL", detail="The document worker output exceeds its limit.")
    try:
        result = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DocVaultError(
            "BLOB_INVALID", detail="The document worker returned invalid output."
        ) from exc
    if not isinstance(result, dict):
        raise DocVaultError(
            "BLOB_INVALID", detail="The document worker returned an invalid result."
        )
    return result


def inspect_pdf(data: bytes) -> dict[str, Any]:
    return run_worker(
        {"operation": "inspect_pdf", "data": base64.b64encode(data).decode("ascii")},
        timeout_seconds=30,
    )


def convert_office(data: bytes, *, filename: str, converter: Path) -> bytes:
    result = run_worker(
        {
            "operation": "convert_office",
            "data": base64.b64encode(data).decode("ascii"),
            "filename": filename,
        },
        timeout_seconds=90,
        converter=converter,
    )
    try:
        converted = base64.b64decode(result["data"], validate=True)
    except (KeyError, ValueError) as exc:
        raise DocVaultError(
            "BLOB_INVALID", detail="The Office converter returned invalid data."
        ) from exc
    if len(converted) > 100 * 1024 * 1024:
        raise DocVaultError("PAYLOAD_TOO_LARGE", detail="The converted PDF exceeds 100 MiB.")
    return converted


def render_page(
    data: bytes,
    *,
    mime: str,
    page: int,
    recipe: dict[str, Any],
    max_edge: int = 1200,
) -> tuple[bytes, dict[str, Any]]:
    result = run_worker(
        {
            "operation": "render_page",
            "data": base64.b64encode(data).decode("ascii"),
            "mime": mime,
            "page": page,
            "recipe": recipe,
            "max_edge": max_edge,
        }
    )
    return base64.b64decode(result["data"], validate=True), {
        key: value for key, value in result.items() if key != "data"
    }


def compose_pdf(pages: list[dict[str, Any]], *, layout: dict[str, Any]) -> bytes:
    sources: dict[str, dict[str, str]] = {}
    page_refs: list[dict[str, Any]] = []
    for page in pages:
        source_data = page["data"]
        source_mime = page["mime"]
        source_key = hashlib.sha256(source_mime.encode("ascii") + b"\x00" + source_data).hexdigest()
        sources.setdefault(
            source_key,
            {
                "mime": source_mime,
                "data": base64.b64encode(source_data).decode("ascii"),
            },
        )
        page_refs.append(
            {
                "source": source_key,
                "page": page["page"],
                "recipe": page.get("recipe", {}),
            }
        )
    result = run_worker(
        {"operation": "compose_pdf", "sources": sources, "pages": page_refs, "layout": layout},
        timeout_seconds=120,
    )
    try:
        return base64.b64decode(result["data"], validate=True)
    except (KeyError, ValueError) as exc:
        raise DocVaultError(
            "BLOB_INVALID", detail="The print worker returned invalid data."
        ) from exc
