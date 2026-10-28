"""Audit chain appends, rollover, and tamper detection."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.core.errors import DocVaultError
from app.core.time import now_utc
from app.vault import audit


def test_first_entry_starts_at_zero_hash(tmp_path: Path) -> None:
    # Act
    entry = audit.append_event(tmp_path, action="vault.created")

    # Assert
    assert entry["seq"] == 1
    assert entry["prev_hash"] == audit.ZERO_HASH
    without_hash = {k: v for k, v in entry.items() if k != "hash"}
    assert entry["hash"] == audit.entry_hash(audit.ZERO_HASH, without_hash)


def test_appends_chain_across_months(tmp_path: Path) -> None:
    # Arrange
    october = datetime(2026, 10, 31, 23, 59, tzinfo=UTC)
    november = datetime(2026, 11, 1, 0, 1, tzinfo=UTC)

    # Act
    first = audit.append_event(tmp_path, action="a", moment=october)
    second = audit.append_event(tmp_path, action="b", moment=november)
    check = audit.verify_chain(tmp_path)

    # Assert
    assert check.ok is True
    assert check.entries == 2
    assert second["seq"] == 2
    assert second["prev_hash"] == first["hash"]
    assert (tmp_path / "2026-10.jsonl").is_file()
    assert (tmp_path / "2026-11.jsonl").is_file()


def test_editing_a_middle_entry_breaks_the_chain(tmp_path: Path) -> None:
    # Arrange
    audit.append_event(tmp_path, action="one")
    audit.append_event(tmp_path, action="two")
    path = tmp_path / audit.month_for(now_utc())
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"action":"one"', '"action":"changed"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Act
    check = audit.verify_chain(tmp_path)

    # Assert
    assert check.ok is False
    assert check.first_bad_seq == 1


def test_removing_the_last_entry_is_not_detected(tmp_path: Path) -> None:
    """The documented limit: truncating the newest line leaves a valid chain."""
    # Arrange
    audit.append_event(tmp_path, action="one")
    audit.append_event(tmp_path, action="two")
    path = tmp_path / audit.month_for(now_utc())
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n", encoding="utf-8")

    # Act
    check = audit.verify_chain(tmp_path)

    # Assert
    assert check.ok is True
    assert check.entries == 1


def test_partial_last_line_stops_the_next_append(tmp_path: Path) -> None:
    # Arrange
    audit.append_event(tmp_path, action="one")
    path = tmp_path / audit.month_for(now_utc())
    before = path.read_bytes()
    path.write_bytes(before + b'{"seq":2,"ts":"2026-10-28T')

    # Act / Assert
    with pytest.raises(DocVaultError) as caught:
        audit.append_event(tmp_path, action="two")
    assert caught.value.code == "AUDIT_CHAIN_BROKEN"
    assert path.read_bytes() == before + b'{"seq":2,"ts":"2026-10-28T'
