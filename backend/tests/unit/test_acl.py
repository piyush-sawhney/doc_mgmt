from __future__ import annotations

import pytest

from app.services.acl import PRINT, READ, VIEW, close_down, close_up


@pytest.mark.parametrize(
    ("grant", "expected"),
    [(PRINT, PRINT | READ | VIEW), (READ, READ | VIEW), (VIEW, VIEW)],
)
def test_allow_closure(grant: int, expected: int) -> None:
    assert close_up(grant) == expected


@pytest.mark.parametrize(
    ("denial", "expected"),
    [(VIEW, VIEW | READ | PRINT), (READ, READ | PRINT), (PRINT, PRINT)],
)
def test_deny_closure(denial: int, expected: int) -> None:
    assert close_down(denial) == expected
