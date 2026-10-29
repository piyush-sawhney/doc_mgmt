from __future__ import annotations

import base64

import pytest

from app.core.errors import DocVaultError
from app.services.auth import (
    LoginThrottle,
    _totp_code,
    hash_password,
    normalize_username,
    totp_uri,
    username_blind_index,
    validate_password,
    verify_totp,
)


def test_username_validation_normalizes_case_without_losing_punctuation() -> None:
    assert normalize_username("  Admin.User-1  ") == "admin.user-1"
    assert username_blind_index(b"x" * 32, "admin.user") != username_blind_index(
        b"x" * 32, "adminuser"
    )
    assert len(username_blind_index(b"x" * 32, "admin.user")) == 33


@pytest.mark.parametrize("username", ["ab", "bad name", "bad/name", "a" * 65])
def test_invalid_usernames_are_rejected(username: str) -> None:
    with pytest.raises(DocVaultError) as excinfo:
        normalize_username(username)
    assert excinfo.value.code == "VALIDATION_FAILED"


def test_password_hashes_use_argon2id_and_enforce_minimum_length() -> None:
    encoded = hash_password("a sufficiently long password")
    assert encoded.startswith("$argon2id$")
    with pytest.raises(DocVaultError) as excinfo:
        validate_password("short")
    assert excinfo.value.code == "PASSWORD_POLICY"


def test_totp_window_and_uri() -> None:
    secret = bytes(range(20))
    moment = 1_700_000_000
    code = _totp_code(secret, moment)
    assert verify_totp(secret, code, moment=moment)
    assert verify_totp(secret, code, moment=moment + 30)
    assert not verify_totp(secret, "not-six", moment=moment)
    uri, displayed_secret = totp_uri("operator", secret)
    assert uri.startswith("otpauth://totp/DocVault%3Aoperator?")
    assert base64.b32decode(displayed_secret + "=" * (-len(displayed_secret) % 8)) == secret


def test_login_throttle_enforces_username_and_ip_limits() -> None:
    throttle = LoginThrottle()
    for attempt in range(5):
        throttle.check("operator", "127.0.0.1", now=100.0 + attempt)
        throttle.failed("operator", "127.0.0.1", now=100.0 + attempt)
    with pytest.raises(DocVaultError) as excinfo:
        throttle.check("operator", "127.0.0.1", now=110.0)
    assert excinfo.value.code == "RATE_LIMITED"
    assert excinfo.value.retry_after == 290


def test_login_throttle_expires_attempts_after_window() -> None:
    throttle = LoginThrottle()
    for attempt in range(5):
        throttle.failed("operator", "127.0.0.1", now=100.0 + attempt)
    throttle.check("operator", "127.0.0.1", now=400.0)
