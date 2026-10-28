"""Passphrase policy from ``docs/05-crypto.md`` §8.1.

Length is necessary but not sufficient: a long phrase made of two dictionary
words is still weak. zxcvbn scores the pattern, and a small local list catches
the handful of phrases that show up in every office.
"""

from __future__ import annotations

from zxcvbn import zxcvbn

from app.core.errors import DocVaultError

MIN_LENGTH = 12
MIN_SCORE = 3

# This is not a password dictionary; it is the short list of phrases people
# type when they are trying to satisfy a length rule.
COMMON_PASSPHRASES = frozenset(
    {
        "passwordpassword",
        "password1234",
        "letmeinletmein",
        "qwertyqwerty",
        "administrator",
        "docvaultdocvault",
        "correcthorsebatterystaple",
        "thisisapassword",
        "changemeplease",
    }
)


def validate_passphrase(passphrase: str) -> None:
    """Raise ``PASSPHRASE_POLICY`` when the phrase is not acceptable."""
    if len(passphrase) < MIN_LENGTH:
        raise DocVaultError(
            "PASSPHRASE_POLICY",
            detail=f"The passphrase must be at least {MIN_LENGTH} characters.",
        )
    if passphrase.casefold() in COMMON_PASSPHRASES:
        raise DocVaultError(
            "PASSPHRASE_POLICY",
            detail="That passphrase is on the local common-phrase list.",
        )
    result = zxcvbn(passphrase)
    if int(result["score"]) < MIN_SCORE:
        raise DocVaultError(
            "PASSPHRASE_POLICY",
            detail="That passphrase is too predictable; use several unrelated words.",
        )
