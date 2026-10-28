"""Private CA and server certificate generation.

TLS material lives outside the vault on purpose: the vault is copied to
backups and other machines, and a server private key should not travel with
it. The CA is generated once by ``init`` and imported by every client.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.core.errors import DocVaultError

CA_DAYS = 3650
SERVER_DAYS = 825


@dataclass(frozen=True, slots=True)
class TlsMaterial:
    """Paths and public fingerprints from ``init``."""

    directory: Path
    ca_cert: Path
    ca_key: Path
    server_cert: Path
    server_key: Path
    ca_fingerprint: str
    server_fingerprint: str


def _fingerprint(certificate: x509.Certificate) -> str:
    digest = certificate.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def tls_directory(*, environment: str, config_path: Path | None, vault_root: Path) -> Path:
    """Production uses the OS config folder; development keeps it beside the vault."""
    if environment == "development":
        return vault_root.parent / "tls"
    if config_path is None:
        raise DocVaultError(
            "CONFIG_INVALID", detail="Cannot choose a TLS directory without a config path."
        )
    return config_path.parent / "tls"


def _host_sans(bind: str) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]
    try:
        address = ipaddress.ip_address(bind)
    except ValueError:
        hostname = socket.gethostname()
        with contextlib.suppress(OSError):
            hostname = socket.getfqdn() or hostname
        for name in {bind, hostname}:
            if name and name not in {"0.0.0.0", "::"}:  # noqa: S104 - compares, does not bind
                names.append(x509.DNSName(name))
    else:
        if not address.is_unspecified:
            names.append(x509.IPAddress(address))
        with contextlib.suppress(OSError):
            names.append(x509.DNSName(socket.gethostname()))
    # Stable order keeps the certificate reproducible for a given input.
    return sorted(set(names), key=lambda item: (item.__class__.__name__, str(item)))


def generate_tls(
    directory: Path,
    *,
    bind: str,
    common_name: str = "DocVault",
    force: bool = False,
) -> TlsMaterial:
    """Create a private CA and a server certificate, or return the existing pair."""
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        directory.chmod(0o700)
    ca_cert_path = directory / "docvault-ca.crt"
    ca_key_path = directory / "docvault-ca.key"
    server_cert_path = directory / "docvault-server.crt"
    server_key_path = directory / "docvault-server.key"

    if not force and all(
        path.is_file() for path in (ca_cert_path, ca_key_path, server_cert_path, server_key_path)
    ):
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
        server_cert = x509.load_pem_x509_certificate(server_cert_path.read_bytes())
        return TlsMaterial(
            directory=directory,
            ca_cert=ca_cert_path,
            ca_key=ca_key_path,
            server_cert=server_cert_path,
            server_key=server_key_path,
            ca_fingerprint=_fingerprint(ca_cert),
            server_fingerprint=_fingerprint(server_cert),
        )

    for path in (ca_cert_path, ca_key_path, server_cert_path, server_key_path):
        if path.exists() and not force:
            raise DocVaultError(
                "CONFIG_INVALID",
                detail=f"TLS material is incomplete and {path.name} already exists.",
                remediation="Move the TLS directory aside, or re-run with --force-tls.",
            )
        with contextlib.suppress(OSError):
            path.unlink()

    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocVault"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{common_name} private CA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocVault"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=SERVER_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(_host_sans(bind)), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_bytes = ca_cert.public_bytes(serialization.Encoding.PEM)
    ca_key_bytes = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    server_bytes = server_cert.public_bytes(serialization.Encoding.PEM)
    server_key_bytes = server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    _write_private(ca_key_path, ca_key_bytes)
    _write_private(server_key_path, server_key_bytes)
    ca_cert_path.write_bytes(ca_bytes)
    server_cert_path.write_bytes(server_bytes)
    if os.name == "posix":
        ca_cert_path.chmod(0o644)
        server_cert_path.chmod(0o644)

    return TlsMaterial(
        directory=directory,
        ca_cert=ca_cert_path,
        ca_key=ca_key_path,
        server_cert=server_cert_path,
        server_key=server_key_path,
        ca_fingerprint=_fingerprint(ca_cert),
        server_fingerprint=_fingerprint(server_cert),
    )


def public_fingerprint(path: Path) -> str:
    """Fingerprint of a certificate file, for ``status`` and client checks."""
    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise DocVaultError("CONFIG_INVALID", detail=f"Cannot read certificate {path}.") from exc
    return _fingerprint(certificate)
