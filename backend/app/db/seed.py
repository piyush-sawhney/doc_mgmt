"""The seeded document-type catalogue from ``docs/13`` §4.

Names are encrypted with ``meta_key``, so this cannot be a plain SQL migration:
the vault must be unlocked before it runs. The operation is idempotent and
matches on ``code``; it never rewrites an existing row, because an office may
have renamed a type and that rename must survive an upgrade.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from sqlalchemy import Connection, insert, select

from app.core.errors import DocVaultError
from app.crypto.keys import encrypt_column
from app.db.enums import ConfLevel, SideKind
from app.db.models import DocType

SEED_TABLE = "doc_types"


@dataclass(frozen=True, slots=True)
class TypeSpec:
    code: str
    name: str
    sensitivity: ConfLevel
    requires_expiry: bool = False
    side: SideKind | None = None


@dataclass(frozen=True, slots=True)
class CategorySpec:
    code: str
    name: str
    types: tuple[TypeSpec, ...]


@dataclass(frozen=True, slots=True)
class SeedResult:
    categories_inserted: int
    types_inserted: int
    categories_total: int
    types_total: int

    @property
    def inserted(self) -> int:
        return self.categories_inserted + self.types_inserted


def _type(
    code: str,
    name: str,
    sensitivity: ConfLevel,
    *,
    expiry: bool = False,
    side: SideKind | None = None,
) -> TypeSpec:
    return TypeSpec(
        code=code,
        name=name,
        sensitivity=sensitivity,
        requires_expiry=expiry,
        side=side,
    )


CATALOGUE: tuple[CategorySpec, ...] = (
    CategorySpec(
        code="identity",
        name="Identity and KYC",
        types=(
            _type("pan_card", "PAN card", ConfLevel.SENSITIVE),
            _type("aadhaar", "Aadhaar", ConfLevel.SENSITIVE),
            _type("passport", "Passport", ConfLevel.SENSITIVE, expiry=True),
            _type("voter_id", "Voter ID", ConfLevel.SENSITIVE),
            _type("driving_licence", "Driving licence", ConfLevel.SENSITIVE, expiry=True),
            _type("photograph", "Photograph", ConfLevel.SENSITIVE),
            _type("signature_specimen", "Signature specimen", ConfLevel.RESTRICTED),
            _type("address_proof", "Address proof", ConfLevel.SENSITIVE),
            _type(
                "pan_card_front",
                "PAN card (front)",
                ConfLevel.SENSITIVE,
                side=SideKind.FRONT,
            ),
            _type(
                "pan_card_back",
                "PAN card (back)",
                ConfLevel.SENSITIVE,
                side=SideKind.BACK,
            ),
            _type(
                "aadhaar_front",
                "Aadhaar (front)",
                ConfLevel.SENSITIVE,
                side=SideKind.FRONT,
            ),
            _type(
                "aadhaar_back",
                "Aadhaar (back)",
                ConfLevel.SENSITIVE,
                side=SideKind.BACK,
            ),
        ),
    ),
    CategorySpec(
        code="property",
        name="Property and assets",
        types=(
            _type("sale_deed", "Sale deed", ConfLevel.RESTRICTED),
            _type("purchase_agreement", "Agreement to sell", ConfLevel.SENSITIVE),
            _type("lease_deed", "Lease deed", ConfLevel.SENSITIVE, expiry=True),
            _type("rent_agreement", "Rent agreement", ConfLevel.NORMAL, expiry=True),
            _type(
                "encumbrance_certificate",
                "Encumbrance certificate",
                ConfLevel.SENSITIVE,
                expiry=True,
            ),
            _type("mutation_record", "Mutation record", ConfLevel.SENSITIVE),
            _type(
                "land_record",
                "Land record (khata / 7-12 extract)",
                ConfLevel.SENSITIVE,
                expiry=True,
            ),
            _type("property_tax_receipt", "Property tax receipt", ConfLevel.NORMAL, expiry=True),
            _type("floor_plan", "Floor plan or drawing", ConfLevel.NORMAL),
            _type("possession_letter", "Possession letter", ConfLevel.SENSITIVE),
            _type("mortgage_deed", "Mortgage deed", ConfLevel.RESTRICTED),
            _type("property_noc", "NOC (society or municipal)", ConfLevel.NORMAL, expiry=True),
            _type("valuation_report", "Valuation report", ConfLevel.SENSITIVE, expiry=True),
        ),
    ),
    CategorySpec(
        code="legal",
        name="Legal and court",
        types=(
            _type("power_of_attorney", "Power of attorney", ConfLevel.RESTRICTED, expiry=True),
            _type("affidavit", "Affidavit", ConfLevel.RESTRICTED),
            _type("indemnity_bond", "Indemnity bond", ConfLevel.RESTRICTED),
            _type("court_order", "Court order", ConfLevel.RESTRICTED),
            _type("legal_notice", "Legal notice", ConfLevel.RESTRICTED),
            _type("plaint", "Plaint or petition", ConfLevel.RESTRICTED),
            _type("written_statement", "Written statement", ConfLevel.RESTRICTED),
            _type("settlement_agreement", "Settlement agreement", ConfLevel.RESTRICTED),
            _type("arbitration_award", "Arbitration award", ConfLevel.RESTRICTED),
            _type("will", "Will or testament", ConfLevel.RESTRICTED),
            _type("trust_deed", "Trust deed", ConfLevel.RESTRICTED),
            _type("partnership_deed", "Partnership deed", ConfLevel.RESTRICTED),
        ),
    ),
    CategorySpec(
        code="corporate",
        name="Corporate and secretarial",
        types=(
            _type(
                "certificate_of_incorporation",
                "Certificate of incorporation",
                ConfLevel.SENSITIVE,
            ),
            _type("moa", "Memorandum of association", ConfLevel.SENSITIVE),
            _type("aoa", "Articles of association", ConfLevel.SENSITIVE),
            _type("share_certificate", "Share certificate", ConfLevel.RESTRICTED),
            _type("share_transfer_form", "Share transfer form (SH-4)", ConfLevel.RESTRICTED),
            _type("board_resolution", "Board resolution", ConfLevel.SENSITIVE),
            _type("agm_minutes", "AGM or EGM minutes", ConfLevel.SENSITIVE),
            _type("register_of_members", "Register of members", ConfLevel.RESTRICTED),
            _type("director_change", "Director change (DIR-12)", ConfLevel.SENSITIVE),
            _type("auditor_appointment", "Auditor appointment", ConfLevel.SENSITIVE, expiry=True),
            _type(
                "charge_registration",
                "Charge registration (CHG-1)",
                ConfLevel.SENSITIVE,
                expiry=True,
            ),
            _type("annual_return", "Annual return (MGT-7)", ConfLevel.NORMAL, expiry=True),
        ),
    ),
    CategorySpec(
        code="finance",
        name="Financial and tax",
        types=(
            _type("itr_acknowledgement", "ITR acknowledgement", ConfLevel.SENSITIVE, expiry=True),
            _type("form_26as", "Form 26AS", ConfLevel.SENSITIVE, expiry=True),
            _type("balance_sheet", "Balance sheet", ConfLevel.SENSITIVE, expiry=True),
            _type("profit_and_loss", "Profit and loss statement", ConfLevel.SENSITIVE, expiry=True),
            _type("bank_statement", "Bank statement", ConfLevel.SENSITIVE, expiry=True),
            _type("cheque", "Cheque", ConfLevel.RESTRICTED),
            _type("loan_sanction", "Loan sanction letter", ConfLevel.SENSITIVE, expiry=True),
            _type("gst_registration", "GST registration (REG-06)", ConfLevel.SENSITIVE),
            _type("gst_return", "GST return", ConfLevel.SENSITIVE, expiry=True),
            _type(
                "tds_certificate",
                "TDS certificate (16 / 16A)",
                ConfLevel.SENSITIVE,
                expiry=True,
            ),
            _type("invoice", "Invoice", ConfLevel.NORMAL),
        ),
    ),
    CategorySpec(
        code="employment",
        name="Employment and HR",
        types=(
            _type("appointment_letter", "Appointment letter", ConfLevel.SENSITIVE),
            _type("employment_contract", "Employment contract", ConfLevel.SENSITIVE, expiry=True),
            _type("relieving_letter", "Relieving letter", ConfLevel.NORMAL),
            _type("experience_letter", "Experience letter", ConfLevel.NORMAL),
            _type("salary_slip", "Salary slip", ConfLevel.SENSITIVE, expiry=True),
            _type("pf_record", "PF statement", ConfLevel.SENSITIVE, expiry=True),
            _type("form_16", "Form 16", ConfLevel.SENSITIVE, expiry=True),
        ),
    ),
    CategorySpec(
        code="insurance",
        name="Insurance",
        types=(
            _type("policy_document", "Policy document", ConfLevel.SENSITIVE, expiry=True),
            _type("premium_receipt", "Premium receipt", ConfLevel.NORMAL, expiry=True),
            _type("claim_form", "Claim form", ConfLevel.SENSITIVE),
        ),
    ),
    CategorySpec(
        code="other",
        name="Correspondence and other",
        types=(
            _type("correspondence", "Letter or email printout", ConfLevel.NORMAL),
            _type("courier_receipt", "Courier or post receipt", ConfLevel.NORMAL),
            _type("miscellaneous", "Miscellaneous", ConfLevel.NORMAL),
        ),
    ),
)


def catalogue_size() -> tuple[int, int]:
    """Return ``(categories, types)`` for tests and diagnostics."""
    return len(CATALOGUE), sum(len(category.types) for category in CATALOGUE)


def _encrypted(meta_key: bytes, column: str, value: str) -> bytes:
    sealed = encrypt_column(meta_key, SEED_TABLE, column, value)
    if sealed is None:  # pragma: no cover - value is never None
        raise DocVaultError("SEED_FAILED", detail=f"Could not encrypt doc_types.{column}.")
    return sealed


def _existing_id(
    connection: Connection, code: str, *, parent_id: uuid.UUID | None
) -> uuid.UUID | None:
    row = connection.execute(
        select(DocType.id, DocType.parent_id).where(DocType.code == code)
    ).one_or_none()
    if row is None:
        return None
    if row.parent_id != parent_id:
        where = "a category" if parent_id is None else "a type in another category"
        raise DocVaultError(
            "SEED_CONFLICT",
            detail=f"doc_types.{code} already exists as {where}.",
            remediation="Rename or remove the conflicting row, then run the seed again.",
        )
    return cast(uuid.UUID, row.id)


def seed_catalogue(connection: Connection, *, meta_key: bytes) -> SeedResult:
    """Insert anything missing from the catalogue; never change an existing row.

    The caller owns the transaction. ``docvault migrate`` and ``init`` run this
    after the vault is unlocked, because the display names are encrypted.
    """
    categories_inserted = 0
    types_inserted = 0
    categories_total = 0
    types_total = 0

    for category_order, category in enumerate(CATALOGUE, start=1):
        category_id = _existing_id(connection, category.code, parent_id=None)
        if category_id is None:
            category_id = uuid.uuid7()
            connection.execute(
                insert(DocType).values(
                    id=category_id,
                    code=category.code,
                    name_enc=_encrypted(meta_key, "name", category.name),
                    parent_id=None,
                    default_confidentiality=ConfLevel.NORMAL,
                    retention_months=None,
                    requires_expiry=False,
                    side=None,
                    purpose_enc=None,
                    is_system=True,
                    sort_order=category_order * 10,
                )
            )
            categories_inserted += 1
        categories_total += 1

        for type_order, spec in enumerate(category.types, start=1):
            type_id = _existing_id(connection, spec.code, parent_id=category_id)
            if type_id is not None:
                types_total += 1
                continue
            connection.execute(
                insert(DocType).values(
                    id=uuid.uuid7(),
                    code=spec.code,
                    name_enc=_encrypted(meta_key, "name", spec.name),
                    parent_id=category_id,
                    default_confidentiality=spec.sensitivity,
                    retention_months=None,
                    requires_expiry=spec.requires_expiry,
                    side=spec.side,
                    purpose_enc=None,
                    is_system=True,
                    sort_order=type_order * 10,
                )
            )
            types_inserted += 1
            types_total += 1

    return SeedResult(
        categories_inserted=categories_inserted,
        types_inserted=types_inserted,
        categories_total=categories_total,
        types_total=types_total,
    )


def iter_codes() -> Iterable[str]:
    """Yield every seeded code, categories first. Useful for diagnostics."""
    for category in CATALOGUE:
        yield category.code
        for spec in category.types:
            yield spec.code
