"""Associate one-use tickets with rendition cache entries."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "7e4c2b9a1f30"
down_revision = "c02412ca4b8b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DELETE FROM renditions")
    op.add_column(
        "renditions",
        sa.Column("blob_salt", sa.LargeBinary(), nullable=False),
    )
    op.add_column(
        "document_versions",
        sa.Column("derived_pdf_pages", sa.Integer(), nullable=True),
    )
    op.add_column(
        "document_versions",
        sa.Column("derived_pdf_size", sa.BigInteger(), nullable=True),
    )
    op.create_check_constraint(
        "ck_document_versions_derived_pdf_pages_pair",
        "document_versions",
        "(derived_pdf_addr IS NULL) = (derived_pdf_pages IS NULL)",
    )
    op.create_check_constraint(
        "ck_document_versions_derived_pdf_size_pair",
        "document_versions",
        "(derived_pdf_addr IS NULL) = (derived_pdf_size IS NULL)",
    )
    op.create_check_constraint(
        "ck_document_versions_derived_pdf_pages_positive",
        "document_versions",
        "derived_pdf_pages IS NULL OR derived_pdf_pages > 0",
    )
    op.create_check_constraint(
        "ck_document_versions_derived_pdf_size_non_negative",
        "document_versions",
        "derived_pdf_size IS NULL OR derived_pdf_size >= 0",
    )
    op.add_column(
        "download_tickets",
        sa.Column("rendition_id", sa.UUID(), nullable=True),
    )
    op.create_foreign_key(
        "fk_download_tickets_rendition_id_renditions",
        "download_tickets",
        "renditions",
        ["rendition_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.add_column(
        "renditions",
        sa.Column(
            "is_saved_recipe",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    op.add_column(
        "renditions",
        sa.Column("page_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column(
        "renditions",
        sa.Column("width_px", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column(
        "renditions",
        sa.Column("height_px", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("renditions", "height_px")
    op.drop_column("renditions", "width_px")
    op.drop_column("renditions", "page_count")
    op.drop_column("renditions", "is_saved_recipe")
    op.drop_constraint(
        "fk_download_tickets_rendition_id_renditions",
        "download_tickets",
        type_="foreignkey",
    )
    op.drop_column("download_tickets", "rendition_id")
    op.drop_column("renditions", "blob_salt")
    op.drop_constraint(
        "ck_document_versions_derived_pdf_size_non_negative",
        "document_versions",
        type_="check",
    )
    op.drop_constraint(
        "ck_document_versions_derived_pdf_pages_positive",
        "document_versions",
        type_="check",
    )
    op.drop_constraint(
        "ck_document_versions_derived_pdf_size_pair",
        "document_versions",
        type_="check",
    )
    op.drop_constraint(
        "ck_document_versions_derived_pdf_pages_pair",
        "document_versions",
        type_="check",
    )
    op.drop_column("document_versions", "derived_pdf_size")
    op.drop_column("document_versions", "derived_pdf_pages")
