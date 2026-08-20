"""Add draft revision and one-draft-per-tenant constraint.

Revision ID: 20260820_003
Revises: 20260722_002
Create Date: 2026-08-20
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260820_003"
down_revision: str | None = "20260722_002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "dlp_policy_versions",
        sa.Column(
            "draft_revision",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "dlp_policy_versions",
        sa.Column(
            "updated_by",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.add_column(
        "dlp_policy_versions",
        sa.Column(
            "published_by",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.add_column(
        "dlp_policy_versions",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_foreign_key(
        "fk_dlp_policy_versions_updated_by",
        "dlp_policy_versions",
        "users",
        ["updated_by"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_dlp_policy_versions_published_by",
        "dlp_policy_versions",
        "users",
        ["published_by"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "uq_dlp_policy_versions_one_draft_per_org",
        "dlp_policy_versions",
        ["org_id"],
        unique=True,
        postgresql_where=sa.text("status = 'draft'"),
    )
    op.alter_column(
        "dlp_policy_versions",
        "draft_revision",
        server_default=None,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_dlp_policy_versions_one_draft_per_org",
        table_name="dlp_policy_versions",
    )
    op.drop_constraint(
        "fk_dlp_policy_versions_published_by",
        "dlp_policy_versions",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_dlp_policy_versions_updated_by",
        "dlp_policy_versions",
        type_="foreignkey",
    )
    op.drop_column("dlp_policy_versions", "updated_at")
    op.drop_column("dlp_policy_versions", "published_by")
    op.drop_column("dlp_policy_versions", "updated_by")
    op.drop_column("dlp_policy_versions", "draft_revision")
