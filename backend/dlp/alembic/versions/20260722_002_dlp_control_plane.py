"""Create DLP v2 control-plane tables.

Revision ID: 20260722_002
Revises: 20260722_001
Create Date: 2026-07-22
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260722_002"
down_revision: str | None = "20260722_001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dlp_policy_versions",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "org_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column(
            "policy_document", postgresql.JSONB(), nullable=False
        ),
        sa.Column(
            "created_by", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "version",
            name="uq_dlp_policy_versions_org_version",
        ),
    )
    op.create_index(
        "ix_dlp_policy_versions_org_status",
        "dlp_policy_versions",
        ["org_id", "status"],
    )

    op.create_table(
        "dlp_tenant_configs",
        sa.Column(
            "org_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "mode",
            sa.String(16),
            nullable=False,
            server_default="monitor",
        ),
        sa.Column(
            "domains",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "lexicon_version",
            sa.String(64),
            nullable=False,
            server_default="v1",
        ),
        sa.Column(
            "active_policy_version_id",
            postgresql.UUID(as_uuid=True),
        ),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["active_policy_version_id"],
            ["dlp_policy_versions.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("org_id"),
    )

    op.create_table(
        "dlp_review_actions",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "org_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "message_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "actor_user_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "idempotency_key", sa.String(255), nullable=False
        ),
        sa.Column(
            "command_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"], ["users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["message_id"], ["dlp_messages.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("command_id"),
        sa.UniqueConstraint(
            "org_id",
            "idempotency_key",
            name="uq_dlp_review_actions_idempotency",
        ),
    )
    op.create_index(
        "ix_dlp_review_actions_org_id",
        "dlp_review_actions",
        ["org_id"],
    )
    op.create_index(
        "ix_dlp_review_actions_message_id",
        "dlp_review_actions",
        ["message_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_dlp_review_actions_message_id",
        table_name="dlp_review_actions",
    )
    op.drop_index(
        "ix_dlp_review_actions_org_id",
        table_name="dlp_review_actions",
    )
    op.drop_table("dlp_review_actions")
    op.drop_table("dlp_tenant_configs")
    op.drop_index(
        "ix_dlp_policy_versions_org_status",
        table_name="dlp_policy_versions",
    )
    op.drop_table("dlp_policy_versions")
