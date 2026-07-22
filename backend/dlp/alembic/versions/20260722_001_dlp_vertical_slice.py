"""Create independent DLP v2 runtime tables.

Revision ID: 20260722_001
Revises:
Create Date: 2026-07-22
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260722_001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = ("dlp_v2",)
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dlp_messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("deduplication_key", sa.String(255), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("provider_deployment_id", sa.String(255), nullable=False),
        sa.Column("envelope_from", sa.Text(), nullable=False),
        sa.Column("envelope_to", postgresql.JSONB(), nullable=False),
        sa.Column("blob_uri", sa.Text(), nullable=False),
        sa.Column("mime_sha256", sa.String(64), nullable=False),
        sa.Column("mime_size", sa.BigInteger(), nullable=False),
        sa.Column(
            "state",
            sa.String(32),
            nullable=False,
            server_default="received",
        ),
        sa.Column(
            "received_at", sa.DateTime(timezone=True), nullable=False
        ),
        sa.Column(
            "gateway_occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
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
            ["org_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("deduplication_key"),
    )
    op.create_index("ix_dlp_messages_org_id", "dlp_messages", ["org_id"])
    op.create_index("ix_dlp_messages_state", "dlp_messages", ["state"])
    op.create_index(
        "ix_dlp_messages_org_received",
        "dlp_messages",
        ["org_id", "received_at"],
    )

    op.create_table(
        "dlp_message_parts",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "message_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column("part_index", sa.Integer(), nullable=False),
        sa.Column("content_type", sa.String(255), nullable=False),
        sa.Column("disposition", sa.String(64)),
        sa.Column("filename", sa.Text()),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("extraction_status", sa.String(32), nullable=False),
        sa.Column("extracted_text_sha256", sa.String(64)),
        sa.Column("extracted_text_length", sa.Integer()),
        sa.Column("limitation_code", sa.String(64)),
        sa.Column("limitation_detail", sa.Text()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["message_id"], ["dlp_messages.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "message_id",
            "part_index",
            name="uq_dlp_message_parts_position",
        ),
    )
    op.create_index(
        "ix_dlp_message_parts_message_id",
        "dlp_message_parts",
        ["message_id"],
    )

    op.create_table(
        "dlp_classification_results",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "message_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column("run_key", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column(
            "findings",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("llm_result", postgresql.JSONB()),
        sa.Column(
            "limitations",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("error", sa.Text()),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(
            ["message_id"], ["dlp_messages.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "message_id",
            "run_key",
            name="uq_dlp_classification_results_run",
        ),
    )
    op.create_index(
        "ix_dlp_classification_results_message_id",
        "dlp_classification_results",
        ["message_id"],
    )

    op.create_table(
        "dlp_decisions",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "message_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "classification_result_id",
            postgresql.UUID(as_uuid=True),
        ),
        sa.Column(
            "evaluation_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("intended_action", sa.String(16), nullable=False),
        sa.Column("effective_action", sa.String(16), nullable=False),
        sa.Column(
            "matched_rule_ids",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "finding_references",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("evaluation_latency_ms", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["classification_result_id"],
            ["dlp_classification_results.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["message_id"], ["dlp_messages.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "message_id",
            "evaluation_version",
            name="uq_dlp_decisions_evaluation",
        ),
    )
    op.create_index(
        "ix_dlp_decisions_message_id",
        "dlp_decisions",
        ["message_id"],
    )

    op.create_table(
        "dlp_message_events",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "message_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column("event_key", sa.String(255), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column(
            "occurred_at", sa.DateTime(timezone=True), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["message_id"], ["dlp_messages.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_key"),
    )
    op.create_index(
        "ix_dlp_message_events_message_id",
        "dlp_message_events",
        ["message_id"],
    )

    op.create_table(
        "dlp_command_outbox",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "message_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column(
            "org_id", postgresql.UUID(as_uuid=True), nullable=False
        ),
        sa.Column("command_type", sa.String(16), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column(
            "status",
            sa.String(16),
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
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
            ["message_id"], ["dlp_messages.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_dlp_command_outbox_message_id",
        "dlp_command_outbox",
        ["message_id"],
    )
    op.create_index(
        "ix_dlp_command_outbox_org_id",
        "dlp_command_outbox",
        ["org_id"],
    )
    op.create_index(
        "ix_dlp_command_outbox_pending",
        "dlp_command_outbox",
        ["status", "available_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_dlp_command_outbox_pending",
        table_name="dlp_command_outbox",
    )
    op.drop_index(
        "ix_dlp_command_outbox_org_id",
        table_name="dlp_command_outbox",
    )
    op.drop_index(
        "ix_dlp_command_outbox_message_id",
        table_name="dlp_command_outbox",
    )
    op.drop_table("dlp_command_outbox")
    op.drop_index(
        "ix_dlp_message_events_message_id",
        table_name="dlp_message_events",
    )
    op.drop_table("dlp_message_events")
    op.drop_index(
        "ix_dlp_decisions_message_id", table_name="dlp_decisions"
    )
    op.drop_table("dlp_decisions")
    op.drop_index(
        "ix_dlp_classification_results_message_id",
        table_name="dlp_classification_results",
    )
    op.drop_table("dlp_classification_results")
    op.drop_index(
        "ix_dlp_message_parts_message_id",
        table_name="dlp_message_parts",
    )
    op.drop_table("dlp_message_parts")
    op.drop_index(
        "ix_dlp_messages_org_received", table_name="dlp_messages"
    )
    op.drop_index("ix_dlp_messages_state", table_name="dlp_messages")
    op.drop_index("ix_dlp_messages_org_id", table_name="dlp_messages")
    op.drop_table("dlp_messages")
