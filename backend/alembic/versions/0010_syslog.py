"""syslog: przelaczniki per urzadzenie + tabela wpisow

Revision ID: 0010_syslog
Revises: 0009_ping_targets
Create Date: 2026-08-03

Urzadzenia same wysylaja wpisy (push, UDP przez tunel) — portal ich nie odpytuje.
Podpiecie urzadzenia wlacza warning/error/critical; `info` to osobna flaga, bo
generuje setki wpisow na dobe (zmierzone: dhcp,info dominuje log Routera).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_syslog"
down_revision: Union[str, None] = "0009_ping_targets"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("syslog_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "devices",
        sa.Column("syslog_info_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    op.create_table(
        "device_log_entries",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column(
            "device_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("received_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        # poziom wyluskany z topikow (warning/error/critical/info) — do filtrowania i alertow
        sa.Column("level", sa.String(), nullable=False),
        sa.Column("topics", sa.String(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
    )
    # retencja kasuje po czasie, przeglad filtruje per urzadzenie — stad taki uklad
    op.create_index(
        "ix_device_log_entries_device_time",
        "device_log_entries",
        ["device_id", "received_at"],
    )
    op.create_index("ix_device_log_entries_received_at", "device_log_entries", ["received_at"])


def downgrade() -> None:
    op.drop_index("ix_device_log_entries_received_at", table_name="device_log_entries")
    op.drop_index("ix_device_log_entries_device_time", table_name="device_log_entries")
    op.drop_table("device_log_entries")
    op.drop_column("devices", "syslog_info_enabled")
    op.drop_column("devices", "syslog_enabled")
