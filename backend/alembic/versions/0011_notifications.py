"""powiadomienia: dziennik wyslanych i wyciszonych

Revision ID: 0011_notifications
Revises: 0010_syslog
Create Date: 2026-08-03

Dziennik jest potrzebny do dzialania trzech bezpiecznikow antyspamowych (limit na
urzadzenie/godzine, globalny sufit, wyciszanie powtorek) — w pamieci procesu resetowalyby
sie przy kazdym restarcie backendu, czyli dokladnie wtedy, gdy cos sie sypie. Przy okazji
daje wglad: co poszlo, co zostalo wyciszone i dlaczego.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_notifications"
down_revision: Union[str, None] = "0010_syslog"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        # typ zdarzenia, np. "syslog.error", "device.offline", "portal.login"
        sa.Column("event_key", sa.String(), nullable=False),
        # klucz dedupu: to samo zdarzenie z tego samego zrodla nie leci w kolko
        sa.Column("dedup_key", sa.String(), nullable=False),
        sa.Column(
            "device_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("devices.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),  # sent | suppressed | failed
        sa.Column("reason", sa.String(), nullable=True),   # dlaczego wyciszone/nieudane
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_notifications_created_at", "notifications", ["created_at"])
    op.create_index("ix_notifications_dedup", "notifications", ["dedup_key", "created_at"])
    op.create_index("ix_notifications_device", "notifications", ["device_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_notifications_device", table_name="notifications")
    op.drop_index("ix_notifications_dedup", table_name="notifications")
    op.drop_index("ix_notifications_created_at", table_name="notifications")
    op.drop_table("notifications")
