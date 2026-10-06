"""device status columns for polling (Faza 2)

Revision ID: 0002_device_status
Revises: 0001_initial
Create Date: 2026-07-08

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_device_status"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("last_handshake_at", sa.DateTime(), nullable=True))
    op.add_column("devices", sa.Column("wg_reachable", sa.Boolean(), nullable=True))
    op.add_column("devices", sa.Column("api_reachable", sa.Boolean(), nullable=True))
    op.add_column("devices", sa.Column("routeros_version", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("routeros_uptime", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("last_polled_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "last_polled_at")
    op.drop_column("devices", "routeros_uptime")
    op.drop_column("devices", "routeros_version")
    op.drop_column("devices", "api_reachable")
    op.drop_column("devices", "wg_reachable")
    op.drop_column("devices", "last_handshake_at")
