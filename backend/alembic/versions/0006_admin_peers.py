"""admin_peers table + routeros_winbox_port column

Revision ID: 0006_admin_peers
Revises: 0005_backups
Create Date: 2026-07-09

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_admin_peers"
down_revision: Union[str, None] = "0005_backups"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("routeros_winbox_port", sa.String(), nullable=True))

    op.create_table(
        "admin_peers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(), nullable=False, unique=True),
        sa.Column("wg_public_key", sa.String(), nullable=False, unique=True),
        sa.Column("wg_private_key_encrypted", sa.String(), nullable=False),
        sa.Column("wg_ip", postgresql.INET(), nullable=False, unique=True),
        sa.Column("last_handshake_at", sa.DateTime(), nullable=True),
        sa.Column("wg_reachable", sa.Boolean(), nullable=True),
        sa.Column("last_polled_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("admin_peers")
    op.drop_column("devices", "routeros_winbox_port")
