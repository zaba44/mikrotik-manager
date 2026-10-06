"""wg preshared-key per device + admin peer

Revision ID: 0008_preshared_key
Revises: 0007_user_status_only
Create Date: 2026-07-10

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008_preshared_key"
down_revision: Union[str, None] = "0007_user_status_only"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("wg_preshared_key_encrypted", sa.String(), nullable=True))
    op.add_column("admin_peers", sa.Column("wg_preshared_key_encrypted", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("admin_peers", "wg_preshared_key_encrypted")
    op.drop_column("devices", "wg_preshared_key_encrypted")
