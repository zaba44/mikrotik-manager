"""users.status_only flag (operator read-only vs can operate)

Revision ID: 0007_user_status_only
Revises: 0006_admin_peers
Create Date: 2026-07-09

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007_user_status_only"
down_revision: Union[str, None] = "0006_admin_peers"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("status_only", sa.Boolean(), nullable=False, server_default=sa.true()),
    )


def downgrade() -> None:
    op.drop_column("users", "status_only")
