"""routeros identity column (Mikrotik's own device name)

Revision ID: 0004_identity
Revises: 0003_updates
Create Date: 2026-07-08

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_identity"
down_revision: Union[str, None] = "0003_updates"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("routeros_identity", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "routeros_identity")
