"""Adres lokalny wskazany recznie + adres publiczny na urzadzeniu

Revision ID: 0013_local_address
Revises: 0012_notify_overrides
"""
import sqlalchemy as sa
from alembic import op

revision = "0013_local_address"
down_revision = "0012_notify_overrides"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("local_addr_interface", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("local_addr_value", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("local_addr_dynamic", sa.Boolean(),
                                       nullable=False, server_default="false"))
    op.add_column("devices", sa.Column("local_addr_note", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("public_address", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("public_behind_nat", sa.Boolean(), nullable=True))
    op.add_column("devices", sa.Column("addr_checked_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    for col in ("addr_checked_at", "public_behind_nat", "public_address", "local_addr_note",
                "local_addr_dynamic", "local_addr_value", "local_addr_interface"):
        op.drop_column("devices", col)
