"""Zwijanie nieudanych przebiegow aktualizacji (kto i kiedy przyjal blad do wiadomosci)

Revision ID: 0017_update_run_ack
Revises: 0016_device_hardware
"""
import sqlalchemy as sa
from alembic import op

revision = "0017_update_run_ack"
down_revision = "0016_device_hardware"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("update_runs", sa.Column("acknowledged_at", sa.DateTime(), nullable=True))
    op.add_column("update_runs", sa.Column("acknowledged_by", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("update_runs", "acknowledged_by")
    op.drop_column("update_runs", "acknowledged_at")
