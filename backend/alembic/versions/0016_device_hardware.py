"""Sprzet urzadzenia: nazwa handlowa, model, numer seryjny, obecnosc modemu LTE/5G

Revision ID: 0016_device_hardware
Revises: 0015_backup_note
"""
import sqlalchemy as sa
from alembic import op

revision = "0016_device_hardware"
down_revision = "0015_backup_note"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("board_name", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("model", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("serial_number", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("has_lte", sa.Boolean(), nullable=True))


def downgrade() -> None:
    for col in ("has_lte", "serial_number", "model", "board_name"):
        op.drop_column("devices", col)
