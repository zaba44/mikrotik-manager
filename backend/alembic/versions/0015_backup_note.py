"""Opis kopii — zrzuty WireGuard/BTH mowia, PRZED jaka zmiana powstaly

Revision ID: 0015_backup_note
Revises: 0014_poe_locks
"""
import sqlalchemy as sa
from alembic import op

revision = "0015_backup_note"
down_revision = "0014_poe_locks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("backups", sa.Column("note", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("backups", "note")
