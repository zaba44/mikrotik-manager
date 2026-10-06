"""Porty PoE zablokowane jako uplink + licznik portow PoE na urzadzeniu

Revision ID: 0014_poe_locks
Revises: 0013_local_address
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0014_poe_locks"
down_revision = "0013_local_address"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("poe_port_count", sa.Integer(), nullable=True))
    op.create_table(
        "poe_locked_ports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("device_id", UUID(as_uuid=True),
                  sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("interface", sa.String(), nullable=False),
        sa.Column("note", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("device_id", "interface", name="uq_poe_lock_device_iface"),
    )


def downgrade() -> None:
    op.drop_table("poe_locked_ports")
    op.drop_column("devices", "poe_port_count")
