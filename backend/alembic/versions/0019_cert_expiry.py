"""Koniec waznosci certyfikatu API urzadzenia (ostrzezenie na pulpicie floty)

Revision ID: 0019_cert_expiry
Revises: 0018_device_name_per_location
"""
import sqlalchemy as sa
from alembic import op

revision = "0019_cert_expiry"
down_revision = "0018_device_name_per_location"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("cert_expires_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "cert_expires_at")
