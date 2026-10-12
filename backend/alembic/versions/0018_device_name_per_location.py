"""Nazwa urzadzenia unikalna w obrebie lokalizacji, nie w calym portalu

Ta sama nazwa (np. „SWITCH POE 24P") moze byc w kazdej lokalizacji. Urzadzenia bez
lokalizacji tez nie moga sie powtarzac — NULLS NOT DISTINCT (Postgres 15+, stack ma 16).

Revision ID: 0018_device_name_per_location
Revises: 0017_update_run_ack
"""
from alembic import op

revision = "0018_device_name_per_location"
down_revision = "0017_update_run_ack"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("devices_name_key", "devices", type_="unique")
    op.execute("ALTER TABLE devices ADD CONSTRAINT uq_devices_location_name "
               "UNIQUE NULLS NOT DISTINCT (location_id, name)")


def downgrade() -> None:
    # Nie przejdzie, jesli ta sama nazwa jest juz w dwoch lokalizacjach — trzeba je najpierw
    # przemianowac.
    op.drop_constraint("uq_devices_location_name", "devices", type_="unique")
    op.create_unique_constraint("devices_name_key", "devices", ["name"])
