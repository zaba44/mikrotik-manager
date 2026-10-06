"""firmware version columns + update run tracking (Faza 3)

Revision ID: 0003_updates
Revises: 0002_device_status
Create Date: 2026-07-08

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_updates"
down_revision: Union[str, None] = "0002_device_status"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("available_routeros_version", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("current_firmware", sa.String(), nullable=True))
    op.add_column("devices", sa.Column("available_firmware", sa.String(), nullable=True))

    op.create_table(
        "update_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id"), nullable=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("locations.id"), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="running"),
        sa.Column("started_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("error_message", sa.String(), nullable=True),
    )

    op.create_table(
        "update_run_steps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("update_runs.id"), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("step_type", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="running"),
        sa.Column("started_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("detail", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("update_run_steps")
    op.drop_table("update_runs")
    op.drop_column("devices", "available_firmware")
    op.drop_column("devices", "current_firmware")
    op.drop_column("devices", "available_routeros_version")
