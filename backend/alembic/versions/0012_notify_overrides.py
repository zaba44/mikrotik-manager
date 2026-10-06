"""nadpisania powiadomien per lokalizacja/urzadzenie

Revision ID: 0012_notify_overrides
Revises: 0011_notifications
Create Date: 2026-08-03

JEDEN wiersz na zakres, nie osiem: tryb + opcjonalna lista typow zdarzen.
Lista jako pole tekstowe jest tu swiadoma — to zamkniety, krotki zbior, nigdy nie
szukamy po pojedynczym elemencie (wczytujemy wiersz i sprawdzamy przynaleznosc
w kodzie), a w zamian zestawienie wyjatkow w panelu to doslownie lista wierszy.

Rozstrzyganie: urzadzenie -> lokalizacja -> globalne, pierwszy jawny wpis wygrywa.
Tryb "custom" ZASTEPUJE poziom wyzszy (nie dokleja sie) — dzieki temu patrzac na
urzadzenie widzisz komplet, bez skladania w glowie co jeszcze siedzi wyzej.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012_notify_overrides"
down_revision: Union[str, None] = "0011_notifications"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notification_overrides",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scope_type", sa.String(), nullable=False),  # device | location
        sa.Column("scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),  # muted | custom
        # tylko dla mode="custom": klucze typow zdarzen po przecinku
        sa.Column("event_keys", sa.String(), nullable=True),
        # tylko dla mode="muted": NULL = bezterminowo (wyrozniane w panelu)
        sa.Column("muted_until", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("scope_type", "scope_id", name="uq_notification_override_scope"),
    )
    op.create_index(
        "ix_notification_overrides_scope", "notification_overrides", ["scope_type", "scope_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_notification_overrides_scope", table_name="notification_overrides")
    op.drop_table("notification_overrides")
