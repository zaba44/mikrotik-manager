"""Nazwa urzadzenia unikalna w obrebie lokalizacji (migracja 0018), etykiety „Lokalizacja / Nazwa"
tam, gdzie lokalizacji nie widac."""
import asyncio
import os
import types
import uuid

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.models import Device, Location
from app.queries import device_label, file_label, label

MIGRATION = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "alembic", "versions", "0018_device_name_per_location.py")


def test_model_unique_per_location_with_nulls_not_distinct():
    ddl = str(CreateTable(Device.__table__).compile(dialect=postgresql.dialect()))
    assert "CONSTRAINT uq_devices_location_name UNIQUE NULLS NOT DISTINCT (location_id, name)" in ddl
    assert "UNIQUE (name)" not in ddl


def test_migration_replaces_global_unique():
    text = open(MIGRATION, encoding="utf-8").read()
    assert 'drop_constraint("devices_name_key"' in text
    assert "UNIQUE NULLS NOT DISTINCT (location_id, name)" in text
    assert 'down_revision = "0017_update_run_ack"' in text


def test_labels():
    assert label("SWITCH POE 24P", "BUDEX") == "BUDEX / SWITCH POE 24P"
    assert label("SWITCH POE 24P", None) == "SWITCH POE 24P"
    assert file_label("BUDEX / SWITCH POE 24P") == "BUDEX-SWITCH POE 24P"


class _Session:
    def __init__(self, locations):
        self.locations = locations

    async def get(self, model, key):
        assert model is Location
        return self.locations.get(key)


def test_device_label_uses_location():
    loc_id = uuid.uuid4()
    s = _Session({loc_id: types.SimpleNamespace(name="BUDEX")})
    dev = types.SimpleNamespace(name="SWITCH POE 24P", location_id=loc_id)
    assert asyncio.run(device_label(s, dev)) == "BUDEX / SWITCH POE 24P"
    dev.location_id = None
    assert asyncio.run(device_label(s, dev)) == "SWITCH POE 24P"
