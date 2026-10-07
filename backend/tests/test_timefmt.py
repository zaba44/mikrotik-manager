"""Czas w panelu: UTC w bazie, wyswietlanie w strefie portalu (app/timefmt.py)."""
import datetime
import os
import time

import pytest

from app import timefmt


@pytest.fixture
def zone():
    """Kazdy test zaczyna w Europe/Warsaw i oddaje strefe procesu taka, jaka zastal."""
    before_env, before = os.environ.get("TZ"), timefmt.LOCAL_TZ_NAME
    timefmt.apply_zone("Europe/Warsaw")
    yield timefmt
    timefmt.apply_zone(before)
    if before_env is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = before_env
    time.tzset()


def test_summer_and_winter_time(zone):
    """Ta sama godzina UTC: latem +2 (CEST), zima +1 (CET) — bez recznej zmiany."""
    assert zone.dt(datetime.datetime(2026, 10, 7, 14, 35), "%H:%M") == "16:35"
    assert zone.dt(datetime.datetime(2026, 11, 7, 14, 35), "%H:%M") == "15:35"


def test_change_of_time_across_dst_switch(zone):
    """Noc zmiany czasu (25.10.2026): 00:30 i 01:30 UTC to 02:30 CEST i 02:30 CET."""
    assert zone.dt(datetime.datetime(2026, 10, 25, 0, 30), "%H:%M %Z") == "02:30 CEST"
    assert zone.dt(datetime.datetime(2026, 10, 25, 1, 30), "%H:%M %Z") == "02:30 CET"


def test_aware_iso_and_empty(zone):
    aware = datetime.datetime(2026, 10, 7, 14, 35, tzinfo=datetime.timezone.utc)
    assert zone.dt(aware) == "2026-10-07 16:35"
    assert zone.dt("2026-10-07T14:04:50+00:00") == "2026-10-07 16:04"   # z tabeli settings
    assert zone.dt(None, default="nigdy") == "nigdy"
    assert zone.dt("", default="—") == "—"
    assert zone.dt("to nie data", default="?") == "?"
    assert zone.dt(datetime.date(2027, 1, 31), "%Y-%m-%d") == "2027-01-31"  # sama data bez zmian


@pytest.mark.parametrize("name,ok", [
    ("Europe/Warsaw", True), ("America/New_York", True), ("UTC", True),
    ("Europe/Narnia", False), ("../../etc/passwd", False), ("Europe/Warsaw; rm -rf /", False), ("", False), (None, False),
])
def test_zone_validation(name, ok):
    assert timefmt.valid_zone(name) is ok


def test_invalid_zone_keeps_current(zone):
    zone.apply_zone("Europe/Narnia")
    assert zone.LOCAL_TZ_NAME == "Europe/Warsaw"


def test_process_local_time_follows_zone(zone):
    """Nazwy plikow, maile i raport tygodniowy uzywaja datetime.now() — ma byc czas lokalny."""
    zone.apply_zone("Asia/Tokyo")  # bez czasu letniego: zawsze UTC+9
    local_now = datetime.datetime.now()
    utc_now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    assert abs((local_now - utc_now) - datetime.timedelta(hours=9)) < datetime.timedelta(minutes=1)
    assert zone.local_zone_name() == "Asia/Tokyo"


def test_utcnow_is_naive_utc():
    n = timefmt.utcnow()
    assert n.tzinfo is None
    assert abs(n - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)) < datetime.timedelta(seconds=5)


def test_zone_choices_list_regions():
    zones = timefmt.zone_choices()
    assert "Europe/Warsaw" in zones and not any(z.startswith("Etc/") for z in zones)
