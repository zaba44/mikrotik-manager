"""Recenzja 0.7.6: porownania czasu z baza (UTC) i harmonogram po zmianie strefy."""
import asyncio
import datetime

import pytest
from sqlalchemy.dialects import postgresql

from app import notifications, timefmt


@pytest.fixture
def warsaw():
    before = timefmt.LOCAL_TZ_NAME
    timefmt.apply_zone("Europe/Warsaw")
    yield
    timefmt.apply_zone(before)


class _NotificationsDB:
    """Atrapa bazy: liczy wiersze z created_at (UTC, jak w Postgresie) >= granicy z zapytania."""

    def __init__(self, sent_at):
        self.sent_at = sent_at

    async def execute(self, stmt):
        params = stmt.compile(dialect=postgresql.dialect()).params
        bounds = [v for v in params.values() if isinstance(v, datetime.datetime)]
        n = sum(1 for t in self.sent_at if all(t >= b for b in bounds))

        class R:
            def scalar_one(self):
                return n
        return R()


def test_hourly_cap_counts_recent_mails_in_warsaw_zone(warsaw, monkeypatch):
    """Recenzja: 20 maili minute temu, limit 10/h — przy strefie Warszawa okno liczone w czasie
    lokalnym (2 h do przodu wzgledem bazy) nie widzialo ich i przepuszczalo kolejne."""
    settings = {"notify_dedup_minutes": 0, "notify_max_per_device_hour": 0, "notify_max_total_hour": 10}

    async def fake_int(session, key):
        return settings[key]
    monkeypatch.setattr(notifications, "get_int_setting", fake_int)
    minute_ago = timefmt.utcnow() - datetime.timedelta(minutes=1)
    reason = asyncio.run(notifications._blocked_reason(_NotificationsDB([minute_ago] * 20),
                                                       event_key="x", dedup_key="k", device_id=None))
    assert reason == "globalny limit 10/h"


def test_scheduler_runs_in_utc_and_job_times_are_aware():
    """Po zmianie strefy panelu zadanie „teraz" nie moze trafic w przeszlosc i zostac pominiete."""
    from app import scheduler as sch
    import inspect
    src = inspect.getsource(sch.start_scheduler)
    assert "AsyncIOScheduler(timezone=datetime.timezone.utc)" in src
    assert "datetime.datetime.now()" not in src
    now = timefmt.utc_now_aware()
    assert now.tzinfo is not None and now.utcoffset() == datetime.timedelta(0)


def test_no_naive_now_in_job_scheduling():
    import pathlib
    for f in pathlib.Path("app").rglob("*.py"):
        text = f.read_text(encoding="utf-8")
        assert "next_run_time=datetime.datetime.now()" not in text, f


def test_job_time_survives_zone_change(warsaw):
    """Termin ze strefa jest tym samym momentem niezaleznie od strefy procesu."""
    t1 = timefmt.utc_now_aware()
    timefmt.apply_zone("UTC")
    t2 = timefmt.utc_now_aware()
    assert abs((t2 - t1).total_seconds()) < 5
