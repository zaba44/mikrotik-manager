"""Skrot przebiegu aktualizacji lokalizacji (wiersz na urzadzenie) i zwijanie po godzinie."""
import datetime
import types

from app import update_summary
from app.templating import templates

T0 = datetime.datetime(2026, 10, 7, 18, 47, 45)  # UTC, jak w bazie


def _step(dev, kind, status, minute, detail=None, done=True):
    start = T0 + datetime.timedelta(minutes=minute)
    return types.SimpleNamespace(device_id=dev, device=types.SimpleNamespace(name=dev), step_type=kind,
                                 status=status, started_at=start,
                                 finished_at=start + datetime.timedelta(minutes=1) if done else None,
                                 detail=detail)


def _run(status="succeeded", steps=None, finished_minutes=20, error=None, ack=None, day=0):
    start = T0 - datetime.timedelta(days=day)
    return types.SimpleNamespace(
        id=f"run-{status}-{day}", status=status, started_at=start, error_message=error, steps=steps or [],
        finished_at=start + datetime.timedelta(minutes=finished_minutes) if status != "running" else None,
        acknowledged_at=ack, acknowledged_by="jan" if ack else None)


FULL = [  # przebieg z produkcji: RouterOS + firmware na jednym, drugi juz aktualny
    _step("ROUTER GŁÓWNY", "software", "succeeded", 0, "Downloaded 84% (11.9MiB)"),
    _step("ROUTER GŁÓWNY", "wait_online", "succeeded", 1, "wrócił po restarcie (uptime 1m13s)"),
    _step("ROUTER GŁÓWNY", "verify", "succeeded", 3, "RouterOS 7.24.5 (oczekiwano 7.24.5)"),
    _step("ROUTER GŁÓWNY", "firmware", "succeeded", 3),
    _step("ROUTER GŁÓWNY", "reboot", "succeeded", 3),
    _step("ROUTER GŁÓWNY", "wait_online", "succeeded", 4, "wrócił po restarcie (uptime 1m11s)"),
    _step("ROUTER GŁÓWNY", "verify", "succeeded", 5, "firmware 7.24.5 (oczekiwano 7.24.5)"),
    _step("WI-FI1", "software", "skipped", 6, "RouterOS 7.24.5 już najnowszy — pominięto"),
    _step("WI-FI1", "firmware", "skipped", 6, "firmware 7.24.5 już najnowszy — pominięto"),
]


def test_one_row_per_device_with_versions():
    rows = update_summary.summarize(_run(steps=FULL))
    assert [r.name for r in rows] == ["ROUTER GŁÓWNY", "WI-FI1"]
    main, wifi = rows
    assert (main.status, main.routeros, main.firmware) == ("succeeded", "7.24.5", "7.24.5")
    assert main.duration == "6 min 00 s"
    assert (wifi.status, wifi.routeros, wifi.firmware) == ("skipped", "7.24.5 (bez zmian)", "7.24.5 (bez zmian)")
    assert update_summary.counts(rows) == {"succeeded": 1, "skipped": 1}


def test_running_and_failed_rows_say_what_is_happening():
    steps = [_step("A", "software", "succeeded", 0, "Downloaded 90%"),
             _step("A", "wait_online", "failed", 1, "timeout po 600s"),
             _step("B", "software", "succeeded", 2),
             _step("B", "wait_online", "running", 3, None, done=False)]
    a, b = update_summary.summarize(_run("running", steps))
    assert (a.status, a.current) == ("failed", "timeout po 600s")
    assert (b.status, b.current, b.duration) == ("running", "wait_online", None)


def test_collapse_only_successful_runs_after_an_hour():
    ok = _run(steps=FULL)
    end = ok.finished_at
    assert not update_summary.collapsed(ok, end + datetime.timedelta(minutes=59))
    assert update_summary.collapsed(ok, end + datetime.timedelta(minutes=61))
    late = end + datetime.timedelta(days=5)
    assert not update_summary.collapsed(_run("failed", FULL), late)    # bledy zostaja rozwiniete...
    assert update_summary.collapsed(_run("failed", FULL, ack=late), late)  # ...dopoki ktos ich nie zwinie
    assert not update_summary.collapsed(_run("aborted", FULL), late)
    assert not update_summary.collapsed(_run("running", FULL), late)


def _render(run, previous=(), role=None):
    user = types.SimpleNamespace(role=role, status_only=False) if role else None
    req = types.SimpleNamespace(state=types.SimpleNamespace(user=user))
    loc = types.SimpleNamespace(id="loc", name="BUDEX")
    return templates.get_template("_location_update.html").render(request=req, location=loc, run=run,
                                                                  previous=list(previous))


def test_template_collapses_old_success_and_keeps_failure_open(monkeypatch):
    monkeypatch.setattr(update_summary, "utcnow", lambda: T0 + datetime.timedelta(days=3))
    html = _render(_run(steps=FULL))
    assert "pokaż szczegóły" in html and "2 urządzenia, 1 zaktualizowane, 1 już aktualne" in html
    html = _render(_run("failed", FULL, error="WI-FI1: nie wrócił po restarcie"))
    assert "pokaż szczegóły" not in html and "nie wrócił po restarcie" in html
    assert "wszystkie kroki (9)" in html


def test_template_fresh_success_shows_summary_not_step_flood(monkeypatch):
    monkeypatch.setattr(update_summary, "utcnow", lambda: T0 + datetime.timedelta(minutes=30))
    html = _render(_run(steps=FULL))
    assert "pokaż szczegóły" not in html
    summary_part = html.split("wszystkie kroki")[0]
    assert summary_part.count("ROUTER GŁÓWNY") == 1          # skrot: jeden wiersz na urzadzenie
    assert html.count("ROUTER GŁÓWNY") == 1 + 7               # + 7 krokow pod rozwinieciem


def test_failed_run_can_be_acknowledged_and_then_folds(monkeypatch):
    monkeypatch.setattr(update_summary, "utcnow", lambda: T0 + datetime.timedelta(days=3))
    failed = _run("aborted", FULL, error="WI-FI1: nie wrócił po restarcie — sekwencja przerwana")
    html = _render(failed, role="operator")
    assert "/update-runs/run-aborted-0/acknowledge" in html and "pokaż szczegóły" not in html
    assert "/acknowledge" not in _render(failed)                      # bez uprawnien — bez przycisku
    failed.acknowledged_at, failed.acknowledged_by = T0 + datetime.timedelta(days=1), "jan"
    html = _render(failed, role="operator")
    assert "/acknowledge" not in html and "pokaż szczegóły" in html
    assert "zwinięte: jan" in html and "sekwencja przerwana" in html  # blad dalej widoczny jedna linia


def test_previous_runs_listed_folded(monkeypatch):
    monkeypatch.setattr(update_summary, "utcnow", lambda: T0 + datetime.timedelta(minutes=10))
    html = _render(_run(steps=FULL), previous=[_run(steps=FULL, day=7), _run("failed", FULL, day=14)])
    assert "wcześniejsze aktualizacje (2)" in html
    history = html.split("wcześniejsze aktualizacje")[1]
    assert history.count("pokaż szczegóły") == 2 and "/acknowledge" not in history


def test_acknowledge_is_operational_write():
    from app.main import _is_operational_write
    assert _is_operational_write("/locations/abc/update-runs/def/acknowledge")
    assert not _is_operational_write("/locations/abc/delete")
