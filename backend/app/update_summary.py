"""Skrot przebiegu aktualizacji lokalizacji: jeden wiersz na urzadzenie zamiast kilkunastu
krokow (software, wait_online, verify, firmware, reboot...) i zwijanie starego przebiegu.

Tabela krokow zostaje pod rozwinieciem — skrot to tylko inny widok tych samych danych."""
import datetime
import re
from dataclasses import dataclass, field

from app.timefmt import utcnow

# Udany przebieg zwija sie do jednej linii po tym czasie od zakonczenia. Bledy i przerwania
# zostaja rozwiniete — wymagaja uwagi.
COLLAPSE_AFTER = datetime.timedelta(hours=1)

_VERSION = {"software": re.compile(r"^RouterOS (\S+)"), "firmware": re.compile(r"^firmware (\S+)")}


@dataclass
class DeviceSummary:
    name: str
    status: str = "succeeded"  # succeeded | running | failed | skipped (wszystko aktualne)
    routeros: str | None = None
    firmware: str | None = None
    started_at: datetime.datetime | None = None
    finished_at: datetime.datetime | None = None
    current: str | None = None  # krok w toku albo opis bledu
    steps: list = field(default_factory=list)

    @property
    def duration(self) -> str | None:
        if not (self.started_at and self.finished_at):
            return None
        minutes, seconds = divmod(int((self.finished_at - self.started_at).total_seconds()), 60)
        return f"{minutes} min {seconds:02d} s" if minutes else f"{seconds} s"


def _result(step, kind: str) -> str | None:
    """`RouterOS 7.24.5 (oczekiwano 7.24.5)` -> "7.24.5"; pominiety krok -> "7.24.5 (bez zmian)"."""
    m = _VERSION[kind].match(step.detail or "")
    if not m:
        return None
    return f"{m.group(1)} (bez zmian)" if step.status == "skipped" else m.group(1)


def summarize(run) -> list[DeviceSummary]:
    rows: dict = {}
    for step in run.steps:
        key = step.device_id
        if key not in rows:
            rows[key] = DeviceSummary(name=step.device.name if step.device else "—")
        row = rows[key]
        row.steps.append(step)
        row.started_at = min(filter(None, [row.started_at, step.started_at]), default=None)
        row.finished_at = max(filter(None, [row.finished_at, step.finished_at]), default=None)
        if step.step_type == "verify" or step.status == "skipped":
            kind = "firmware" if (step.detail or "").startswith("firmware") else "software"
            value = _result(step, kind)
            if value:
                setattr(row, "routeros" if kind == "software" else kind, value)
    for row in rows.values():
        statuses = [s.status for s in row.steps]
        if "failed" in statuses:
            row.status = "failed"
            row.current = next(s.detail for s in reversed(row.steps) if s.status == "failed")
        elif "running" in statuses:
            row.status = "running"
            step = next(s for s in reversed(row.steps) if s.status == "running")
            row.current = step.step_type + (f" — {step.detail}" if step.detail else "")
            row.finished_at = None
        elif all(s == "skipped" for s in statuses):
            row.status = "skipped"
    return list(rows.values())


def collapsed(run, now: datetime.datetime | None = None) -> bool:
    """Udany przebieg starszy niz godzina -> jedna linia. Blad albo przerwanie — rozwiniete,
    dopoki ktos go nie zwinie („Zwiń"). W toku — zawsze rozwiniety."""
    if run is None or run.finished_at is None or run.status == "running":
        return False
    if run.status != "succeeded":
        return getattr(run, "acknowledged_at", None) is not None
    return (now or utcnow()) - run.finished_at > COLLAPSE_AFTER


def counts(summary: list[DeviceSummary]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in summary:
        out[row.status] = out.get(row.status, 0) + 1
    return out
