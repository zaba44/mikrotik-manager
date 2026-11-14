"""Stan floty w jednym miejscu: liczby na pulpit zbiorczy i ostrzezenia, ktore dotad
wychodzily dopiero po objawach (Back To Home na 7.15, „WG OK, API nie" przez port www-ssl).
Wszystko liczone z bazy — strona nie odpytuje routerow."""
import datetime
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Backup, Device
from app.portal_update import MIN_ROUTEROS, routeros_tuple
from app.timefmt import utcnow

# Ponizej tej wersji portal dziala, ale to tu MikroTik zmienial nazwy menu i parametrow
# (uzytkownicy Back To Home do 7.16, `available-from` od 7.24) — kazda taka wersja to
# osobna sciezka w kodzie, wiec warto wiedziec, ile ich jeszcze jest.
RECOMMENDED_ROUTEROS = (7, 18)
OFFLINE_DAYS = 7
CERT_WARN_DAYS = 365


@dataclass
class Warning:
    key: str
    title: str
    hint: str
    devices: list = field(default_factory=list)
    level: str = "warn"  # warn | bad


def update_available(d: Device) -> bool:
    ros = bool(d.available_routeros_version and d.available_routeros_version not in (d.routeros_version or ""))
    fw = bool(d.available_firmware and d.current_firmware and d.available_firmware != d.current_firmware)
    return ros or fw


async def load_devices(session: AsyncSession) -> list[Device]:
    return list((await session.execute(
        select(Device).options(selectinload(Device.location)).order_by(Device.name))).scalars().all())


async def failed_backups(session: AsyncSession, days: int = 7) -> dict:
    """{device_id: liczba nieudanych kopii} z ostatnich dni."""
    since = utcnow() - datetime.timedelta(days=days)
    rows = (await session.execute(
        select(Backup.device_id, func.count(Backup.id))
        .where(Backup.status != "success", Backup.created_at >= since).group_by(Backup.device_id))).all()
    return dict(rows)


def warnings(devices: list[Device], backup_failures: dict, now: datetime.datetime | None = None) -> list[Warning]:
    now = now or utcnow()
    out = [
        Warning("too_old", f"RouterOS starszy niż {'.'.join(map(str, MIN_ROUTEROS))}",
                "Portal nie obsługuje tych wersji — zaktualizuj RouterOS.", level="bad"),
        Warning("api_down", "Tunel działa, API nie odpowiada",
                "Najczęściej usługa www-ssl nie słucha na porcie 443 (ustaw: /ip service set www-ssl port=443) "
                "albo jest wyłączona; rzadziej — brak certyfikatu lub konta mtm-api.", level="bad"),
        Warning("offline", f"Bez połączenia od ponad {OFFLINE_DAYS} dni",
                "Tunel nie zestawił się od dawna — router wyłączony, bez internetu albo usunięty z sieci.", level="bad"),
        Warning("backup", "Nieudane kopie w ostatnich 7 dniach",
                "Kopia, która nie działa, wychodzi zwykle dopiero przy odtwarzaniu.", level="bad"),
        Warning("old", f"RouterOS starszy niż {'.'.join(map(str, RECOMMENDED_ROUTEROS))}",
                "Działa, ale to wersje, w których MikroTik inaczej nazywał część menu — warto zaktualizować."),
        Warning("cert", "Certyfikat API wygasa w ciągu roku",
                "Odnowisz go akcją „Odnów certyfikat API”. Wygaśnięcie nie zrywa połączenia z portalem."),
        Warning("never", "Nigdy nie połączone",
                "Urządzenie zarejestrowane, ale skrypt rejestracji nie został jeszcze wklejony na routerze."),
    ]
    by = {w.key: w for w in out}
    for d in devices:
        t = routeros_tuple(d.routeros_version)
        if t is not None and t[:2] < MIN_ROUTEROS:
            by["too_old"].devices.append(d)
        elif t is not None and t[:2] < RECOMMENDED_ROUTEROS:
            by["old"].devices.append(d)
        if d.last_polled_at is not None and d.wg_reachable and d.api_reachable is False:
            by["api_down"].devices.append(d)
        if d.last_handshake_at is None and not d.wg_reachable:
            by["never"].devices.append(d)
        elif not d.wg_reachable and d.last_handshake_at and now - d.last_handshake_at > datetime.timedelta(days=OFFLINE_DAYS):
            by["offline"].devices.append(d)
        if backup_failures.get(d.id):
            by["backup"].devices.append(d)
        expires = getattr(d, "cert_expires_at", None)
        if expires and expires - now < datetime.timedelta(days=CERT_WARN_DAYS):
            by["cert"].devices.append(d)
    return [w for w in out if w.devices]


def summary(devices: list[Device], backup_failures: dict) -> dict:
    versions: dict[str, int] = {}
    for d in devices:
        key = (d.routeros_version or "").split(" ")[0] or "nieznana"
        versions[key] = versions.get(key, 0) + 1
    return {
        "total": len(devices),
        "online": sum(1 for d in devices if d.api_reachable),
        "wg_only": sum(1 for d in devices if d.wg_reachable and not d.api_reachable),
        "offline": sum(1 for d in devices if d.last_polled_at is not None and not d.wg_reachable),
        "updates": sum(1 for d in devices if update_available(d)),
        "backup_failures": sum(1 for d in devices if backup_failures.get(d.id)),
        "versions": sorted(versions.items(), key=lambda kv: routeros_tuple(kv[0]) or (0,), reverse=True),
    }


def parse_cert_date(value: str | None) -> datetime.datetime | None:
    """`invalid-after` z /certificate: „2036-10-09 15:05:32" (7.x) albo „oct/09/2036 15:05:32"."""
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%b/%d/%Y %H:%M:%S"):
        try:
            return datetime.datetime.strptime(value.strip().title() if "/" in value else value.strip(), fmt)
        except ValueError:
            continue
    return None
