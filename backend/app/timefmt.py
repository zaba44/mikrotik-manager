"""Czas w panelu: baza i logika w UTC, wyswietlanie w strefie wybranej w Ustawieniach.

Dlaczego tak: kontenery Dockera nie dziedzicza strefy hosta i bez ustawienia pracuja w UTC,
wiec panel pokazywal wszystkie godziny o 1–2 h do tylu wzgledem czasu polskiego (zgloszone
przy pierwszej aktualizacji z panelu na produkcji). Zapis zostaje w UTC — zmiana czasu
z letniego na zimowy niczego w danych nie psuje — a przeliczenie robi jeden filtr `dt`
w szablonach, z automatycznym czasem letnim/zimowym.

Strefa to USTAWIENIE PORTALU (Ustawienia -> O portalu), nie zmienna w docker-compose: zmiana
compose wymagalaby recznej podmiany pliku na serwerze, a aktualizacja z panelu wymienia tylko
obrazy. Kolejnosc: ustawienie w bazie > zmienna TZ (jesli ktos ja poda) > Europe/Warsaw.
Wybrana strefa trafia tez do srodowiska procesu (TZ + tzset), wiec `datetime.now()` w nazwach
plikow, mailach i raporcie tygodniowym tez jest w czasie lokalnym.

Konwencja danych: datetime BEZ strefy w bazie i w kodzie to UTC (kolumny `func.now()`
w Postgresie z TimeZone=UTC i `utcnow()`). Datetime ze strefa jest po prostu przeliczany.
"""
import datetime
import os
import re
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

UTC = datetime.timezone.utc
DEFAULT_ZONE = "Europe/Warsaw"
SETTING_KEY = "portal_timezone"
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$")

LOCAL_TZ: datetime.tzinfo = ZoneInfo("UTC")
LOCAL_TZ_NAME = "UTC"


def valid_zone(name: str | None) -> bool:
    if not name or not _NAME.match(name):
        return False
    try:
        ZoneInfo(name)
        return True
    except (ZoneInfoNotFoundError, ValueError):
        return False


def apply_zone(name: str) -> None:
    """Ustawia strefe panelu (filtr `dt`) i procesu (`datetime.now()`, `time.strftime`)."""
    global LOCAL_TZ, LOCAL_TZ_NAME
    if not valid_zone(name):
        return
    LOCAL_TZ, LOCAL_TZ_NAME = ZoneInfo(name), name
    os.environ["TZ"] = name
    if hasattr(time, "tzset"):
        time.tzset()


def initial_zone() -> str:
    env = (os.environ.get("TZ") or "").strip().lstrip(":")
    return env if valid_zone(env) else DEFAULT_ZONE


async def load_zone() -> None:
    """Przy starcie: strefa z ustawien portalu (jesli ktos ja wybral)."""
    from app.database import async_session
    from app.settings_store import get_setting
    async with async_session() as s:
        saved = await get_setting(s, SETTING_KEY)
    apply_zone(saved if valid_zone(saved) else initial_zone())


def zone_choices() -> list[str]:
    return sorted(z for z in available_timezones() if "/" in z and not z.startswith(("Etc/", "SystemV/", "posix/", "right/")))


def local_zone_name() -> str:
    return LOCAL_TZ_NAME


def utcnow() -> datetime.datetime:
    """Teraz w UTC, bez strefy — w tej postaci zapisujemy czasy w bazie."""
    return datetime.datetime.now(UTC).replace(tzinfo=None)


def to_local(value):
    """datetime (bez strefy = UTC) albo tekst ISO -> datetime w strefie panelu.
    Sama data (bez godziny) wraca bez zmian; puste i nieczytelne -> None."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            value = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(LOCAL_TZ)
    return value


def dt(value, pattern: str = "%Y-%m-%d %H:%M", default: str = "—") -> str:
    """Filtr szablonow: `{{ device.created_at | dt }}`, `{{ x | dt("%H:%M:%S", "nigdy") }}`."""
    local = to_local(value)
    return local.strftime(pattern) if local is not None else default


apply_zone(initial_zone())
