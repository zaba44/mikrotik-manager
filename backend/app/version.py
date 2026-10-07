"""Wersja portalu — wbudowana w obraz przy budowaniu (release.yml przekazuje numer z tagu,
commit i date). Obraz zbudowany recznie ze zrodel (infra/docker-compose.yml) ma `dev`.

Nazwy zmiennych `MTM_BUILD_*` celowo inne niz `MTM_VERSION` z .env: tamta wybiera, KTORY
obraz pobrac, ta mowi, CO faktycznie jest w obrazie. Gdyby nosily te sama nazwe, wpis
w `environment:` compose po cichu nadpisalby wartosc z obrazu.
"""
import datetime
import os
import re

VERSION = os.environ.get("MTM_BUILD_VERSION") or "dev"
COMMIT = os.environ.get("MTM_BUILD_COMMIT") or ""
BUILD_DATE = os.environ.get("MTM_BUILD_DATE") or ""
PROJECT_URL = "https://github.com/zaba44/mikrotik-manager"
# Start procesu (import przy uruchomieniu) — czas pracy backendu w Ustawieniach -> O portalu.
STARTED_AT = datetime.datetime.now(datetime.timezone.utc)

_RELEASE = re.compile(r"^(\d{1,4})\.(\d{1,4})\.(\d{1,4})$")


def parse(version: str | None) -> tuple[int, int, int] | None:
    """`0.6.8` -> (0, 6, 8). Wszystko inne (dev, latest, 0.6, 1.0.0-rc1) -> None."""
    m = _RELEASE.match((version or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def newest(tags) -> str | None:
    """Najnowsze WYDANIE z listy tagow rejestru — pomija `latest`, `0.6` i inne nie-wersje."""
    releases = [t for t in tags if parse(t)]
    return max(releases, key=parse) if releases else None


def is_newer(candidate: str | None, current: str | None) -> bool:
    c, cur = parse(candidate), parse(current)
    return bool(c and cur and c > cur)


def short_commit() -> str:
    return COMMIT[:7]
