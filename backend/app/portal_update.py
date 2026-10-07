"""Wersja portalu, sprawdzanie aktualizacji i aktualizacja z panelu (Ustawienia -> O portalu).

Podzial rol:
  * backend sprawdza, czy w rejestrze obrazow jest nowsze wydanie, pilnuje warunkow
    (nic nie trwa, wersja zgodna z ostatnim sprawdzeniem), robi kopie portalu i PROSI
    o aktualizacje,
  * aktualizacje wykonuje osobna usluga `updater` (infra/updater) — tylko ona ma dostep do
    Dockera. Backend nie dostaje gniazda Dockera: przejecie panelu nie moze oznaczac
    przejecia hosta. Brak uslugi = portal pokazuje polecenie do recznego wykonania.

Wydania sprawdzamy w tym samym rejestrze, z ktorego compose pobiera obrazy (MTM_IMAGE),
przez standardowe API rejestru (v2): wersja jest „dostepna", dopiero gdy istnieja obrazy
backendu I agenta — nie wtedy, gdy ktos wypchnal tag, a budowanie jeszcze trwa.
"""
import datetime
import importlib.metadata
import logging
import os
import platform
import re
import time

import httpx
from sqlalchemy import func, select, text

from app import timefmt, version
from app.database import async_session
from app.models import Device, Location, UpdateRun, User
from app.settings_store import get_setting, set_setting

logger = logging.getLogger("portal_update")

UPDATER_URL = "http://updater:9091"
UPDATER_TOKEN_FILE = "/data/updater/token"
PRE_UPDATE_DIR = "/data/backups/pre-update"
PRE_UPDATE_KEEP = 3
MIN_ROUTEROS = (7, 15)
_KEY_LATEST, _KEY_CHECKED, _KEY_ERROR = "portal_update_latest", "portal_update_checked_at", "portal_update_error"

# Ostatni wynik sprawdzenia w pamieci — panel boczny pokazuje znaczek bez zapytania do bazy.
LATEST: str | None = None


# ---- rejestr obrazow ----

def _image_base() -> str:
    return (os.environ.get("MTM_IMAGE") or "ghcr.io/zaba44/mikrotik-manager").strip()


def registry_of(repo: str) -> tuple[str, str]:
    """`ghcr.io/zaba44/x-backend` -> ("https://ghcr.io", "zaba44/x-backend"). MTM_REGISTRY_API
    nadpisuje adres API (np. lokalny rejestr testowy osiagalny pod inna nazwa niz dla Dockera)."""
    first, _, rest = repo.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        host, name = first, rest
    else:  # Docker Hub: `uzytkownik/obraz` albo `obraz`
        host, name = "registry-1.docker.io", repo if "/" in repo else f"library/{repo}"
    return (os.environ.get("MTM_REGISTRY_API") or f"https://{host}").rstrip("/"), name


async def fetch_tags(repo: str, client: httpx.AsyncClient | None = None) -> list[str]:
    """Lista tagow obrazu przez API rejestru v2, z anonimowym tokenem (ghcr.io, Docker Hub)."""
    api, name = registry_of(repo)
    url = f"{api}/v2/{name}/tags/list?n=1000"
    own = client is None
    client = client or httpx.AsyncClient(timeout=15.0, follow_redirects=True)
    try:
        r = await client.get(url)
        if r.status_code == 401:
            params = dict(re.findall(r'(\w+)="([^"]*)"', r.headers.get("www-authenticate", "")))
            if "realm" not in params:
                r.raise_for_status()
            t = await client.get(params["realm"], params={k: v for k, v in params.items() if k in ("service", "scope")})
            t.raise_for_status()
            token = t.json().get("token") or t.json().get("access_token")
            r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        return list(r.json().get("tags") or [])
    finally:
        if own:
            await client.aclose()


async def check(client: httpx.AsyncClient | None = None) -> dict:
    """Najnowsze wydanie, dla ktorego sa obrazy backendu i agenta. Wynik zapisywany w bazie."""
    global LATEST
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    try:
        base = _image_base()
        backend = set(await fetch_tags(f"{base}-backend", client))
        agent = set(await fetch_tags(f"{base}-wireguard", client))
        latest, error = version.newest(backend & agent), None
    except Exception as e:
        latest, error = None, f"{type(e).__name__}: {e}"[:300]
    async with async_session() as s:
        if latest:
            await set_setting(s, _KEY_LATEST, latest)
        await set_setting(s, _KEY_CHECKED, now)
        await set_setting(s, _KEY_ERROR, error or "")
        await s.commit()
    if latest:
        LATEST = latest
    return {"latest": latest, "checked_at": now, "error": error}


async def check_quietly() -> None:
    """Codzienne sprawdzenie z harmonogramu — tylko informacja, nic sie samo nie aktualizuje."""
    if version.parse(version.VERSION) is None:
        return  # wersja deweloperska: porownanie i tak bez sensu
    result = await check()
    if result["error"]:
        logger.warning("Sprawdzanie aktualizacji portalu: %s", result["error"])


async def load_cached() -> None:
    global LATEST
    async with async_session() as s:
        LATEST = (await get_setting(s, _KEY_LATEST)) or None


def update_available() -> bool:
    return version.is_newer(LATEST, version.VERSION)


# ---- usluga aktualizacji ----

def _updater_headers() -> dict:
    try:
        with open(UPDATER_TOKEN_FILE) as f:
            return {"X-Updater-Token": f.read().strip()}
    except OSError:
        return {}


async def updater_status() -> dict | None:
    """Stan uslugi `updater`. None = jej nie ma (albo nie odpowiada)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(f"{UPDATER_URL}/status", headers=_updater_headers())
            r.raise_for_status()
            return r.json()
    except Exception:
        return None


async def updater_start(target: str) -> tuple[bool, str | None]:
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.post(f"{UPDATER_URL}/update", json={"version": target, "tz": timefmt.LOCAL_TZ_NAME},
                             headers=_updater_headers())
        if r.status_code == 202:
            return True, None
        return False, (r.json().get("error") if r.headers.get("content-type", "").startswith("application/json")
                       else r.text[:200])
    except Exception as e:
        return False, f"usługa aktualizacji nie odpowiada ({type(e).__name__})"


async def blockers(target: str | None, updater: dict | None) -> list[str]:
    """Powody, dla ktorych aktualizacji z panelu nie wolno teraz uruchomic (pusta lista = wolno)."""
    from app.portal_backup import pending_restore

    out = []
    if version.parse(version.VERSION) is None:
        out.append("To wersja deweloperska (zbudowana ze źródeł) — aktualizujesz ją przez git i budowanie obrazów.")
    elif not target or not version.is_newer(target, version.VERSION):
        out.append("Brak nowszej wersji — najpierw sprawdź aktualizacje.")
    if updater is None:
        out.append("Usługa aktualizacji (updater) nie działa — w tej instalacji zaktualizujesz portal poleceniem na serwerze.")
    elif "error" in (updater.get("stack") or {}):
        out.append(f"Usługa aktualizacji nie widzi stacka: {updater['stack']['error']}.")
    elif updater.get("state") == "running":
        out.append("Aktualizacja już trwa.")
    if pending_restore():
        out.append("Odtwarzanie kopii portalu nie jest dokończone.")
    async with async_session() as s:
        running = (await s.execute(select(func.count()).where(UpdateRun.status == "running"))).scalar()
    if running:
        out.append(f"Trwa aktualizacja routerów ({running}) — restart portalu by ją przerwał.")
    return out


# ---- kopia przed aktualizacja ----

async def pre_update_backup(target: str) -> str:
    """Pelna konfiguracja + historia (bez kopii urzadzen i syslogu — to one robia rozmiar).
    Migracje bazy dzialaja tylko w przod, wiec powrot do starszej wersji = odtworzenie tej kopii."""
    from app.portal_backup import export_portal

    data = await export_portal(False, False, True)
    os.makedirs(PRE_UPDATE_DIR, mode=0o700, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(PRE_UPDATE_DIR, f"mtm-portal-przed-{version.VERSION}-do-{target}-{ts}.tar.gz")
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)
    for old in list_pre_update_backups()[PRE_UPDATE_KEEP:]:
        try:
            os.remove(os.path.join(PRE_UPDATE_DIR, old["name"]))
        except OSError:
            pass
    return path


def list_pre_update_backups() -> list[dict]:
    try:
        names = [n for n in os.listdir(PRE_UPDATE_DIR) if n.endswith(".tar.gz")]
    except OSError:
        return []
    out = []
    for n in names:
        st = os.stat(os.path.join(PRE_UPDATE_DIR, n))
        out.append({"name": n, "size": st.st_size,
                    "created": datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc)})
    return sorted(out, key=lambda b: b["created"], reverse=True)


# ---- informacje do zakladki „O portalu" ----

def routeros_tuple(value: str | None) -> tuple[int, ...] | None:
    """`7.13.5 (stable)` -> (7, 13, 5)."""
    m = re.match(r"^\s*(\d+)\.(\d+)(?:\.(\d+))?", value or "")
    return tuple(int(x) for x in m.groups() if x is not None) if m else None


_PACKAGES = ("fastapi", "starlette", "uvicorn", "sqlalchemy", "alembic", "asyncpg", "httpx",
             "cryptography", "jinja2", "apscheduler", "asyncssh", "segno")


def _package_versions() -> list[tuple[str, str]]:
    out = []
    for name in _PACKAGES:
        try:
            out.append((name, importlib.metadata.version(name)))
        except importlib.metadata.PackageNotFoundError:
            pass
    return out


def _alembic_head() -> str | None:
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory
        return ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()
    except Exception:
        return None


async def collect_about() -> dict:
    from app.wg_agent_client import get_interface_status, get_peers
    from app.wg_config import wg
    from app.config import settings

    info: dict = {}
    now = datetime.datetime.now(datetime.timezone.utc)
    info["portal"] = {
        "version": version.VERSION, "commit": version.short_commit(), "commit_full": version.COMMIT,
        "build_date": version.BUILD_DATE, "project_url": version.PROJECT_URL,
        "started_at": version.STARTED_AT, "uptime": now - version.STARTED_AT,
        "python": platform.python_version(), "packages": _package_versions(),
    }

    async with async_session() as s:
        db: dict = {}
        try:
            db["server"] = (await s.execute(text("SHOW server_version"))).scalar()
            db["size"] = (await s.execute(text("SELECT pg_size_pretty(pg_database_size(current_database()))"))).scalar()
            db["revision"] = (await s.execute(text("SELECT version_num FROM alembic_version"))).scalar()
        except Exception as e:
            db["error"] = f"{type(e).__name__}: {e}"[:200]
        db["head"] = _alembic_head()
        info["db"] = db

        devices = (await s.execute(select(Device.name, Device.routeros_version, Device.api_reachable)
                                   .order_by(Device.name))).all()
        info["counts"] = {
            "users": (await s.execute(select(func.count()).select_from(User))).scalar(),
            "admins": (await s.execute(select(func.count()).where(User.role == "admin"))).scalar(),
            "locations": (await s.execute(select(func.count()).select_from(Location))).scalar(),
        }
        # Klucz NIE moze sie nazywac "update": w szablonie `about.update` trafia w metode
        # dict.update zamiast w ten slownik (pole daty sprawdzenia bylo zawsze puste).
        info["check"] = {"latest": await get_setting(s, _KEY_LATEST) or None,
                          "checked_at": await get_setting(s, _KEY_CHECKED) or None,
                          "error": await get_setting(s, _KEY_ERROR) or None}

    versions: dict[str, int] = {}
    too_old, unknown = [], []
    for name, ros, _reachable in devices:
        key = (ros or "").split(" ")[0] or "nieznana"
        versions[key] = versions.get(key, 0) + 1
        t = routeros_tuple(ros)
        if t is None:
            unknown.append(name)
        elif t[:2] < MIN_ROUTEROS:
            too_old.append(f"{name} ({ros})")
    info["fleet"] = {
        "total": len(devices), "reachable": sum(1 for d in devices if d[2]),
        "versions": sorted(versions.items(), key=lambda kv: routeros_tuple(kv[0]) or (0,), reverse=True),
        "too_old": too_old, "unknown": unknown, "min": ".".join(map(str, MIN_ROUTEROS)),
    }

    status = await get_interface_status()
    peers, _ = await get_peers()
    info["hub"] = {
        "subnet": wg.subnet, "server_ip": wg.server_ip, "endpoint": wg.hub_endpoint,
        "port": settings.wg_port, "public_key": wg.server_public_key,
        "agent": status, "peers": len(peers or []),
        "peers_saved": sum(1 for p in peers or [] if p.get("persisted") is True),
    }
    info["server_time"] = now
    info["timezone"] = time.tzname[0]
    return info
