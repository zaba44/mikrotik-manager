import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from starlette.middleware.sessions import SessionMiddleware

from app import first_run
from app import setup_token
from app.auth import can_operate, is_admin, session_fingerprint
from app.backup_transfer import start_backup_sftp_server
from app.config import settings
from app.database import async_session
from app.first_run import users_exist
from app.models import Location, User
from app.routers import auth, backups, dashboard, devices, locations, routerwg, routerwg_write, setup, settings as settings_router
from app.scheduler import start_scheduler
from app.syslog_receiver import start_receiver, stop_receiver
from app.portal_backup import pending_restore, resume_pending_restore
from app.update_orchestrator import cleanup_stale_runs
from app.wg_bringup import ensure_wg_up
from app.wg_config import load_wg_config

# Trasy dostępne bez logowania.
_PUBLIC_EXACT = {"/login", "/health"}
# Prefiksy tylko dla admina (kopie zawierają show-sensitive export = hasła; ustawienia
# to konfiguracja globalna + peery admina + użytkownicy).
_ADMIN_PREFIXES = ("/settings", "/backups")
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Zapisy dostępne dla każdego zalogowanego (dot. własnego konta).
_SELF_WRITE = {"/logout", "/account/password"}


def _is_operational_write(path: str) -> bool:
    """Akcje operacyjne na urządzeniu/lokalizacji — dostępne dla operatora bez
    'tylko statusy' (kontrola lokalizacji w handlerze). Backup celowo tu NIE ma —
    kopie zostają admin-only.

    PoE: przestawienie i restart portu to akcje operacyjne jak restart urządzenia
    (operator restartuje kamerę w swojej lokalizacji). Oznaczanie i zdejmowanie blokady
    uplinku NIE — to decyzja o zabezpieczeniu, więc zostaje dla administratora.
    Przed tą poprawką handler wpuszczał operatora, a middleware go odrzucał: operator
    widział przycisk „Restart" i dostawał 403. Ten sam błąd miało przypinanie adresu
    lokalnego (wytknięty w recenzji zewnętrznej) — wskazanie adresu to notatka operacyjna,
    a handler i szablon od początku dopuszczały operatora."""
    if path.startswith("/devices/"):
        return (path.endswith(("/update", "/reboot", "/check-updates", "/poe/set", "/poe/cycle",
                               "/addresses/pin", "/addresses/unpin"))
                or "/ping" in path)
    return path.startswith("/locations/") and path.endswith("/update-all")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Portal niezalozony -> token instalacyjny do logow, zanim ktokolwiek dotrze do kreatora.
    async with async_session() as s:
        if not await users_exist(s):
            setup_token.ensure()
    await load_wg_config()
    # Niedokonczone odtwarzanie kopii PRZED zwyklym podniesieniem tunelu: zwykle
    # ensure_wg_up() na swiezej instalacji kazaloby agentowi wygenerowac NOWY klucz huba,
    # a flota zna tylko ten z kopii (wytkniete w drugiej recenzji).
    await resume_pending_restore()
    if pending_restore() is None:
        await ensure_wg_up()
    await cleanup_stale_runs()
    scheduler = start_scheduler()
    app.state.scheduler = scheduler
    sftp_server = await start_backup_sftp_server()
    await start_receiver()  # syslog UDP — urządzenia pushują wpisy przez tunel
    yield
    await stop_receiver()
    sftp_server.close()
    scheduler.shutdown(wait=False)


app = FastAPI(title="MikroTik Manager", lifespan=lifespan)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path in _PUBLIC_EXACT or path.startswith("/static"):
        return await call_next(request)

    # Pierwsze uruchomienie (brak użytkowników) -> kreator. /setup dostępne bez sesji.
    if not first_run._users_exist:
        async with async_session() as s:
            await users_exist(s)
    if not first_run._users_exist:
        if path.startswith("/setup"):
            return await call_next(request)
        return RedirectResponse(url="/setup", status_code=303)
    if path.startswith("/setup"):
        return RedirectResponse(url="/", status_code=303)

    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=303)

    async with async_session() as session:
        user = await session.get(User, uuid.UUID(user_id))
        # Sesja musi nosic odcisk AKTUALNEGO hasla: po zmianie hasla (wlasnej albo resecie
        # przez admina) wszystkie stare sesje tego konta przestaja dzialac.
        if user is None or request.session.get("pwv") != session_fingerprint(user.password_hash):
            request.session.clear()
            return RedirectResponse(url="/login", status_code=303)

        # Lokalizacje do sidebara — zawężone do lokalizacji operatora.
        if is_admin(user):
            nav_locations = list(
                (await session.execute(select(Location).order_by(Location.name))).scalars().all()
            )
        elif user.location_id:
            loc = await session.get(Location, user.location_id)
            nav_locations = [loc] if loc else []
        else:
            nav_locations = []

    request.state.user = user
    request.state.nav_locations = nav_locations

    # Strefy tylko-admina (GET i zapis): kopie (show-sensitive) + panel ustawień.
    if any(path.startswith(p) for p in _ADMIN_PREFIXES) and not is_admin(user):
        return PlainTextResponse("Brak uprawnień — tylko administrator.", status_code=403)

    # Autoryzacja zapisów.
    if request.method in _WRITE_METHODS:
        if path in _SELF_WRITE:
            allowed = True  # własne konto — każdy zalogowany
        elif _is_operational_write(path):
            allowed = can_operate(user)  # lokalizację dogląda handler
        else:
            allowed = is_admin(user)
        if not allowed:
            return PlainTextResponse("Brak uprawnień — tylko administrator.", status_code=403)

    return await call_next(request)


# https_only: ciasteczko sesji z flaga Secure. Panel jest wylacznie za Caddym z TLS, wiec
# nic tu nie tracimy, a ciasteczko nie wycieknie przy przypadkowym wejsciu po http.
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret,
                   max_age=60 * 60 * 24 * 14, https_only=True, same_site="lax")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(setup.router)
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(locations.router)
app.include_router(devices.router)
app.include_router(routerwg.router)
app.include_router(routerwg_write.router)
app.include_router(backups.router)
app.include_router(settings_router.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
