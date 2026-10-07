import asyncio
import datetime
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select

from app.backup_service import run_all_backups
from app import local_address
from app import portal_update
from app.routerwg import snapshot as wg_snapshot
from app.config import settings
from app.database import async_session
from app.models import AdminPeer, Device
from app.notifications import notify
from app.portal_backup import resume_pending_restore
from app.weekly_report import weekly_report_tick
from app.log_store import (
    enforce_all_device_caps,
    enforce_notification_retention,
    enforce_retention,
)
from app.routeros_client import check_for_updates, get_routerboard_info, get_status, lte_present
from app.settings_store import get_int_setting, get_setting, set_setting
from app.wg_agent_client import get_peers

logger = logging.getLogger("scheduler")

_HANDSHAKE_FRESH_SECONDS = settings.poll_interval_seconds * 3


# Ile urzadzen odpytujemy naraz. 32 przy 5-sekundowym limicie daje przy 300 nieosiagalnych
# urzadzeniach ~50 s na cykl — miesci sie w minutowym interwale.
_POLL_CONCURRENCY = 32


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


async def poll_devices() -> None:
    peers, error = await get_peers()
    handshake_by_pubkey: dict[str, int] = {}
    if peers is not None:
        handshake_by_pubkey = {peer["public_key"]: peer["latest_handshake"] for peer in peers}
    else:
        logger.warning("Nie udało się pobrać peerów z wg-agent: %s", error)

    now = _utcnow()

    def _apply_handshake(obj) -> None:
        handshake_ts = handshake_by_pubkey.get(obj.wg_public_key, 0)
        if handshake_ts:
            obj.last_handshake_at = datetime.datetime.fromtimestamp(
                handshake_ts, tz=datetime.timezone.utc
            ).replace(tzinfo=None)
            obj.wg_reachable = (now - obj.last_handshake_at).total_seconds() < _HANDSHAKE_FRESH_SECONDS
        else:
            obj.wg_reachable = False
        obj.last_polled_at = now

    # Faza 1: odczyt REST — rownolegle i BEZ otwartej sesji bazy. Wczesniej urzadzenia
    # odpytywane byly po kolei wewnatrz jednej sesji: kazde nieosiagalne to ~5 s czekania,
    # wiec przy 200 nieosiagalnych cykl trwal ~17 minut zamiast minuty, a polaczenie z baza
    # bylo zajete przez caly ten czas (wytkniete w recenzji zewnetrznej).
    async with async_session() as session:
        snapshot = (await session.execute(select(Device))).scalars().all()
        session.expunge_all()
    sem = asyncio.Semaphore(_POLL_CONCURRENCY)

    async def _one(d):
        async with sem:
            status = await get_status(d)
            # Modem LTE/5G sprawdzany JEDNORAZOWO (has_lte=None) — potem raz na dobe przy
            # sprawdzaniu aktualizacji. Dokladanie zapytania do kazdego cyklu przy kilkuset
            # urzadzeniach byloby marnotrawstwem, a modem nie pojawia sie co minute.
            if status.get("reachable") and d.has_lte is None:
                status["has_lte"] = await lte_present(d)
            return status

    results = dict(zip((d.id for d in snapshot), await asyncio.gather(*(_one(d) for d in snapshot))))

    # Faza 2: zapis wynikow w jednej krotkiej sesji.
    transitions: list = []
    async with async_session() as session:
        devices = (await session.execute(select(Device))).scalars().all()

        for device in devices:
            _apply_handshake(device)
            status = results.get(device.id)
            if status is None:  # urzadzenie dodane w trakcie cyklu — zlapie je nastepny
                continue

            was_reachable = device.api_reachable  # None = jeszcze nie sprawdzane
            device.api_reachable = status["reachable"]
            # Zgłaszamy TYLKO zmianę stanu, nie każdy cykl pollingu — inaczej
            # niedostępne urządzenie generowałoby mail co minutę.
            if was_reachable is not None and was_reachable != status["reachable"]:
                transitions.append((device, status["reachable"], status.get("error")))
            if status["reachable"]:
                device.routeros_version = status["version"]
                device.routeros_uptime = status["uptime"]
                device.routeros_identity = status.get("identity")
                device.routeros_winbox_port = status.get("winbox_port")
                if status.get("board_name"):
                    device.board_name = status["board_name"]
                if status.get("has_lte") is not None:
                    device.has_lte = status["has_lte"]

        # Peery administracyjne — status z tego samego dumpu wg (tylko handshake,
        # nie mają REST API do odpytania).
        admin_peers = (await session.execute(select(AdminPeer))).scalars().all()
        for peer in admin_peers:
            _apply_handshake(peer)

        await session.commit()
        count = len(devices)

    logger.info("Polling zakończony: %d urządzeń, %d peerów admina", count, len(admin_peers))

    # Powiadomienia po zamknięciu sesji pollingu — wysyłka nie może opóźniać cyklu.
    for device, online, error in transitions:
        async with async_session() as session:
            if online:
                await notify(
                    session, event_key="device.online", device_id=device.id,
                    subject=f"[MTM] {device.name} znów odpowiada",
                    body=f"Urządzenie {device.name} ({device.wg_ip}) ponownie odpowiada przez API.",
                )
            else:
                await notify(
                    session, event_key="device.offline", device_id=device.id,
                    subject=f"[MTM] {device.name} nie odpowiada",
                    body=(f"Urządzenie {device.name} ({device.wg_ip}) przestało odpowiadać "
                          f"przez API.\n\nSzczegóły: {error or 'brak'}"),
                )


async def check_updates() -> None:
    """Rzadszy cykl (domyślnie raz dziennie) — odpytuje dostępne wersje RouterOS/firmware.
    Osobno od poll_devices, bo check-for-updates jest wolniejsze/cięższe (łączy się
    z serwerami MikroTika) i nie musi lecieć co minutę."""
    async with async_session() as session:
        devices = (
            (await session.execute(select(Device).where(Device.api_reachable.is_(True))))
            .scalars()
            .all()
        )

        for device in devices:
            update_info = await check_for_updates(device)
            if update_info["ok"]:
                device.available_routeros_version = update_info.get("latest_version")

            board_info = await get_routerboard_info(device)
            if board_info["ok"]:
                device.current_firmware = board_info.get("current_firmware")
                device.available_firmware = board_info.get("upgrade_firmware")
                device.model = board_info.get("model") or device.model
                device.serial_number = board_info.get("serial") or device.serial_number

            has_lte = await lte_present(device)
            if has_lte is not None:
                device.has_lte = has_lte

        await session.commit()
        count = len(devices)

    logger.info("Sprawdzanie aktualizacji zakończone: %d urządzeń", count)


async def syslog_retention_tick() -> None:
    """Retencja wpisow syslog — raz na dobe wystarczy, kasowanie idzie po indeksie
    received_at, wiec jest tanie nawet przy milionach wierszy."""
    async with async_session() as session:
        try:
            await enforce_retention(session)
            await enforce_all_device_caps(session)
            await enforce_notification_retention(session)
        except Exception as e:
            logger.warning("Retencja syslog nie powiodla sie: %s", e)


async def backup_scheduler_tick() -> None:
    """Co godzinę sprawdza, czy minął skonfigurowany w panelu /settings interwał
    (backup_schedule_hours) od ostatniego globalnego przebiegu kopii — jeśli tak,
    odpala run_all_backups() (sekwencyjnie po urządzeniach, patrz backup_service.py)."""
    async with async_session() as session:
        schedule_hours = await get_int_setting(session, "backup_schedule_hours")
        last_run_raw = await get_setting(session, "backup_last_run_at")

    if last_run_raw:
        last_run = datetime.datetime.fromisoformat(last_run_raw)
        if _utcnow() - last_run < datetime.timedelta(hours=schedule_hours):
            return

    async with async_session() as session:
        await set_setting(session, "backup_last_run_at", _utcnow().isoformat())

    await run_all_backups()


def start_scheduler() -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        poll_devices,
        "interval",
        seconds=settings.poll_interval_seconds,
        next_run_time=datetime.datetime.now(),
        id="poll_devices",
    )
    scheduler.add_job(
        check_updates,
        "interval",
        hours=24,
        next_run_time=datetime.datetime.now(),
        id="check_updates",
    )
    scheduler.add_job(
        backup_scheduler_tick,
        "interval",
        hours=1,
        next_run_time=datetime.datetime.now(),
        id="backup_scheduler_tick",
    )
    scheduler.add_job(
        syslog_retention_tick,
        "interval",
        hours=24,
        next_run_time=datetime.datetime.now(),
        id="syslog_retention_tick",
    )
    # Adresy LAN praktycznie sie nie zmieniaja, wiec dokladanie ich do cyklu minutowego
    # byloby przy 300 urzadzeniach czystym marnotrawstwem. Na zadanie i tak jest przycisk.
    scheduler.add_job(
        local_address.refresh_all,
        "interval",
        hours=1,
        next_run_time=datetime.datetime.now(),
        id="local_address_refresh",
    )
    scheduler.add_job(
        wg_snapshot.purge_old,
        "interval",
        hours=24,
        next_run_time=datetime.datetime.now(),
        id="wg_snapshot_purge",
    )
    # Odtwarzanie kopii, ktorego tunel albo peery nie weszly (agent niedostepny itp.),
    # ponawiane az do skutku. Bez dziennika na dysku job konczy sie na jednym os.path.exists.
    # Raz na dobe: czy jest nowsze wydanie portalu. TYLKO informacja (znaczek w panelu,
    # zakladka O portalu) — aktualizacje uruchamia czlowiek przyciskiem.
    scheduler.add_job(
        portal_update.check_quietly,
        "interval",
        hours=24,
        next_run_time=datetime.datetime.now() + datetime.timedelta(minutes=2),
        id="portal_update_check",
    )
    scheduler.add_job(
        resume_pending_restore,
        "interval",
        minutes=1,
        id="portal_restore_resume",
    )
    scheduler.add_job(
        weekly_report_tick,
        "interval",
        hours=1,  # sam job sprawdza dzien i godzine + znacznik ostatniej wysylki
        next_run_time=datetime.datetime.now(),
        id="weekly_report_tick",
    )
    scheduler.start()
    return scheduler
