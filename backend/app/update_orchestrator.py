import asyncio
import datetime
import logging
import uuid

from sqlalchemy import select

from app.config import settings
from app.database import async_session
from app.notifications import notify
from app.models import Device, UpdateRun, UpdateRunStep
from app.routeros_client import (
    check_for_updates,
    get_routerboard_info,
    get_status,
    install_package_update,
    reboot,
    upgrade_firmware,
)
from app.routerwg.model import parse_duration

logger = logging.getLogger("update_orchestrator")

_POLL_INTERVAL_SECONDS = 10

# Sprawdzenie „czy cos juz biegnie" i utworzenie przebiegu MUSZA byc jedna operacja.
# Miedzy nimi sa await-y, wiec dwa zadania (podwojne klikniecie, dwoch adminow, aktualizacja
# urzadzenia rownolegle z aktualizacja jego lokalizacji) mogly oba zobaczyc „nic nie biegnie"
# i oba ruszyc (wytkniete w recenzji zewnetrznej). Blokada w pamieci procesu wystarcza,
# bo backend dziala jako JEDEN proces uvicorna — przy wielu workerach trzeba by blokady
# w bazie (np. pg_advisory_lock).
_RUN_LOCK = asyncio.Lock()


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


async def _has_active_device_run(session, device_id: uuid.UUID) -> bool:
    result = await session.execute(
        select(UpdateRun.id).where(UpdateRun.device_id == device_id, UpdateRun.status == "running")
    )
    return result.first() is not None


async def _has_active_location_run(session, location_id: uuid.UUID) -> bool:
    result = await session.execute(
        select(UpdateRun.id).where(UpdateRun.location_id == location_id, UpdateRun.status == "running")
    )
    return result.first() is not None


async def cleanup_stale_runs() -> None:
    """Wołane przy starcie backendu — runy, które zostały 'running' bo backend padł
    w trakcie, nigdy same się nie dokończą. Oznacz jako failed, żeby UI nie kłamało."""
    async with async_session() as session:
        stale = (await session.execute(select(UpdateRun).where(UpdateRun.status == "running"))).scalars().all()
        for run in stale:
            run.status = "failed"
            run.finished_at = _utcnow()
            run.error_message = "Przerwane restartem backendu w trakcie wykonywania"
        if stale:
            await session.commit()
            logger.warning("Oznaczono %d przerwanych runów jako failed przy starcie", len(stale))


async def _uptime(device: Device) -> float | None:
    status = await get_status(device)
    return parse_duration(status.get("uptime")) if status.get("reachable") else None


async def _wait_until_online(session, run_id: uuid.UUID, device: Device, uptime_before: float | None) -> bool:
    """Czekamy, az router wroci PO RESTARCIE — nie na pierwsza odpowiedz.

    Pierwsze sprawdzenie leci kilka sekund po poleceniu instalacji albo restartu; jesli
    router jeszcze nie zaczal sie wylaczac, odpowiada STARA instancja i dawniej krok
    konczyl sie „sukcesem", choc restart dopiero mial nastapic. Dowodem restartu jest
    spadek uptime'u ponizej wartosci sprzed polecenia. Gdy uptime'u sprzed nie znamy
    (router nie odpowiadal), zostaje sama osiagalnosc — lepiej niz zatrzymac sekwencje."""
    step = UpdateRunStep(run_id=run_id, device_id=device.id, step_type="wait_online")
    session.add(step)
    await session.commit()

    deadline = _utcnow() + datetime.timedelta(seconds=settings.update_wait_timeout_seconds)
    seen_old_instance = False

    while _utcnow() < deadline:
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)
        status = await get_status(device)
        if not status["reachable"]:
            continue
        now = parse_duration(status.get("uptime"))
        if uptime_before is not None and now is not None and now >= uptime_before:
            seen_old_instance = True  # odpowiada, ale to jeszcze ta sama instancja
            continue
        step.status = "succeeded"
        step.finished_at = _utcnow()
        step.detail = f"wrócił po restarcie (uptime {status.get('uptime')})"
        await session.commit()
        return True

    step.status = "failed"
    step.finished_at = _utcnow()
    step.detail = (f"router odpowiada, ale nie zrestartował się (uptime nie spadł) — timeout "
                   f"{settings.update_wait_timeout_seconds}s" if seen_old_instance
                   else f"timeout po {settings.update_wait_timeout_seconds}s")
    await session.commit()
    return False


async def _record_verify(session, run_id: uuid.UUID, device: Device, ok: bool, detail: str) -> None:
    step = UpdateRunStep(run_id=run_id, device_id=device.id, step_type="verify",
                         status="succeeded" if ok else "failed", detail=detail)
    step.finished_at = _utcnow()
    session.add(step)
    await session.commit()


async def _run_software_step(session, run_id: uuid.UUID, device: Device) -> bool:
    step = UpdateRunStep(run_id=run_id, device_id=device.id, step_type="software")
    session.add(step)
    await session.commit()

    result = await install_package_update(device)
    step.status = "succeeded" if result["ok"] else "failed"
    step.finished_at = _utcnow()
    step.detail = result.get("detail") or result.get("error")
    await session.commit()
    return result["ok"]


async def _run_firmware_step(session, run_id: uuid.UUID, device: Device) -> bool:
    step = UpdateRunStep(run_id=run_id, device_id=device.id, step_type="firmware")
    session.add(step)
    await session.commit()

    result = await upgrade_firmware(device)
    step.status = "succeeded" if result["ok"] else "failed"
    step.finished_at = _utcnow()
    step.detail = result.get("error")
    await session.commit()
    if not result["ok"]:
        return False

    reboot_step = UpdateRunStep(run_id=run_id, device_id=device.id, step_type="reboot")
    session.add(reboot_step)
    await session.commit()
    rb = await reboot(device)
    reboot_step.status = "succeeded" if rb["ok"] else "failed"
    reboot_step.detail = rb.get("error") or rb.get("note")
    reboot_step.finished_at = _utcnow()
    await session.commit()
    return rb["ok"]


async def _refresh_software_info(session, device: Device) -> None:
    """Świeże sprawdzenie wersji RouterOS tuż przed decyzją — kolumny w bazie mogą być
    nieaktualne (scheduler check_updates leci raz na 24h, urządzenie mogło zostać
    zaktualizowane poza portalem). Best-effort: jak się nie uda (offline), kolumny
    zostają jakie były."""
    info = await check_for_updates(device)
    if info["ok"]:
        device.available_routeros_version = info.get("latest_version")
        if info.get("installed_version"):
            device.routeros_version = info.get("installed_version")
        await session.commit()


async def _refresh_firmware_info(session, device: Device) -> None:
    """Świeże sprawdzenie firmware'u. Ważne w sekwencji 'both': po aktualizacji
    RouterOS wartość upgrade-firmware zmienia się na nową wersję, więc firmware trzeba
    sprawdzać dopiero po kroku software (i po powrocie urządzenia online)."""
    board = await get_routerboard_info(device)
    if board["ok"]:
        device.current_firmware = board.get("current_firmware")
        device.available_firmware = board.get("upgrade_firmware")
        await session.commit()


def _normalize_version(value: str | None) -> str | None:
    """RouterOS podaje wersję w dwóch formatach zależnie od źródła: /system/resource
    zwraca '7.23.2 (stable)', a check-for-updates '7.23.2'. Do porównania bierzemy sam
    numer (pierwszy token), żeby te dwa formaty się zrównały."""
    return value.split()[0] if value else value


def _software_already_current(device: Device) -> bool:
    """True tylko gdy pewnie wiemy, że zainstalowana = najnowsza. Brak danych (np.
    urządzenie nieosiągalne, checka nigdy nie było) -> False, żeby zachować dotychczasowe
    zachowanie (próba + ewentualne przerwanie sekwencji), a nie po cichu pomijać."""
    installed = _normalize_version(device.routeros_version)
    latest = _normalize_version(device.available_routeros_version)
    return bool(installed and latest and installed == latest)


def _firmware_already_current(device: Device) -> bool:
    current = _normalize_version(device.current_firmware)
    available = _normalize_version(device.available_firmware)
    return bool(current and available and current == available)


async def _record_skip(session, run_id: uuid.UUID, device: Device, step_type: str, detail: str) -> None:
    step = UpdateRunStep(
        run_id=run_id, device_id=device.id, step_type=step_type, status="skipped", detail=detail
    )
    step.finished_at = _utcnow()
    session.add(step)
    await session.commit()


async def _device_sequence(session, run: UpdateRun, device: Device, mode: str) -> tuple[bool, str | None]:
    """mode: software | firmware | both. Przed każdym krokiem sprawdza świeżo wersję
    i pomija (bez restartu) to, co już jest w najnowszej wersji. Po kazdym kroku SPRAWDZA
    wynik: aktualizacja konczy sie sukcesem dopiero, gdy router zglasza oczekiwana wersje —
    sama osiagalnosc REST niczego nie dowodzi (router, ktory sie nie zaktualizowal, tez
    odpowiada). Zwraca (ok, powod porazki)."""
    if mode in ("software", "both"):
        await _refresh_software_info(session, device)
        if _software_already_current(device):
            await _record_skip(
                session, run.id, device, "software",
                f"RouterOS {device.routeros_version} już najnowszy — pominięto",
            )
        else:
            target = _normalize_version(device.available_routeros_version)
            before = await _uptime(device)
            if not await _run_software_step(session, run.id, device):
                return False, f"{device.name}: polecenie instalacji RouterOS nie powiodło się"
            if not await _wait_until_online(session, run.id, device, before):
                return False, f"{device.name}: nie wrócił po restarcie w oczekiwanym czasie"
            await asyncio.sleep(settings.update_post_online_buffer_seconds)
            await _refresh_software_info(session, device)
            now = _normalize_version(device.routeros_version)
            if now != target:
                # check-for-updates tuz po restarcie bywa chwilowo niedostepny — wtedy w bazie
                # zostaje stara wersja i weryfikacja klamalaby porazka. Drugie zrodlo: /system/resource.
                status = await get_status(device)
                if status.get("reachable") and status.get("version"):
                    device.routeros_version = status["version"]
                    await session.commit()
                    now = _normalize_version(status["version"])
            ok = bool(target) and now == target
            await _record_verify(session, run.id, device, ok,
                                 f"RouterOS {now} (oczekiwano {target})")
            if not ok:
                return False, f"{device.name}: po aktualizacji RouterOS ma {now}, oczekiwano {target}"

    if mode in ("firmware", "both"):
        await _refresh_firmware_info(session, device)
        if _firmware_already_current(device):
            await _record_skip(
                session, run.id, device, "firmware",
                f"firmware {device.current_firmware} już najnowszy — pominięto",
            )
        else:
            target = _normalize_version(device.available_firmware)
            before = await _uptime(device)
            if not await _run_firmware_step(session, run.id, device):
                return False, f"{device.name}: wgranie firmware albo restart nie powiodły się"
            if not await _wait_until_online(session, run.id, device, before):
                return False, f"{device.name}: nie wrócił po restarcie w oczekiwanym czasie"
            await asyncio.sleep(settings.update_post_online_buffer_seconds)
            await _refresh_firmware_info(session, device)
            now = _normalize_version(device.current_firmware)
            if now != target:
                await asyncio.sleep(5)  # jedna ponowna proba — odczyt routerboard tuz po starcie bywa pusty
                await _refresh_firmware_info(session, device)
                now = _normalize_version(device.current_firmware)
            ok = bool(target) and now == target
            await _record_verify(session, run.id, device, ok, f"firmware {now} (oczekiwano {target})")
            if not ok:
                return False, f"{device.name}: po restarcie firmware to {now}, oczekiwano {target}"

    return True, None


async def run_device_update(device_id: uuid.UUID, mode: str) -> None:
    async with async_session() as session:
        device = await session.get(Device, device_id)
        if device is None:
            return

        async with _RUN_LOCK:
            if await _has_active_device_run(session, device_id):
                logger.warning("Run już trwa dla urządzenia %s, pomijam", device_id)
                return
            if device.location_id and await _has_active_location_run(session, device.location_id):
                logger.warning("Run lokalizacji już trwa i obejmuje %s, pomijam", device_id)
                return
            run = UpdateRun(scope="device", device_id=device_id, status="running")
            session.add(run)
            await session.commit()

        try:
            ok, reason = await _device_sequence(session, run, device, mode)
            run.status = "succeeded" if ok else "failed"
            if not ok:
                run.error_message = reason
        except Exception as e:
            logger.exception("Błąd podczas aktualizacji urządzenia %s", device_id)
            run.status = "failed"
            run.error_message = str(e)
        run.finished_at = _utcnow()
        await session.commit()

        if run.status == "failed":
            await notify(
                session, event_key="update.failed", device_id=device.id,
                dedup_key=f"update.failed:{device.id}",
                subject=f"[MTM] Nieudana aktualizacja: {device.name}",
                body=(f"Aktualizacja {device.name} zakończyła się niepowodzeniem.\n\n"
                      f"Tryb: {mode}\nSzczegóły: {run.error_message or 'brak'}"),
            )


async def run_location_update(location_id: uuid.UUID) -> None:
    async with async_session() as session:
        async with _RUN_LOCK:
            if await _has_active_location_run(session, location_id):
                logger.warning("Run lokalizacji %s już trwa, pomijam", location_id)
                return

            devices = list(
                (
                    await session.execute(
                        select(Device).where(Device.location_id == location_id).order_by(Device.created_at)
                    )
                )
                .scalars()
                .all()
            )
            for device in devices:
                if await _has_active_device_run(session, device.id):
                    logger.warning("Urządzenie %s ma już aktywny run, przerywam start sekwencji lokalizacji", device.id)
                    return

            run = UpdateRun(scope="location", location_id=location_id, status="running")
            session.add(run)
            await session.commit()

        aborted = False
        for device in devices:
            try:
                ok, reason = await _device_sequence(session, run, device, "both")
            except Exception as e:
                logger.exception("Błąd podczas aktualizacji %s w sekwencji lokalizacji", device.id)
                ok, reason = False, str(e)
            if not ok:
                aborted = True
                run.error_message = f"{reason} — sekwencja przerwana"
                break

        run.status = "aborted" if aborted else "succeeded"
        run.finished_at = _utcnow()
        await session.commit()
