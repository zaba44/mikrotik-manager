"""Utrzymanie zapisanych wpisów syslog: retencja automatyczna + ręczne czyszczenie.

Trzy zakresy czyszczenia (urządzenie / lokalizacja / cały portal) to ta sama operacja
z innym warunkiem WHERE, więc nie ma powodu wybierać jednego — każdy odpowiada innej
sytuacji: po diagnozie jednego urządzenia, po awarii w lokalizacji, przed oddaniem
portalu komuś innemu. Retencja czasowa działa niezależnie i to ona pilnuje, żeby
tabela nie rosła w nieskończoność.
"""
import datetime
import logging

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Device, DeviceLogEntry, Notification
from app.settings_store import get_int_setting

logger = logging.getLogger(__name__)


async def count_entries(session: AsyncSession, *, device_id=None, location_id=None) -> int:
    stmt = select(func.count(DeviceLogEntry.id))
    if device_id is not None:
        stmt = stmt.where(DeviceLogEntry.device_id == device_id)
    elif location_id is not None:
        stmt = stmt.where(DeviceLogEntry.device_id.in_(
            select(Device.id).where(Device.location_id == location_id)
        ))
    return (await session.execute(stmt)).scalar_one()


async def purge(session: AsyncSession, *, device_id=None, location_id=None) -> int:
    """Bez argumentów czyści WSZYSTKO. Zwraca liczbę usuniętych wpisów."""
    stmt = delete(DeviceLogEntry)
    if device_id is not None:
        stmt = stmt.where(DeviceLogEntry.device_id == device_id)
    elif location_id is not None:
        stmt = stmt.where(DeviceLogEntry.device_id.in_(
            select(Device.id).where(Device.location_id == location_id)
        ))
    result = await session.execute(stmt)
    await session.commit()
    return result.rowcount or 0


async def enforce_device_cap(session: AsyncSession, device_id, cap: int) -> int:
    """Twardy sufit wpisów na urządzenie — DRUGI bezpiecznik, obok retencji czasowej.
    Retencja po dniach nie chroni przed nagłym zalewem: przy włączonym `info` jedno
    urządzenie robi setki wpisów na dobę (zmierzone), a sprzątanie przyszłoby dopiero
    po 90 dniach. Limit ogranicza najgorszy przypadek niezależnie od tempa — dokładnie
    tak, jak bufor w samym RouterOS.

    Kasujemy po `received_at`, bo na tej kolumnie mamy indeks (device_id, received_at)."""
    if cap <= 0:
        return 0
    cutoff = (await session.execute(
        select(DeviceLogEntry.received_at)
        .where(DeviceLogEntry.device_id == device_id)
        .order_by(DeviceLogEntry.received_at.desc())
        .offset(cap).limit(1)
    )).scalar_one_or_none()
    if cutoff is None:
        return 0  # poniżej limitu, nie ma czego przycinać
    result = await session.execute(
        delete(DeviceLogEntry).where(
            DeviceLogEntry.device_id == device_id, DeviceLogEntry.received_at <= cutoff
        )
    )
    await session.commit()
    return result.rowcount or 0


async def syslog_stats(session: AsyncSession) -> dict:
    """Liczby do panelu. Przy 300 urządzeniach na VPS-ie trzeba WIDZIEĆ, że coś rośnie,
    zanim skończy się dysk — samo ustawienie retencji o tym nie powie."""
    total = (await session.execute(select(func.count(DeviceLogEntry.id)))).scalar_one()
    connected = (await session.execute(
        select(func.count(Device.id)).where(Device.syslog_enabled.is_(True))
    )).scalar_one()
    with_info = (await session.execute(
        select(func.count(Device.id)).where(Device.syslog_info_enabled.is_(True))
    )).scalar_one()
    oldest = (await session.execute(select(func.min(DeviceLogEntry.received_at)))).scalar_one()
    # Ile urządzeń ma jeszcze konfigurację na routerze wg naszej bazy — po wyłączeniu
    # globalnego przełącznika to one dalej wysyłają w próżnię.
    return {
        "total": total,
        "connected": connected,
        "with_info": with_info,
        "oldest": oldest,
        # ~200 B na wiersz z narzutem Postgresa i indeksami (oszacowane z pomiarów)
        "approx_mb": round(total * 200 / 1024 / 1024, 1),
    }


async def enforce_retention(session: AsyncSession) -> int:
    """Kasuje wpisy starsze niż `syslog_retention_days`. 0 = trzymaj bez ograniczeń
    (świadoma decyzja użytkownika, nie domyślna — domyślnie 90 dni)."""
    days = await get_int_setting(session, "syslog_retention_days")
    if days <= 0:
        return 0
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    result = await session.execute(
        delete(DeviceLogEntry).where(DeviceLogEntry.received_at < cutoff)
    )
    await session.commit()
    removed = result.rowcount or 0
    if removed:
        logger.info("Retencja syslog: usunięto %s wpisów starszych niż %s dni", removed, days)
    return removed


async def enforce_all_device_caps(session: AsyncSession) -> int:
    """Przycięcie do limitu dla każdego urządzenia — odpalane w tym samym jobie co
    retencja. Odbiornik robi to też na bieżąco, ale tylko dla urządzeń, które akurat
    coś przysłały; to domyka resztę (np. po obniżeniu limitu w panelu)."""
    cap = await get_int_setting(session, "syslog_max_entries_per_device")
    if cap <= 0:
        return 0
    device_ids = (await session.execute(
        select(DeviceLogEntry.device_id).group_by(DeviceLogEntry.device_id)
        .having(func.count(DeviceLogEntry.id) > cap)
    )).scalars().all()
    total = 0
    for device_id in device_ids:
        total += await enforce_device_cap(session, device_id, cap)
    if total:
        logger.info("Limit wpisów: przycięto %s wpisów na %s urządzeniach", total, len(device_ids))
    return total


async def enforce_notification_retention(session: AsyncSession) -> int:
    """Dziennik powiadomien tez rosnie — trzymamy go krocej niz logi urzadzen, bo sluzy
    do wgladu i do liczenia limitow z ostatniej godziny, nie do archiwum."""
    days = await get_int_setting(session, "notify_retention_days")
    if days <= 0:
        return 0
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    result = await session.execute(
        delete(Notification).where(Notification.created_at < cutoff)
    )
    await session.commit()
    removed = result.rowcount or 0
    if removed:
        logger.info("Retencja powiadomien: usunieto %s wpisow", removed)
    return removed
