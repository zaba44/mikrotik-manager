import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import AdminPeer, Backup, Device, Location, PingTarget, UpdateRun, UpdateRunStep


def label(name: str, location_name: str | None) -> str:
    """„BUDEX / SWITCH POE 24P" — nazwa jest unikalna tylko w lokalizacji, wiec tam, gdzie
    lokalizacji nie widac (e-mail, raport, nazwa pliku), podajemy ja razem z nazwa."""
    return f"{location_name} / {name}" if location_name else name


def file_label(text: str) -> str:
    """Etykieta do nazwy pliku: „BUDEX-SWITCH POE 24P" (bez ukosnika)."""
    return text.replace(" / ", "-")


async def device_label(session: AsyncSession, device: Device) -> str:
    location = await session.get(Location, device.location_id) if device.location_id else None
    return label(device.name, location.name if location else None)


async def list_locations(session: AsyncSession) -> list[Location]:
    return list((await session.execute(select(Location).order_by(Location.name))).scalars().all())


async def latest_device_run(session: AsyncSession, device_id: uuid.UUID) -> UpdateRun | None:
    result = await session.execute(
        select(UpdateRun)
        .options(selectinload(UpdateRun.steps))
        .where(UpdateRun.device_id == device_id)
        .order_by(UpdateRun.started_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def list_ping_targets(session: AsyncSession, device_id: uuid.UUID) -> list[PingTarget]:
    result = await session.execute(
        select(PingTarget).where(PingTarget.device_id == device_id).order_by(PingTarget.created_at)
    )
    return list(result.scalars().all())


async def list_admin_peers(session: AsyncSession) -> list[AdminPeer]:
    return list((await session.execute(select(AdminPeer).order_by(AdminPeer.created_at))).scalars().all())


async def list_device_backups(session: AsyncSession, device_id: uuid.UUID) -> list[Backup]:
    result = await session.execute(
        select(Backup).where(Backup.device_id == device_id).order_by(Backup.created_at.desc())
    )
    return list(result.scalars().all())


async def location_runs(session: AsyncSession, location_id: uuid.UUID) -> tuple[UpdateRun | None, list[UpdateRun]]:
    """(ostatni przebieg, wczesniejsze) — ile ich jest, pilnuje `update_runs_keep`."""
    result = await session.execute(
        select(UpdateRun)
        .options(selectinload(UpdateRun.steps).selectinload(UpdateRunStep.device))
        .where(UpdateRun.location_id == location_id)
        .order_by(UpdateRun.started_at.desc())
    )
    runs = list(result.scalars().all())
    return (runs[0] if runs else None), runs[1:]


