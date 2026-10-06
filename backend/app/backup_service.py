import asyncio
import datetime
import logging
import os
import uuid

from sqlalchemy import select

from app.backup_transfer import SFTP_USERNAME, cleanup_incoming, wait_for_upload
from app.config import settings
from app.database import async_session
from app.models import Backup, Device
from app.notifications import notify
from app.routeros_client import (
    cleanup_router_backup_file,
    create_binary_backup,
    export_config,
    push_backup_via_fetch,
)
from app.security import encrypt, encrypt_bytes
from app.settings_store import get_int_setting
from app.wg_config import wg

logger = logging.getLogger("backup_service")

STORE_DIR = "/data/backups/store"

# Odstęp między urządzeniami w run_all_backups — kopie mają lecieć sekwencyjnie,
# jedno urządzenie na raz, żeby kilkadziesiąt routerów nie zaczęło wysyłać plików
# do huba jednocześnie.
_INTER_DEVICE_DELAY_SECONDS = 5


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


async def _push_and_retrieve(device: Device, *, router_filename: str, token: str) -> tuple[bytes | None, str | None]:
    """Wspólna końcówka dla export i binary: router ma już gotowy, ustabilizowany
    plik (router_filename) — wysyła go przez /tool fetch (push), czekamy aż dotrze
    do naszego serwera SFTP, czytamy bajty, sprzątamy po obu stronach."""
    pushed = await push_backup_via_fetch(
        device,
        local_filename=router_filename,
        remote_filename=token,
        sftp_host=wg.server_ip,
        sftp_port=settings.backup_sftp_port,
        sftp_user=SFTP_USERNAME,
        sftp_password=settings.backup_sftp_password,
    )
    if not pushed["ok"]:
        return None, f"nie udało się wywołać /tool fetch: {pushed.get('error')}"

    incoming_path = await wait_for_upload(token, settings.backup_upload_timeout_seconds)
    await cleanup_router_backup_file(device, router_filename)  # best-effort, nie blokuje wyniku

    if incoming_path is None:
        return None, f"plik nie dotarł w ciągu {settings.backup_upload_timeout_seconds}s"

    with open(incoming_path, "rb") as f:
        raw = f.read()
    cleanup_incoming(token)
    return raw, None


async def _backup_export(device: Device) -> Backup:
    timestamp = _utcnow().strftime("%Y%m%d%H%M%S")
    router_name = f"mtm-export-{device.id.hex[:12]}-{timestamp}"

    created = await export_config(device, name=router_name)
    if not created["ok"]:
        return Backup(
            device_id=device.id, backup_type="export",
            status="failed", error_message=f"nie udało się utworzyć exportu na routerze: {created.get('error')}",
        )

    filename = created["filename"]
    raw, error = await _push_and_retrieve(device, router_filename=filename, token=filename)
    if error:
        return Backup(device_id=device.id, backup_type="export", status="failed", error_message=error)

    text = raw.decode("utf-8", errors="replace")
    return Backup(
        device_id=device.id, backup_type="export",
        content_text_encrypted=encrypt(text), size_bytes=len(raw), status="success",
    )


async def _backup_binary(device: Device) -> Backup:
    backup_id = uuid.uuid4()
    timestamp = _utcnow().strftime("%Y%m%d%H%M%S")
    router_name = f"mtm-{device.id.hex[:12]}-{timestamp}"

    created = await create_binary_backup(device, name=router_name)
    if not created["ok"]:
        return Backup(
            id=backup_id, device_id=device.id, backup_type="binary",
            status="failed", error_message=f"nie udało się utworzyć backupu na routerze: {created.get('error')}",
        )

    filename = created["filename"]
    raw, error = await _push_and_retrieve(device, router_filename=filename, token=filename)
    if error:
        return Backup(id=backup_id, device_id=device.id, backup_type="binary", status="failed", error_message=error)

    os.makedirs(STORE_DIR, exist_ok=True)
    store_path = os.path.join(STORE_DIR, f"{backup_id}.enc")
    with open(store_path, "wb") as f:
        f.write(encrypt_bytes(raw))

    return Backup(
        id=backup_id, device_id=device.id, backup_type="binary",
        file_path=store_path, size_bytes=len(raw), status="success",
    )


async def backup_device(device_id: uuid.UUID) -> None:
    async with async_session() as session:
        device = await session.get(Device, device_id)
        if device is None:
            return

        if not device.api_username or not device.api_password_encrypted:
            session.add(Backup(
                device_id=device.id, backup_type="export", status="failed",
                error_message="urządzenie nie ma skonfigurowanych danych API",
            ))
            await session.commit()
            logger.warning("Pomijam kopię %s — brak danych API", device.name)
            return

        export_backup = await _backup_export(device)
        session.add(export_backup)
        binary_backup = await _backup_binary(device)
        session.add(binary_backup)
        await session.commit()

        logger.info(
            "Kopia %s: export=%s binary=%s", device.name, export_backup.status, binary_backup.status
        )

        # Nieudana kopia to cichy zabojca — potrafi nie dzialac miesiacami, a dowiadujesz
        # sie przy odtwarzaniu. Zglaszamy raz na urzadzenie, nie osobno per typ.
        failed = [b for b in (export_backup, binary_backup) if b.status != "success"]
        if failed:
            details = "\n".join(f"  {b.backup_type}: {b.error_message}" for b in failed)
            await notify(
                session, event_key="backup.failed", device_id=device.id,
                dedup_key=f"backup.failed:{device.id}",
                subject=f"[MTM] Nieudana kopia: {device.name}",
                body=f"Kopia zapasowa {device.name} nie powiodła się.\n\n{details}",
            )

    await enforce_retention(device_id)


async def enforce_retention(device_id: uuid.UUID) -> None:
    """Retencja liczy WYLACZNIE udane kopie. Wczesniej limit obejmowal tez proby nieudane,
    wiec przy retencji 10 wystarczylo dziesiec nocy z awaria (router offline, padniete lacze),
    zeby nie zostala ani jedna dobra kopia — dokladnie wtedy, gdy jest najbardziej potrzebna
    (wytkniete w recenzji zewnetrznej). Nieudane proby to historia diagnostyczna: maja osobny
    limit tej samej wielkosci i nigdy nie wypieraja udanych kopii."""
    async with async_session() as session:
        retention = await get_int_setting(session, "backup_retention_count")

        for backup_type in ("export", "binary"):
            for statuses in (("success",), ("failed",)):
                rows = (
                    (
                        await session.execute(
                            select(Backup)
                            .where(Backup.device_id == device_id, Backup.backup_type == backup_type,
                                   Backup.status.in_(statuses))
                            .order_by(Backup.created_at.desc())
                        )
                    )
                    .scalars()
                    .all()
                )
                for old in rows[retention:]:
                    if old.file_path and os.path.exists(old.file_path):
                        os.remove(old.file_path)
                    await session.delete(old)

        await session.commit()


async def run_all_backups() -> None:
    async with async_session() as session:
        device_ids = list(
            (await session.execute(select(Device.id).order_by(Device.created_at))).scalars().all()
        )

    logger.info("Start sekwencji kopii zapasowych: %d urządzeń", len(device_ids))
    for device_id in device_ids:
        try:
            await backup_device(device_id)
        except Exception:
            logger.exception("Błąd podczas kopii urządzenia %s", device_id)
        await asyncio.sleep(_INTER_DEVICE_DELAY_SECONDS)
    logger.info("Sekwencja kopii zapasowych zakończona")
