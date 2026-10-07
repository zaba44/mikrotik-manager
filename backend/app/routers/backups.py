import os
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.timefmt import dt
from app.database import get_session
from app.filenames import ascii_part
from app.models import Backup, Device
from app.security import decrypt, decrypt_bytes

router = APIRouter(prefix="/backups")


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=404, detail="Nie znaleziono kopii")


def _safe_filename_part(value: str) -> str:
    """Wspolny mechanizm — patrz app/filenames.py (pulapka isalnum() z polskimi znakami)."""
    return ascii_part(value, "urzadzenie")


@router.get("/{backup_id}/download")
async def download_backup(backup_id: str, session: AsyncSession = Depends(get_session)):
    backup = await session.get(Backup, _parse_uuid(backup_id))
    if backup is None or backup.status != "success":
        raise HTTPException(status_code=404, detail="Nie znaleziono kopii")

    device = await session.get(Device, backup.device_id)
    device_name = _safe_filename_part(device.name if device else "urzadzenie")
    timestamp = dt(backup.created_at, "%Y%m%d-%H%M%S")  # czas lokalny panelu, jak w tabeli kopii

    if backup.backup_type == "wg-snapshot":
        text = decrypt(backup.content_text_encrypted)
        filename = f"{device_name}-zrzut-wg-{timestamp}.json"
        return Response(
            content=text,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    if backup.backup_type == "export":
        text = decrypt(backup.content_text_encrypted)
        filename = f"{device_name}-export-{timestamp}.rsc"
        return Response(
            content=text,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    if not backup.file_path or not os.path.exists(backup.file_path):
        raise HTTPException(status_code=404, detail="Plik kopii nie istnieje na dysku")

    with open(backup.file_path, "rb") as f:
        raw = decrypt_bytes(f.read())
    filename = f"{device_name}-backup-{timestamp}.backup"
    return Response(
        content=raw,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{backup_id}/delete")
async def delete_backup(backup_id: str, session: AsyncSession = Depends(get_session)):
    backup = await session.get(Backup, _parse_uuid(backup_id))
    if backup is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono kopii")

    device_id = backup.device_id
    if backup.file_path and os.path.exists(backup.file_path):
        os.remove(backup.file_path)

    await session.delete(backup)
    await session.commit()
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)
