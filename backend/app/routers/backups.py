import os
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import config_diff
from app.queries import list_locations
from app.templating import templates
from app.timefmt import dt
from app.database import get_session
from app.filenames import ascii_part
from app.models import Backup, Device, Location
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


@router.get("/{backup_id}/diff")
async def diff_backup(request: Request, backup_id: str, other: str = "", session: AsyncSession = Depends(get_session)):
    """Co sie zmienilo w konfiguracji: ten eksport wzgledem wczesniejszego (domyslnie
    poprzedniego udanego). Sekrety ukryte — zob. app/config_diff.py."""
    backup = await session.get(Backup, _parse_uuid(backup_id))
    if backup is None or backup.status != "success" or backup.backup_type != "export":
        raise HTTPException(status_code=404, detail="Nie znaleziono eksportu")
    device = await session.get(Device, backup.device_id)
    exports = (await session.execute(
        select(Backup).where(Backup.device_id == backup.device_id, Backup.backup_type == "export",
                             Backup.status == "success").order_by(Backup.created_at.desc()))).scalars().all()
    older = [b for b in exports if b.created_at < backup.created_at]
    base = next((b for b in exports if str(b.id) == other and b.id != backup.id), None) or (older[0] if older else None)
    rows, added, removed = [], 0, 0
    current = backup  # kopia, z ktorej strony przyszedl uzytkownik — formularz wyboru zostaje przy niej
    if base is not None:
        first, second = sorted((base, backup), key=lambda b: b.created_at)
        rows = config_diff.diff(decrypt(first.content_text_encrypted), decrypt(second.content_text_encrypted))
        added, removed = config_diff.stats(rows)
        base, backup = first, second
    return templates.TemplateResponse("backup_diff.html", {
        "request": request, "nav_locations": await list_locations(session), "device": device,
        "backup": backup, "base": base, "current": current, "exports": exports, "rows": rows, "added": added, "removed": removed,
    }, headers={"Cache-Control": "no-store"})


@router.get("/{backup_id}/download")
async def download_backup(backup_id: str, session: AsyncSession = Depends(get_session)):
    backup = await session.get(Backup, _parse_uuid(backup_id))
    if backup is None or backup.status != "success":
        raise HTTPException(status_code=404, detail="Nie znaleziono kopii")

    device = await session.get(Device, backup.device_id)
    device_name = _safe_filename_part(device.name if device else "urzadzenie")
    location = await session.get(Location, device.location_id) if device and device.location_id else None
    if location:  # nazwa urzadzenia jest unikalna tylko w lokalizacji — w pliku obie
        device_name = f"{_safe_filename_part(location.name)}-{device_name}"
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
