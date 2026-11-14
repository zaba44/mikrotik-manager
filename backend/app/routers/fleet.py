"""Flota: pulpit zbiorczy (stan, ostrzezenia) i akcje na wielu urzadzeniach naraz —
takze z roznych lokalizacji. Tylko administrator (prefiks w main._ADMIN_PREFIXES)."""
import uuid
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app import fleet_actions, fleet_health
from app.backup_service import backup_device
from app.database import get_session
from app.models import Device
from app.queries import list_locations
from app.templating import templates
from app.timefmt import utc_now_aware
from app.update_orchestrator import run_devices_update

router = APIRouter(prefix="/fleet")

# Akcje, ktore trwaja dlugo i maja wlasny przebieg (log krokow na stronie urzadzenia).
JOBS = {
    "update": ("Aktualizuj RouterOS i firmware", "Aktualizacja idzie po kolei, urządzenie po urządzeniu "
               "(nigdy równolegle). Postęp i wynik są na stronach urządzeń."),
    "backup": ("Zrób kopię teraz", "Kopie wykonują się po kolei w tle; wynik jest w sekcji kopii urządzenia."),
}


async def _selected(session: AsyncSession, ids: list[str]) -> list[Device]:
    wanted = []
    for raw in ids:
        try:
            wanted.append(uuid.UUID(raw))
        except ValueError:
            continue
    if not wanted:
        return []
    rows = (await session.execute(
        select(Device).options(selectinload(Device.location)).where(Device.id.in_(wanted)).order_by(Device.name)
    )).scalars().all()
    return list(rows)


async def _backups_in_order(ids: list[uuid.UUID]) -> None:
    for device_id in ids:
        await backup_device(device_id)


@router.get("")
async def fleet_page(request: Request, note: str = "", err: str = "", session: AsyncSession = Depends(get_session)):
    devices = await fleet_health.load_devices(session)
    failures = await fleet_health.failed_backups(session)
    return templates.TemplateResponse("fleet.html", {
        "request": request, "nav_locations": await list_locations(session), "devices": devices,
        "summary": fleet_health.summary(devices, failures),
        "warnings": fleet_health.warnings(devices, failures),
        "backup_failures": failures, "actions": fleet_actions.ACTIONS, "jobs": JOBS,
        "update_available": fleet_health.update_available, "note": note or None, "error": err or None,
    })


@router.post("/run")
async def fleet_run(request: Request, action: str = Form(""), device_ids: list[str] = Form(default=[]),
                    back: str = Form("/fleet"), session: AsyncSession = Depends(get_session)):
    back = back if back.startswith("/") and not back.startswith("//") else "/fleet"
    devices = await _selected(session, device_ids)
    sep = "&" if "?" in back else "?"
    if not devices:
        return RedirectResponse(url=f"{back}{sep}err=" + quote("Nie zaznaczono żadnego urządzenia."), status_code=303)
    if action in JOBS:
        ids = [d.id for d in devices]
        job = run_devices_update if action == "update" else _backups_in_order
        request.app.state.scheduler.add_job(job, args=[ids], next_run_time=utc_now_aware())
        return RedirectResponse(url=f"{back}{sep}note=" + quote(
            f"{JOBS[action][0]}: uruchomiono dla {len(ids)} urządzeń. {JOBS[action][1]}"), status_code=303)
    if action not in fleet_actions.ACTIONS:
        return RedirectResponse(url=f"{back}{sep}err=" + quote("Wybierz akcję."), status_code=303)
    results = await fleet_actions.run_many(session, devices, action)
    return templates.TemplateResponse("fleet_result.html", {
        "request": request, "nav_locations": await list_locations(session),
        "action": fleet_actions.ACTIONS[action], "results": results, "back": back,
        "ok_count": sum(1 for r in results if r["ok"]),
    })
