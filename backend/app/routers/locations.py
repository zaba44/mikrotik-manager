import datetime
import uuid
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_user, is_admin, require_location, require_operate_location
from app.database import get_session
from app.log_report import build_report, content_disposition
from app.log_store import purge
from app.notifications import scope_view
from app.notify_forms import apply_scope_form
from app.models import Device, Location, NotificationOverride, UpdateRun, User
from app.queries import latest_location_run, list_locations
from app.templating import templates
from app.update_orchestrator import run_location_update

router = APIRouter(prefix="/locations")


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=404, detail="Nie znaleziono lokalizacji")


async def _devices_at(session: AsyncSession, location_id: uuid.UUID) -> list[Device]:
    return list(
        (
            await session.execute(select(Device).where(Device.location_id == location_id).order_by(Device.name))
        ).scalars().all()
    )


@router.get("/{location_id}/log-report")
async def location_log_report(
    request: Request, location_id: str, session: AsyncSession = Depends(get_session)
):
    """Zbiorczy raport zdarzeń z całej lokalizacji — jednorazowy odczyt buforów logów,
    bez włączania syslogu i bez zapisywania czegokolwiek. Urządzenia po kolei."""
    loc_id = _parse_uuid(location_id)
    location = await session.get(Location, loc_id)
    if location is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono lokalizacji")
    require_location(request, loc_id)
    devices = await _devices_at(session, loc_id)
    await session.close()  # odczyt kilkunastu buforów potrafi potrwać

    text = await build_report(devices, scope_name=location.name)
    return Response(
        content=text.encode("utf-8"),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": content_disposition(location.name)},
    )


@router.post("/{location_id}/syslog/clear")
async def clear_location_syslog(
    request: Request, location_id: str, session: AsyncSession = Depends(get_session)
):
    """Czyści zapisane wpisy syslog ze wszystkich urządzeń lokalizacji."""
    loc_id = _parse_uuid(location_id)
    location = await session.get(Location, loc_id)
    if location is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono lokalizacji")
    user = current_user(request)
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Tylko administrator")
    await purge(session, location_id=loc_id)
    return RedirectResponse(url=f"/locations/{location_id}", status_code=303)


@router.get("/{location_id}/fragment/notifications")
async def location_notifications_fragment(
    request: Request, location_id: str, session: AsyncSession = Depends(get_session)
):
    location = await session.get(Location, _parse_uuid(location_id))
    if location is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono lokalizacji")
    require_location(request, location.id)
    ctx = await scope_view(session, location=location)
    return templates.TemplateResponse(
        "_notify_scope.html",
        {"request": request, "scope_url": f"/locations/{location.id}", **ctx},
    )


@router.post("/{location_id}/notifications")
async def set_location_notifications(
    request: Request, location_id: str, session: AsyncSession = Depends(get_session)
):
    location = await session.get(Location, _parse_uuid(location_id))
    if location is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono lokalizacji")
    if not is_admin(current_user(request)):
        raise HTTPException(status_code=403, detail="Tylko administrator")
    form = await request.form()
    await apply_scope_form(session, "location", location.id, form)
    ctx = await scope_view(session, location=location)
    return templates.TemplateResponse(
        "_notify_scope.html",
        {"request": request, "scope_url": f"/locations/{location.id}", **ctx},
    )


@router.get("")
async def index(request: Request, session: AsyncSession = Depends(get_session)):
    user = current_user(request)
    if is_admin(user):
        locations = await list_locations(session)
    else:
        loc = await session.get(Location, user.location_id) if user.location_id else None
        locations = [loc] if loc else []
    return templates.TemplateResponse(
        "locations.html", {"request": request, "locations": locations, "nav_locations": locations}
    )


@router.post("")
async def create_location(
    request: Request,
    name: str = Form(...),
    notes: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    session.add(Location(name=name.strip(), notes=notes.strip() or None))

    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        locations = await list_locations(session)
        return templates.TemplateResponse(
            "_locations_list.html",
            {
                "request": request,
                "locations": locations,
                "error": f'Lokalizacja "{name.strip()}" już istnieje.',
            },
            status_code=409,
        )

    locations = await list_locations(session)
    return templates.TemplateResponse("_locations_list.html", {"request": request, "locations": locations})


@router.get("/{location_id}")
async def location_detail(request: Request, location_id: str, err: str = "",
                          session: AsyncSession = Depends(get_session)):
    location = await session.get(Location, _parse_uuid(location_id))
    if location is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono lokalizacji")
    require_location(request, location.id)

    devices = await _devices_at(session, location.id)
    nav_locations = await list_locations(session)
    run = await latest_location_run(session, location.id)
    return templates.TemplateResponse(
        "locations/detail.html",
        {"request": request, "location": location, "devices": devices, "nav_locations": nav_locations,
         "run": run, "error": err or None},
    )


@router.post("/{location_id}")
async def update_location(
    request: Request,
    location_id: str,
    name: str = Form(...),
    notes: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    location = await session.get(Location, _parse_uuid(location_id))
    if location is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono lokalizacji")

    location.name = name.strip()
    location.notes = notes.strip() or None

    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        await session.refresh(location)
        devices = await _devices_at(session, location.id)
        nav_locations = await list_locations(session)
        run = await latest_location_run(session, location.id)
        return templates.TemplateResponse(
            "locations/detail.html",
            {
                "request": request,
                "location": location,
                "devices": devices,
                "nav_locations": nav_locations,
                "run": run,
                "error": f'Nazwa "{name.strip()}" jest już zajęta przez inną lokalizację.',
            },
            status_code=409,
        )

    devices = await _devices_at(session, location.id)
    nav_locations = await list_locations(session)
    run = await latest_location_run(session, location.id)
    return templates.TemplateResponse(
        "locations/detail.html",
        {"request": request, "location": location, "devices": devices, "nav_locations": nav_locations, "run": run},
    )


@router.get("/{location_id}/fragment/update")
async def location_update_fragment(request: Request, location_id: str, session: AsyncSession = Depends(get_session)):
    location = await session.get(Location, _parse_uuid(location_id))
    if location is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono lokalizacji")
    require_location(request, location.id)
    run = await latest_location_run(session, location.id)
    return templates.TemplateResponse(
        "_location_update.html", {"request": request, "location": location, "run": run}
    )


@router.post("/{location_id}/update-all")
async def start_location_update(request: Request, location_id: str, session: AsyncSession = Depends(get_session)):
    location = await session.get(Location, _parse_uuid(location_id))
    if location is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono lokalizacji")
    require_operate_location(request, location.id)

    request.app.state.scheduler.add_job(
        run_location_update, args=[location.id], next_run_time=datetime.datetime.now()
    )
    return RedirectResponse(url=f"/locations/{location_id}", status_code=303)


@router.post("/{location_id}/delete")
async def delete_location(location_id: str, session: AsyncSession = Depends(get_session)):
    location = await session.get(Location, _parse_uuid(location_id))
    if location is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono lokalizacji")

    # Operatorzy przypisani do lokalizacji: odmawiamy zamiast odpinac. Operator bez
    # lokalizacji nie widzi niczego — konto dzialaloby, ale bylo bezuzyteczne, a nikt by
    # nie wiedzial dlaczego. Najpierw trzeba im wskazac inna lokalizacje.
    operators = (await session.execute(
        select(User.username).where(User.location_id == location.id))).scalars().all()
    if operators:
        return RedirectResponse(url=f"/locations/{location_id}?err=" + quote(
            f"Do tej lokalizacji są przypisani operatorzy: {', '.join(operators)}. "
            "Najpierw przypisz ich gdzie indziej (Ustawienia → Użytkownicy)."), status_code=303)

    # Urządzenia zostają, tylko tracą przypisanie do tej lokalizacji. Historia aktualizacji
    # tez zostaje — przebiegi traca tylko odnosnik do usuwanej lokalizacji. Wczesniej
    # klucz obcy z update_runs blokowal usuniecie kazdej lokalizacji, ktora miala za soba
    # choc jedna aktualizacje (wytkniete w recenzji zewnetrznej).
    await session.execute(update(Device).where(Device.location_id == location.id).values(location_id=None))
    await session.execute(update(UpdateRun).where(UpdateRun.location_id == location.id).values(location_id=None))
    await session.execute(delete(NotificationOverride).where(
        NotificationOverride.scope_type == "location", NotificationOverride.scope_id == location.id))
    await session.delete(location)
    await session.commit()
    return RedirectResponse(url="/locations", status_code=303)
