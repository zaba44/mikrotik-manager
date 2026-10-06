from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import current_user, is_admin
from app.database import get_session
from app.models import Device, Location
from app.queries import list_locations
from app.templating import templates

router = APIRouter()


@router.get("/")
async def dashboard(request: Request, session: AsyncSession = Depends(get_session)):
    user = current_user(request)

    query = select(Device).options(selectinload(Device.location)).order_by(Device.name)
    if not is_admin(user):
        query = query.where(Device.location_id == user.location_id)
    devices = (await session.execute(query)).scalars().all()

    if is_admin(user):
        locations = await list_locations(session)
    else:
        loc = await session.get(Location, user.location_id) if user.location_id else None
        locations = [loc] if loc else []

    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "devices": devices, "locations": locations, "nav_locations": locations},
    )
