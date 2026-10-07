"""Wspólna obsługa formularza nadpisań — ten sam kształt dla urządzenia i lokalizacji,
więc trzymany w jednym miejscu zamiast duplikowany w dwóch routerach."""
import datetime

from app.notifications import set_override
from app.timefmt import utcnow


async def apply_scope_form(session, scope_type: str, scope_id, form) -> None:
    mode = form.get("mode") or "default"
    if mode == "muted":
        hours = int(form.get("mute_hours") or 0)
        # 0 = bezterminowo (NULL) — świadomy wybór, wyróżniany w zestawieniu i raporcie
        until = utcnow() + datetime.timedelta(hours=hours) if hours else None  # w bazie UTC
        await set_override(session, scope_type, scope_id, mode="muted", muted_until=until)
    elif mode == "custom":
        events = form.getlist("events") if hasattr(form, "getlist") else form.get("events", [])
        await set_override(session, scope_type, scope_id, mode="custom", event_keys=events)
    else:
        await set_override(session, scope_type, scope_id, mode="default")
