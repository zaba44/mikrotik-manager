"""Warstwa zdarzeń portalu — jedno wejście dla wszystkiego, co warto zgłosić mailem.

Świadomie NIE jest to dodatek do syslogu: syslog to tylko jedno ze źródeł. Pozostałe
(logowania do panelu, urządzenie offline, nieudana kopia, nieudana aktualizacja) wołają
tę samą funkcję `notify()`, więc limity i subskrypcje działają na wszystkie tak samo,
a dołożenie kolejnego źródła to jedna linijka w miejscu zdarzenia.

TRZY NIEZALEŻNE BEZPIECZNIKI (bo jeden nie wystarcza):
1. `notify_dedup_minutes` — to samo zdarzenie z tego samego źródła nie leci w kółko.
   Chroni przed migającym łączem, które generuje setki identycznych zgłoszeń.
2. `notify_max_per_device_hour` — sufit na jedno urządzenie. Chroni przed jednym
   zepsutym routerem, który zasypuje skrzynkę różnymi błędami.
3. `notify_max_total_hour` — sufit globalny. Chroni przed awarią zasilania w lokalizacji,
   gdzie naraz odzywa się kilkanaście urządzeń.
Wyciszone zdarzenia i tak lądują w dzienniku (ze statusem `suppressed` i powodem), więc
nic nie ginie po cichu — po prostu nie zamienia się w pocztę.
"""
import datetime
import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.timefmt import dt, utcnow
from app.mailer import send_mail
from app.models import Device, Notification, NotificationOverride
from app.settings_store import get_int_setting, get_setting

logger = logging.getLogger(__name__)

# Typy zdarzeń: klucz ustawienia -> (event_key, opis do panelu)
EVENT_TYPES = {
    "notify_syslog_error": ("syslog.error", "Błędy i zdarzenia krytyczne z urządzeń (syslog)"),
    "notify_syslog_warning": ("syslog.warning", "Ostrzeżenia z urządzeń (syslog)"),
    "notify_device_offline": ("device.offline", "Urządzenie przestało odpowiadać"),
    "notify_device_online": ("device.online", "Urządzenie wróciło"),
    "notify_portal_login": ("portal.login", "Logowanie do panelu (kto i kiedy)"),
    "notify_portal_login_failed": ("portal.login_failed", "Nieudane logowanie do panelu"),
    "notify_backup_failed": ("backup.failed", "Nieudana kopia zapasowa urządzenia"),
    "notify_update_failed": ("update.failed", "Nieudana aktualizacja urządzenia"),
}
_SETTING_BY_EVENT = {event: key for key, (event, _) in EVENT_TYPES.items()}


async def _override_for(session, scope_type: str, scope_id):
    if scope_id is None:
        return None
    return (await session.execute(
        select(NotificationOverride).where(
            NotificationOverride.scope_type == scope_type,
            NotificationOverride.scope_id == scope_id,
        )
    )).scalar_one_or_none()


def _override_applies(override) -> bool:
    """Wyciszenie z terminem samo wygasa — nie trzeba go sprzątać, wystarczy sprawdzić."""
    if override is None:
        return False
    if override.mode == "muted" and override.muted_until is not None:
        return utcnow() < override.muted_until  # muted_until zapisane w UTC (timefmt)
    return True


async def resolve_subscription(session, event_key: str, device=None, location_id=None) -> dict:
    """Czy dane zdarzenie ma być zgłoszone i NA JAKIEJ PODSTAWIE.

    Kolejność: urządzenie -> lokalizacja -> globalne, pierwszy jawny wpis wygrywa.
    Zwracamy też źródło decyzji, bo panel pokazuje użytkownikowi nie tylko „co",
    ale i „skąd" — przy kilkuset urządzeniach to jedyny sposób, żeby nie zgadywać."""
    loc_id = location_id if device is None else device.location_id

    for scope_type, scope_id, label in (
        ("device", getattr(device, "id", None), "urządzenia"),
        ("location", loc_id, "lokalizacji"),
    ):
        override = await _override_for(session, scope_type, scope_id)
        if not _override_applies(override):
            continue
        if override.mode == "muted":
            until = override.muted_until
            detail = f"do {dt(until)}" if until else "bezterminowo"
            return {"send": False, "source": f"wyciszenie {label} ({detail})"}
        allowed = {k.strip() for k in (override.event_keys or "").split(",") if k.strip()}
        return {
            "send": event_key in allowed,
            "source": f"własne ustawienia {label}",
        }

    setting_key = _SETTING_BY_EVENT.get(event_key)
    if setting_key and (await get_setting(session, setting_key)) != "1":
        return {"send": False, "source": "ustawienia globalne"}
    return {"send": True, "source": "ustawienia globalne"}


async def _log(session, *, event_key, dedup_key, device_id, subject, status, reason=None):
    session.add(Notification(
        event_key=event_key, dedup_key=dedup_key[:255], device_id=device_id,
        subject=subject[:255], status=status, reason=reason,
    ))
    await session.commit()


async def _blocked_reason(session, *, event_key, dedup_key, device_id) -> str | None:
    """Zwraca powód wyciszenia albo None, gdy można wysłać."""
    now = utcnow()  # created_at w bazie jest w UTC — czas lokalny przesuwal okna o 1–2 h

    dedup_minutes = await get_int_setting(session, "notify_dedup_minutes")
    if dedup_minutes > 0:
        since = now - datetime.timedelta(minutes=dedup_minutes)
        recent = (await session.execute(
            select(func.count(Notification.id)).where(
                Notification.dedup_key == dedup_key[:255],
                Notification.status == "sent",
                Notification.created_at >= since,
            )
        )).scalar_one()
        if recent:
            return f"powtórka w ciągu {dedup_minutes} min"

    hour_ago = now - datetime.timedelta(hours=1)
    if device_id is not None:
        per_device = await get_int_setting(session, "notify_max_per_device_hour")
        if per_device > 0:
            count = (await session.execute(
                select(func.count(Notification.id)).where(
                    Notification.device_id == device_id,
                    Notification.status == "sent",
                    Notification.created_at >= hour_ago,
                )
            )).scalar_one()
            if count >= per_device:
                return f"limit {per_device}/h dla tego urządzenia"

    total_cap = await get_int_setting(session, "notify_max_total_hour")
    if total_cap > 0:
        total = (await session.execute(
            select(func.count(Notification.id)).where(
                Notification.status == "sent", Notification.created_at >= hour_ago
            )
        )).scalar_one()
        if total >= total_cap:
            return f"globalny limit {total_cap}/h"
    return None


async def notify(
    session: AsyncSession, *, event_key: str, subject: str, body: str,
    dedup_key: str | None = None, device_id=None,
) -> dict:
    """Jedyne wejście do powiadomień. Nigdy nie rzuca wyjątkiem — zgłoszenie zdarzenia
    nie może wywrócić operacji, w trakcie której powstało (kopii, aktualizacji, logowania)."""
    try:
        if (await get_setting(session, "notify_enabled")) != "1":
            return {"ok": False, "status": "disabled"}

        device = await session.get(Device, device_id) if device_id else None
        decision = await resolve_subscription(session, event_key, device=device)
        if not decision["send"]:
            return {"ok": False, "status": "unsubscribed", "reason": decision["source"]}

        dedup = dedup_key or f"{event_key}:{device_id or '-'}"
        reason = await _blocked_reason(
            session, event_key=event_key, dedup_key=dedup, device_id=device_id
        )
        if reason:
            await _log(session, event_key=event_key, dedup_key=dedup, device_id=device_id,
                       subject=subject, status="suppressed", reason=reason)
            return {"ok": False, "status": "suppressed", "reason": reason}

        result = await send_mail(session, subject=subject, body=body)
        if result.get("ok"):
            await _log(session, event_key=event_key, dedup_key=dedup, device_id=device_id,
                       subject=subject, status="sent")
            return {"ok": True, "status": "sent"}
        await _log(session, event_key=event_key, dedup_key=dedup, device_id=device_id,
                   subject=subject, status="failed", reason=result.get("error"))
        return {"ok": False, "status": "failed", "reason": result.get("error")}
    except Exception as e:  # nigdy nie wywracamy operacji źródłowej
        logger.warning("Powiadomienie %s nie powiodło się: %s", event_key, e)
        return {"ok": False, "status": "error", "reason": str(e)}


async def recent_notifications(session: AsyncSession, limit: int = 50):
    return (await session.execute(
        select(Notification).order_by(Notification.created_at.desc()).limit(limit)
    )).scalars().all()


async def notification_stats(session: AsyncSession) -> dict:
    hour_ago = utcnow() - datetime.timedelta(hours=1)  # porownanie z created_at (UTC)
    day_ago = utcnow() - datetime.timedelta(days=1)

    async def count(*conditions):
        return (await session.execute(
            select(func.count(Notification.id)).where(*conditions)
        )).scalar_one()

    return {
        "sent_hour": await count(Notification.status == "sent", Notification.created_at >= hour_ago),
        "sent_day": await count(Notification.status == "sent", Notification.created_at >= day_ago),
        "suppressed_day": await count(
            Notification.status == "suppressed", Notification.created_at >= day_ago
        ),
        "failed_day": await count(
            Notification.status == "failed", Notification.created_at >= day_ago
        ),
    }


# ---- Zarządzanie nadpisaniami (panel) ----

MODES = ("default", "muted", "custom")


async def set_override(session, scope_type: str, scope_id, *, mode: str,
                       event_keys=None, muted_until=None) -> None:
    """`mode="default"` kasuje wpis — brak wiersza ZNACZY dziedziczenie, więc nie
    trzymamy pustych nadpisań, które tylko zaśmiecałyby zestawienie wyjątków."""
    existing = await _override_for(session, scope_type, scope_id)
    if mode == "default":
        if existing:
            await session.delete(existing)
            await session.commit()
        return
    if existing is None:
        existing = NotificationOverride(scope_type=scope_type, scope_id=scope_id, mode=mode)
        session.add(existing)
    existing.mode = mode
    existing.event_keys = ",".join(event_keys) if event_keys else None
    existing.muted_until = muted_until if mode == "muted" else None
    await session.commit()


async def list_overrides(session) -> list:
    return list((await session.execute(
        select(NotificationOverride).order_by(
            NotificationOverride.scope_type, NotificationOverride.created_at
        )
    )).scalars().all())


async def override_summary(session) -> dict:
    """Zestawienie wyjątków do panelu: nazwy zakresów, ile urządzeń dotyka wyciszona
    lokalizacja i które wyciszenia są BEZTERMINOWE (te są niebezpieczne — z terminem
    znikną same)."""
    from app.models import Location

    rows = []
    indefinite = 0
    for override in await list_overrides(session):
        if not _override_applies(override):
            continue  # wygasłe wyciszenie traktujemy jak brak
        if override.scope_type == "device":
            obj = await session.get(Device, override.scope_id)
            name, affected, url = (
                (obj.name, 1, f"/devices/{obj.id}") if obj else ("(usunięte)", 0, None)
            )
        else:
            obj = await session.get(Location, override.scope_id)
            affected = (await session.execute(
                select(func.count(Device.id)).where(Device.location_id == override.scope_id)
            )).scalar_one() if obj else 0
            name, url = (obj.name, f"/locations/{obj.id}") if obj else ("(usunięta)", None)

        forever = override.mode == "muted" and override.muted_until is None
        indefinite += 1 if forever else 0
        rows.append({
            "override": override, "name": name, "affected": affected,
            "url": url, "forever": forever,
            "events": [k.strip() for k in (override.event_keys or "").split(",") if k.strip()],
        })
    return {"rows": rows, "indefinite": indefinite}


async def scope_view(session, *, device=None, location=None) -> dict:
    """Wszystko, czego szablon potrzebuje, żeby pokazać stan I jego źródło.

    Etykieta dziedziczenia mówi PRAWDĘ: przy urządzeniu w lokalizacji z własnymi
    ustawieniami „domyślne" znaczy „jak w lokalizacji X", a nie „jak globalnie"."""
    from app.models import Location

    scope_type = "device" if device is not None else "location"
    scope_obj = device if device is not None else location
    override = await _override_for(session, scope_type, scope_obj.id)
    if not _override_applies(override):
        override = None

    inherit_label = "Jak globalnie"
    if device is not None and device.location_id:
        parent = await _override_for(session, "location", device.location_id)
        if _override_applies(parent):
            loc = await session.get(Location, device.location_id)
            inherit_label = f"Jak w lokalizacji {loc.name}" if loc else "Jak w lokalizacji"

    effective, source = [], ""
    for setting_key, (event, label) in EVENT_TYPES.items():
        decision = await resolve_subscription(
            session, event,
            device=device,
            location_id=None if device is not None else scope_obj.id,
        )
        source = decision["source"]
        if decision["send"]:
            effective.append(label)

    return {
        "ov": override,
        "scope_id": scope_obj.id,
        "inherit_label": inherit_label,
        "event_types": [(event, label) for _, (event, label) in EVENT_TYPES.items()],
        "selected_events": {k.strip() for k in (override.event_keys or "").split(",")} if override else set(),
        "effective": effective,
        "effective_source": source,
    }
