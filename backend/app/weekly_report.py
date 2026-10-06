"""Cotygodniowy raport stanu portalu.

Świadomie wysyłany NIEZALEŻNIE od tego, czy coś jest nie tak — jego wartość polega na
regularności, a „wszystko w porządku" to też informacja. Z tego samego powodu pomija
bezpieczniki antyspamowe (nie jest zdarzeniem, tylko cyklicznym podsumowaniem), ale
respektuje główny przełącznik powiadomień i własny checkbox.

Głównym powodem powstania było przypomnienie o BEZTERMINOWYCH wyciszeniach: lista
wyjątków w panelu działa tylko wtedy, gdy ktoś pamięta, żeby na nią zajrzeć — a problem
polega właśnie na tym, że się nie pamięta. Reszta statystyk dołożona, bo raz w tygodniu
i tak warto zobaczyć puls floty.
"""
import datetime
import logging

from sqlalchemy import func, select

from app.database import async_session
from app.mailer import send_mail
from app.models import Backup, Device, DeviceLogEntry, Notification
from app.notifications import override_summary
from app.settings_store import get_setting, set_setting

logger = logging.getLogger(__name__)

_LAST_RUN_KEY = "notify_weekly_report_last"


async def build_weekly_report(session) -> str:
    now = datetime.datetime.now()
    week = now - datetime.timedelta(days=7)
    lines = [
        "MikroTik Manager — raport tygodniowy",
        f"Wygenerowany: {now:%Y-%m-%d %H:%M}",
        "",
    ]

    # --- Wyciszenia bezterminowe: pierwotny powód istnienia tego raportu ---
    summary = await override_summary(session)
    forever = [r for r in summary["rows"] if r["forever"]]
    lines.append("== Wyciszenia bezterminowe ==")
    if forever:
        for row in forever:
            age = (now - row["override"].created_at).days
            scope = "lokalizacja" if row["override"].scope_type == "location" else "urządzenie"
            affected = f", dotyczy {row['affected']} urządzeń" if scope == "lokalizacja" else ""
            lines.append(f"  {scope} {row['name']} — od {age} dni{affected}")
        lines.append("  Te zakresy NIE wyślą żadnego powiadomienia, dopóki ich nie odciszysz.")
    else:
        lines.append("  Brak — nic nie jest wyciszone na stałe.")
    lines.append("")

    # --- Flota ---
    total = (await session.execute(select(func.count(Device.id)))).scalar_one()
    offline = (await session.execute(
        select(func.count(Device.id)).where(Device.api_reachable.is_(False))
    )).scalar_one()
    lines += ["== Flota ==", f"  Urządzeń: {total}, niedostępnych teraz: {offline}", ""]

    # --- Kopie zapasowe: cichy zabójca, potrafią nie działać miesiącami ---
    failed = (await session.execute(
        select(Device.name, func.count(Backup.id))
        .join(Backup, Backup.device_id == Device.id)
        .where(Backup.status != "success", Backup.created_at >= week)
        .group_by(Device.name)
    )).all()
    lines.append("== Kopie zapasowe (7 dni) ==")
    if failed:
        for name, count in failed:
            lines.append(f"  NIEUDANE: {name} — {count}")
    else:
        lines.append("  Bez błędów.")
    lines.append("")

    # --- Aktualizacje ---
    pending = (await session.execute(
        select(func.count(Device.id)).where(
            Device.available_routeros_version.is_not(None),
            Device.routeros_version.is_not(None),
        )
    )).scalar_one()
    lines += ["== Aktualizacje ==", f"  Urządzeń z odczytaną wersją: {pending}", ""]

    # --- Zdarzenia z syslogu ---
    events = (await session.execute(
        select(func.count(DeviceLogEntry.id)).where(
            DeviceLogEntry.received_at >= week,
            DeviceLogEntry.level.in_(("error", "critical", "warning")),
        )
    )).scalar_one()
    top = (await session.execute(
        select(Device.name, func.count(DeviceLogEntry.id).label("c"))
        .join(DeviceLogEntry, DeviceLogEntry.device_id == Device.id)
        .where(DeviceLogEntry.received_at >= week,
               DeviceLogEntry.level.in_(("error", "critical", "warning")))
        .group_by(Device.name).order_by(func.count(DeviceLogEntry.id).desc()).limit(3)
    )).all()
    lines.append("== Zdarzenia z urządzeń (7 dni) ==")
    lines.append(f"  Błędów i ostrzeżeń: {events}")
    for name, count in top:
        lines.append(f"    {name}: {count}")
    lines.append("")

    # --- Same powiadomienia: liczba wyciszonych jest DIAGNOSTYCZNA ---
    sent = (await session.execute(
        select(func.count(Notification.id)).where(
            Notification.status == "sent", Notification.created_at >= week)
    )).scalar_one()
    suppressed = (await session.execute(
        select(func.count(Notification.id)).where(
            Notification.status == "suppressed", Notification.created_at >= week)
    )).scalar_one()
    lines += [
        "== Powiadomienia (7 dni) ==",
        f"  Wysłane: {sent}, wyciszone przez limity: {suppressed}",
    ]
    if suppressed > sent and suppressed > 10:
        lines.append("  UWAGA: limity wycinają więcej niż przepuszczają — sprawdź progi "
                     "albo źródło, które się notorycznie odzywa.")
    return "\n".join(lines)


async def weekly_report_tick() -> None:
    """Poniedziałek rano. Znacznik ostatniej wysyłki w `settings`, więc restart backendu
    ani kilka ticków w tej samej godzinie nie zdublują raportu."""
    now = datetime.datetime.now()
    if now.weekday() != 0 or now.hour < 7:
        return
    async with async_session() as session:
        if (await get_setting(session, "notify_enabled")) != "1":
            return
        if (await get_setting(session, "notify_weekly_report")) != "1":
            return
        last = await get_setting(session, _LAST_RUN_KEY)
        if last and (now - datetime.datetime.fromisoformat(last)).days < 5:
            return

        body = await build_weekly_report(session)
        # force=True: raport nie jest zdarzeniem, więc nie podlega dedupowi ani limitom
        result = await send_mail(
            session, subject=f"[MTM] Raport tygodniowy — {now:%Y-%m-%d}", body=body, force=True
        )
        if result.get("ok"):
            await set_setting(session, _LAST_RUN_KEY, now.isoformat())
            logger.info("Raport tygodniowy wysłany")
        else:
            logger.warning("Raport tygodniowy nie poszedł: %s", result.get("error"))
