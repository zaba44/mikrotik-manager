import datetime
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, Response

from app.portal_backup import BackupError, export_portal, pending_restore, resume_pending_restore
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.admin_peer_service import build_admin_peer_config, create_admin_peer, delete_admin_peer
from app.auth import current_user, hash_password
from app.database import get_session
from app.certs import ca_pem, cert_info, install_uploaded, issue_server_cert
from app.filenames import content_disposition
from app.log_store import purge, syslog_stats
from app.mailer import (
    send_mail,
    clear_smtp_password,
    get_smtp_settings,
    save_smtp_settings,
    send_test_mail,
)
from app.models import AdminPeer, Device, NotificationOverride, User
from app.notifications import (
    EVENT_TYPES,
    notification_stats,
    override_summary,
    recent_notifications,
)
from app.queries import list_admin_peers, list_locations
from app.routeros_client import disable_syslog
from app.settings_store import get_backup_settings, get_setting, get_syslog_settings, set_setting
from app.templating import templates
from app.weekly_report import build_weekly_report

router = APIRouter(prefix="/settings")


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=404, detail="Nie znaleziono peera")


# ---- Zakładka: Kopie zapasowe ----

@router.get("")
async def settings_page(request: Request, session: AsyncSession = Depends(get_session)):
    backup_settings = await get_backup_settings(session)
    nav_locations = await list_locations(session)
    return templates.TemplateResponse(
        "settings.html",
        {"request": request, "backup_settings": backup_settings, "nav_locations": nav_locations,
         "restore_pending": pending_restore()},
    )


@router.post("/portal-restore/resume")
async def portal_restore_resume():
    """Ponowienie niedokonczonego odtwarzania od reki (harmonogram i tak robi to co minute)."""
    await resume_pending_restore()
    return RedirectResponse(url="/settings", status_code=303)


@router.post("")
async def update_settings(
    request: Request,
    backup_schedule_hours: str = Form(...),
    backup_retention_count: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    nav_locations = await list_locations(session)
    try:
        schedule_hours = max(1, int(backup_schedule_hours))
        retention_count = max(1, int(backup_retention_count))
    except ValueError:
        backup_settings = await get_backup_settings(session)
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "backup_settings": backup_settings,
                "nav_locations": nav_locations,
                "error": "Częstotliwość i retencja muszą być liczbami całkowitymi.",
            },
            status_code=400,
        )

    await set_setting(session, "backup_schedule_hours", str(schedule_hours))
    await set_setting(session, "backup_retention_count", str(retention_count))
    return RedirectResponse(url="/settings", status_code=303)


async def _render_syslog(request, session, *, notice=None, error=None, status_code=200):
    return templates.TemplateResponse(
        "settings_syslog.html",
        {
            "request": request,
            "syslog_settings": await get_syslog_settings(session),
            "stats": await syslog_stats(session),
            "nav_locations": await list_locations(session),
            "notice": notice,
            "error": error,
        },
        status_code=status_code,
    )


@router.get("/syslog")
async def syslog_page(request: Request, session: AsyncSession = Depends(get_session)):
    return await _render_syslog(request, session)


@router.post("/syslog")
async def update_syslog_settings(
    request: Request,
    syslog_enabled: str = Form(""),
    syslog_retention_days: str = Form(...),
    syslog_max_entries_per_device: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    try:
        days = max(0, int(syslog_retention_days))
        cap = max(0, int(syslog_max_entries_per_device))
    except ValueError:
        return await _render_syslog(
            request, session, error="Retencja i limit muszą być liczbami całkowitymi.",
            status_code=400,
        )
    await set_setting(session, "syslog_enabled", "1" if syslog_enabled else "0")
    await set_setting(session, "syslog_retention_days", str(days))
    await set_setting(session, "syslog_max_entries_per_device", str(cap))
    return RedirectResponse(url="/settings/syslog", status_code=303)


@router.post("/syslog/clear-entries")
async def clear_all_syslog_entries(request: Request, session: AsyncSession = Depends(get_session)):
    removed = await purge(session)
    return await _render_syslog(request, session, notice=f"Usunięto {removed} zapisanych wpisów.")


@router.post("/syslog/cleanup-devices")
async def cleanup_syslog_on_devices(request: Request, session: AsyncSession = Depends(get_session)):
    """Masowe zdjęcie konfiguracji z routerów — ŚWIADOMIE osobna, jawna akcja, a nie
    efekt uboczny wyłączenia globalnego przełącznika. Idzie po kolei (nie równolegle),
    urządzenia offline są pomijane i raportowane, żeby było wiadomo, co zostało."""
    devices = (await session.execute(
        select(Device).where(Device.syslog_enabled.is_(True)).order_by(Device.name)
    )).scalars().all()

    done, failed = 0, []
    for device in devices:
        result = await disable_syslog(device)
        if result.get("ok"):
            device.syslog_enabled = False
            device.syslog_info_enabled = False
            done += 1
        else:
            failed.append(device.name)
    await session.commit()

    notice = f"Zdjęto konfigurację z {done} urządzeń."
    if failed:
        notice += (f" Nie udało się na {len(failed)} (nieosiągalne przez API): "
                   f"{', '.join(failed[:8])}{'…' if len(failed) > 8 else ''}. "
                   "Zostają oznaczone jako podpięte — powtórz, gdy wrócą.")
    return await _render_syslog(request, session, notice=notice)


# ---- Zakładka: Certyfikat HTTPS ----

async def _suggested_addresses(session) -> str:
    """Podpowiedź adresów: te, pod którymi odpowiada PORTAL. Użytkownik i tak może dopisać —
    jeden certyfikat obejmuje wszystkie naraz (SubjectAlternativeName).

    Świadomie NIE podpowiadamy adresów peerów administracyjnych. To adresy maszyn
    administratorów w tunelu, a nie adresy, pod którymi odpowiada portal (ten stoi na
    adresie huba) — wpis taki jest bezużyteczny, puchnie z każdym administratorem, a przy
    okazji wylicza ich adresy każdemu, kto nawiąże połączenie TLS."""
    out = []
    for key in ("wg_hub_endpoint", "wg_server_ip"):
        value = (await get_setting(session, key) or "").strip()
        if value and value not in out:
            out.append(value)
    for extra in ("localhost", "127.0.0.1"):
        if extra not in out:
            out.append(extra)
    return ", ".join(out)


async def _render_cert(request, session, *, notice=None, error=None, status_code=200):
    return templates.TemplateResponse(
        "settings_cert.html",
        {
            "request": request,
            "info": cert_info(),
            "suggested": await _suggested_addresses(session),
            "nav_locations": await list_locations(session),
            "notice": notice,
            "error": error,
        },
        status_code=status_code,
    )


@router.get("/cert")
async def cert_page(request: Request, session: AsyncSession = Depends(get_session)):
    return await _render_cert(request, session)


@router.post("/cert/regenerate")
async def regenerate_cert(
    request: Request, addresses: str = Form(...), session: AsyncSession = Depends(get_session)
):
    items = [a.strip() for a in addresses.split(",") if a.strip()]
    if not items:
        return await _render_cert(request, session, error="Podaj co najmniej jeden adres.",
                                  status_code=400)
    try:
        issue_server_cert(items)
    except Exception as e:
        return await _render_cert(request, session, error=f"Nie udało się wygenerować: {e}",
                                  status_code=400)
    return await _render_cert(
        request, session,
        notice=f"Certyfikat wygenerowany dla: {', '.join(items)}. "
               "Przeładuj Caddy (instrukcja na dole strony), żeby zaczął go używać.",
    )


@router.post("/cert/upload")
async def upload_cert(
    request: Request,
    cert_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
):
    err = install_uploaded(await cert_file.read(), await key_file.read())
    if err:
        return await _render_cert(request, session, error=err, status_code=400)
    return await _render_cert(
        request, session,
        notice="Certyfikat podmieniony. Przeładuj Caddy (instrukcja na dole strony).",
    )


@router.get("/cert/ca.pem")
async def download_ca(session: AsyncSession = Depends(get_session)):
    pem = ca_pem()
    if pem is None:
        raise HTTPException(status_code=404, detail="Brak wbudowanego CA")
    return Response(
        content=pem, media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="mikrotik-manager-ca.pem"'},
    )


# ---- Zakładka: Poczta (SMTP) ----

async def _render_smtp(request, session, *, notice=None, error=None, status_code=200):
    return templates.TemplateResponse(
        "settings_smtp.html",
        {
            "request": request,
            "smtp": await get_smtp_settings(session),
            "nav_locations": await list_locations(session),
            "notice": notice,
            "error": error,
        },
        status_code=status_code,
    )


@router.get("/smtp")
async def smtp_page(request: Request, session: AsyncSession = Depends(get_session)):
    return await _render_smtp(request, session)


@router.post("/smtp")
async def update_smtp_settings(
    request: Request,
    smtp_enabled: str = Form(""),
    smtp_host: str = Form(""),
    smtp_port: str = Form("587"),
    smtp_security: str = Form("starttls"),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form(""),
    smtp_to: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    try:
        port = int(smtp_port)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        return await _render_smtp(request, session, error="Port musi być liczbą 1–65535.",
                                  status_code=400)
    if smtp_security not in ("none", "starttls", "ssl"):
        smtp_security = "starttls"

    await save_smtp_settings(
        session,
        {
            "smtp_enabled": "1" if smtp_enabled else "0",
            "smtp_host": smtp_host.strip(),
            "smtp_port": str(port),
            "smtp_security": smtp_security,
            "smtp_username": smtp_username.strip(),
            "smtp_from": smtp_from.strip(),
            "smtp_to": smtp_to.strip(),
        },
        smtp_password or None,  # puste = zostaw dotychczasowe hasło
    )
    return RedirectResponse(url="/settings/smtp", status_code=303)


@router.post("/smtp/test")
async def test_smtp(
    request: Request, to: str = Form(""), session: AsyncSession = Depends(get_session)
):
    recipients = [a.strip() for a in to.split(",") if a.strip()] or None
    result = await send_test_mail(session, recipients)
    if result.get("ok"):
        return await _render_smtp(
            request, session,
            notice=f"Wiadomość testowa wysłana do: {', '.join(result['recipients'])}.",
        )
    return await _render_smtp(request, session, error=f"Nie udało się wysłać: {result['error']}")


@router.post("/smtp/clear-password")
async def clear_smtp_password_route(request: Request, session: AsyncSession = Depends(get_session)):
    await clear_smtp_password(session)
    return await _render_smtp(request, session, notice="Hasło SMTP usunięte.")


# ---- Zakładka: Powiadomienia ----

_NOTIFY_LIMITS = ("notify_dedup_minutes", "notify_max_per_device_hour", "notify_max_total_hour")


async def _render_notifications(request, session, *, notice=None, error=None, status_code=200):
    keys = ["notify_enabled", "notify_weekly_report", *EVENT_TYPES.keys(), *_NOTIFY_LIMITS]
    cfg = {key: await get_setting(session, key) for key in keys}
    return templates.TemplateResponse(
        "settings_notifications.html",
        {
            "request": request,
            "cfg": cfg,
            "event_types": [(key, label) for key, (_, label) in EVENT_TYPES.items()],
            "stats": await notification_stats(session),
            "overrides": await override_summary(session),
            "recent": await recent_notifications(session),
            "smtp_ready": bool(await get_setting(session, "smtp_host")),
            "nav_locations": await list_locations(session),
            "notice": notice,
            "error": error,
        },
        status_code=status_code,
    )


@router.get("/notifications")
async def notifications_page(request: Request, session: AsyncSession = Depends(get_session)):
    return await _render_notifications(request, session)


@router.post("/notifications")
async def update_notifications(request: Request, session: AsyncSession = Depends(get_session)):
    """Checkboxy odczytujemy z surowego formularza — typów zdarzeń będzie przybywać,
    a wypisywanie ich jeden po drugim jako parametry zamieniłoby to w listę do
    zapomnienia przy każdym nowym źródle."""
    form = await request.form()
    await set_setting(session, "notify_enabled", "1" if form.get("notify_enabled") else "0")
    await set_setting(session, "notify_weekly_report",
                      "1" if form.get("notify_weekly_report") else "0")
    for key in EVENT_TYPES:
        await set_setting(session, key, "1" if form.get(key) else "0")
    for key in _NOTIFY_LIMITS:
        try:
            await set_setting(session, key, str(max(0, int(form.get(key) or 0))))
        except ValueError:
            return await _render_notifications(
                request, session, error="Bezpieczniki muszą być liczbami całkowitymi.",
                status_code=400,
            )
    return RedirectResponse(url="/settings/notifications", status_code=303)


@router.post("/notifications/send-report")
async def send_report_now(request: Request, session: AsyncSession = Depends(get_session)):
    """Wysyla raport od reki — bez czekania do poniedzialku. Pomija bezpieczniki
    i glowny przelacznik (jak wysylka testowa SMTP), zeby dalo sie zobaczyc, jak
    wyglada, zanim sie go wlaczy na stale."""
    body = await build_weekly_report(session)
    result = await send_mail(
        session,
        subject=f"[MTM] Raport tygodniowy (na zadanie) — {datetime.datetime.now():%Y-%m-%d}",
        body=body, force=True,
    )
    if result.get("ok"):
        return await _render_notifications(
            request, session,
            notice=f"Raport wyslany do: {', '.join(result['recipients'])}.",
        )
    return await _render_notifications(
        request, session, error=f"Nie udalo sie wyslac raportu: {result['error']}"
    )


@router.get("/notifications/preview-report", response_class=Response)
async def preview_report(request: Request, session: AsyncSession = Depends(get_session)):
    """Podglad tresci bez wysylania — przydatne, gdy SMTP jeszcze nie dziala."""
    body = await build_weekly_report(session)
    return Response(content=body.encode("utf-8"), media_type="text/plain; charset=utf-8")


@router.post("/notifications/override/{override_id}/delete")
async def delete_notification_override(
    request: Request, override_id: str, session: AsyncSession = Depends(get_session)
):
    """Przywrócenie domyślnych wprost z zestawienia — bez wchodzenia na stronę
    urządzenia czy lokalizacji. Przy kilkuset urządzeniach to różnica między
    „posprzątam to" a „kiedyś posprzątam"."""
    override = await session.get(NotificationOverride, _parse_uuid(override_id))
    if override is not None:
        await session.delete(override)
        await session.commit()
    return RedirectResponse(url="/settings/notifications", status_code=303)


@router.post("/portal-backup")
async def portal_backup_route(
    request: Request,
    include_device_backups: str = Form(""), include_logs: str = Form(""), include_history: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    try:
        data = await export_portal(bool(include_device_backups), bool(include_logs), bool(include_history))
    except BackupError as e:
        # Niekompletna kopia wyglada jak kompletna, a wychodzi na jaw dopiero przy awarii —
        # dlatego zamiast pliku komunikat.
        return templates.TemplateResponse(
            "settings.html",
            {"request": request, "backup_settings": await get_backup_settings(session),
             "nav_locations": await list_locations(session), "error": str(e)},
            status_code=503,
        )
    kind = "full" if include_device_backups else "config"
    if include_logs:
        kind += "-logs"
    if include_history:
        kind += "-history"
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Response(
        content=data,
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="mtm-portal-{kind}-{ts}.tar.gz"'},
    )


# ---- Zakładka: Peery administracyjne ----

async def _render_admin_peers(request, session, *, new_peer=None, new_config=None, error=None, status_code=200):
    peers = await list_admin_peers(session)
    nav_locations = await list_locations(session)
    return templates.TemplateResponse(
        "settings_admin_peers.html",
        {
            "request": request,
            "peers": peers,
            "nav_locations": nav_locations,
            "new_peer": new_peer,
            "new_config": new_config,
            "error": error,
        },
        status_code=status_code,
    )


@router.get("/admin-peers")
async def admin_peers_page(request: Request, session: AsyncSession = Depends(get_session)):
    return await _render_admin_peers(request, session)


@router.post("/admin-peers")
async def create_admin_peer_route(
    request: Request, name: str = Form(...), session: AsyncSession = Depends(get_session)
):
    if not name.strip():
        return await _render_admin_peers(request, session, error="Podaj nazwę peera.", status_code=400)
    try:
        peer, warning = await create_admin_peer(session, name)
    except IntegrityError:
        await session.rollback()
        return await _render_admin_peers(
            request, session, error=f'Peer o nazwie "{name.strip()}" już istnieje.', status_code=409
        )
    config = build_admin_peer_config(peer)
    return await _render_admin_peers(request, session, new_peer=peer, new_config=config, error=warning)


@router.get("/admin-peers/{peer_id}/config")
async def download_admin_peer_config(peer_id: str, session: AsyncSession = Depends(get_session)):
    peer = await session.get(AdminPeer, _parse_uuid(peer_id))
    if peer is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono peera")
    config = build_admin_peer_config(peer)
    return Response(
        content=config,
        media_type="text/plain",
        headers={"Content-Disposition": content_disposition(f"wg-{peer.name}.conf")},
    )


@router.post("/admin-peers/{peer_id}/delete")
async def delete_admin_peer_route(request: Request, peer_id: str, session: AsyncSession = Depends(get_session)):
    peer = await session.get(AdminPeer, _parse_uuid(peer_id))
    if peer is not None:
        ok, error = await delete_admin_peer(session, peer)
        if not ok:
            return await _render_admin_peers(
                request, session, status_code=503,
                error=(f"Kanał sterujący WireGuard nie odpowiada ({error}). Peer {peer.name} NIE został "
                       "usunięty — dostęp nadal działa. Spróbuj ponownie za chwilę."))
    return RedirectResponse(url="/settings/admin-peers", status_code=303)


# ---- Zakładka: Użytkownicy ----

async def _render_users(request, session, *, error=None, status_code=200):
    users = list(
        (
            await session.execute(
                select(User).options(selectinload(User.location)).order_by(User.username)
            )
        )
        .scalars()
        .all()
    )
    locations = await list_locations(session)
    return templates.TemplateResponse(
        "settings_users.html",
        {"request": request, "users": users, "locations": locations, "error": error},
        status_code=status_code,
    )


@router.get("/users")
async def users_page(request: Request, session: AsyncSession = Depends(get_session)):
    return await _render_users(request, session)


@router.post("/users")
async def create_user_route(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    location_id: str = Form(""),
    status_only: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    if role not in ("admin", "operator"):
        return await _render_users(request, session, error="Nieprawidłowa rola.", status_code=400)
    if not username.strip() or not password:
        return await _render_users(request, session, error="Podaj login i hasło.", status_code=400)

    user = User(
        username=username.strip(),
        password_hash=hash_password(password),
        role=role,
        # Checkbox „Tylko statusy" (domyślnie zaznaczony) dotyczy operatorów; dla admina
        # nieistotny (admin i tak operuje w pełni), więc zapisujemy False.
        status_only=bool(status_only) if role == "operator" else False,
        location_id=(location_id or None) if role == "operator" else None,
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        return await _render_users(
            request, session, error=f'Użytkownik "{username.strip()}" już istnieje.', status_code=409
        )
    return RedirectResponse(url="/settings/users", status_code=303)


@router.post("/users/{user_id}/toggle-status-only")
async def toggle_status_only_route(user_id: str, session: AsyncSession = Depends(get_session)):
    target = await session.get(User, _parse_uuid(user_id))
    # Flaga ma sens tylko dla operatorów — dla admina nic nie zmienia, więc no-op.
    if target is not None and target.role == "operator":
        target.status_only = not target.status_only
        await session.commit()
    return RedirectResponse(url="/settings/users", status_code=303)


@router.post("/users/{user_id}/password")
async def set_user_password_route(
    request: Request,
    user_id: str,
    new_password: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    target = await session.get(User, _parse_uuid(user_id))
    if target is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono użytkownika")
    if not new_password:
        return await _render_users(request, session, error="Podaj nowe hasło.", status_code=400)
    target.password_hash = hash_password(new_password)
    await session.commit()
    return RedirectResponse(url="/settings/users", status_code=303)


@router.post("/users/{user_id}/delete")
async def delete_user_route(request: Request, user_id: str, session: AsyncSession = Depends(get_session)):
    target = await session.get(User, _parse_uuid(user_id))
    if target is None:
        return RedirectResponse(url="/settings/users", status_code=303)
    # Nie pozwól usunąć samego siebie (ochrona przed wylogowaniem/utratą admina).
    if target.id == current_user(request).id:
        return await _render_users(
            request, session, error="Nie możesz usunąć własnego konta.", status_code=400
        )
    await session.delete(target)
    await session.commit()
    return RedirectResponse(url="/settings/users", status_code=303)
