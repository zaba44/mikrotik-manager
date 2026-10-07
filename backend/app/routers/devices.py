import datetime
import os
import uuid
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import can_operate, is_admin, require_admin, require_location, require_operate_location
from app.backup_service import backup_device
from app.config import settings
from app.database import async_session, get_session
from app import local_address
from app.log_report import build_report, content_disposition
from app.log_store import purge
from app.models import (AdminPeer, Backup, Device, DeviceLogEntry, NotificationOverride, PingTarget,
                        PoeLockedPort, UpdateRun, UpdateRunStep)
from app.notifications import scope_view
from app.notify_forms import apply_scope_form as _apply_scope_form
from app.queries import latest_device_run, list_device_backups, list_locations, list_ping_targets
from app.routeros_client import (
    check_for_updates,
    configure_syslog,
    disable_syslog,
    get_device_health,
    get_dhcp_leases,
    get_poe,
    get_routerboard_info,
    poe_power_cycle,
    ping_from_device,
    reboot,
    set_poe_out,
)
from app.settings_store import get_setting
from app.security import (
    allocate_ip,
    decrypt,
    encrypt,
    generate_api_password,
    generate_preshared_key,
    generate_wg_keypair,
)
from app.templating import templates
from app.update_orchestrator import run_device_update
from app.syslog_receiver import invalidate_device_map
from app.wg_agent_client import add_peer, hub_peers_lock, remove_peer
from app.wg_config import wg

router = APIRouter(prefix="/devices")

# Dowolny lokalny port po stronie klienta (MikroTik łączy się wychodząco, port nie
# musi być routowalny z zewnątrz).
CLIENT_LISTEN_PORT = 13231


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")


def ros_quote(value: str) -> str:
    """Tekst bezpieczny wewnatrz "..." w skrypcie RouterOS. Specjalne sa tam nie tylko
    cudzyslow i backslash, ale tez `$` (podstawianie zmiennych) i `?` (w terminalu Winboksa wywoluje
    pomoc zamiast wpisac znak). Nazwy nadaje uzytkownik — `Biuro "Parter"` psulo caly
    skrypt (wytkniete w recenzji zewnetrznej). Znaki konca linii zamieniamy na spacje:
    w komentarzu i tak nie maja sensu, a urwalyby polecenie w pol."""
    out = str(value or "")
    for ch in ("\\", '"', "$", "?"):
        out = out.replace(ch, "\\" + ch)
    return " ".join(out.split())


def build_routeros_script(
    *, device_name: str, client_private_key: str, device_ip: str, api_username: str,
    api_password: str, preshared_key: str = "",
) -> str:
    wg_mask = wg.mask
    psk_arg = f' preshared-key="{preshared_key}"' if preshared_key else ""
    return f"""/interface wireguard add name=wg-mt listen-port={CLIENT_LISTEN_PORT} private-key="{client_private_key}"
/ip address add address={device_ip}/{wg_mask} interface=wg-mt
/interface wireguard peers add interface=wg-mt name=mtm-hub public-key="{wg.server_public_key}"{psk_arg} \\
    endpoint-address={wg.hub_endpoint} endpoint-port={settings.wg_port} \\
    allowed-address={wg.subnet} persistent-keepalive=25s comment="{ros_quote(device_name)} - hub"

/user group add name=mtm-api policy=read,write,test,sensitive,api,rest-api,reboot,policy
/user add name={api_username} password="{api_password}" group=mtm-api address={wg.server_ip}/32

/ip firewall filter add chain=input protocol=icmp src-address={wg.server_ip}/32 \\
    in-interface=wg-mt action=accept place-before=0 comment="MTM: ping z huba"
/ip firewall filter add chain=input protocol=tcp dst-port=443 src-address={wg.server_ip}/32 \\
    in-interface=wg-mt action=accept place-before=0 comment="MTM: REST API z huba"

/certificate add name=mtm-cert common-name={device_ip} days-valid=3650
/certificate sign mtm-cert; :delay 3s; /ip service set www-ssl address={wg.server_ip}/32 certificate=mtm-cert disabled=no
"""
# Certyfikat i usluga HTTPS: dwie pulapki, obie z pierwszej instalacji produkcyjnej (2026-10-07).
#  1. `/ip service set www-ssl certificate=` przyjmuje tylko certyfikat PODPISANY — gdy `sign`
#     stal na koncu skryptu, RouterOS odrzucal usluge („input does not match any value of
#     certificate"): tunel wstawal, REST zostawal niedostepny.
#  2. `/certificate sign` w terminalu wyswietla postep i POLYKA reszte wklejonego tekstu —
#     gdy podpis przeniesiono wyzej, przepadly wszystkie linie po nim (usluga i reguly
#     firewalla; potwierdzone na switchu CRS).
# Dlatego podpis i usluga sa JEDNA, OSTATNIA linia (polecenia rozdzielone `;` sa czescia tej
# samej linii wejscia, wiec terminal nie ma czego polknac), a reguly firewalla ida wczesniej.
# `:delay` na wypadek, gdy podpis konczy sie chwile po powrocie polecenia.


WINBOX_ADDRESS_LIST = "mtm-admin"


def build_winbox_rule_script(device: Device, peers: list) -> str:
    """Gotowy do skopiowania fragment configu, który otwiera Winbox tego routera dla
    komputerów administracyjnych (peery WG admina), przez tunel.

    Portal NICZEGO tu nie wysyła na router — użytkownik wkleja sam i sam ustawia regułę
    w odpowiednim miejscu łańcucha. Świadomie BEZ `place-before=`: przy generatorze
    rejestracji wstawiamy reguły na górę, ale firewalle w terenie są różne i kolejność
    jest decyzją administratora."""
    port = device.routeros_winbox_port or "8291"
    port_note = "" if device.routeros_winbox_port else (
        "# UWAGA: portal nie zna jeszcze portu Winbox tego routera (nie odpytano go przez API),\n"
        "# poniżej wstawiono domyślny 8291 — sprawdź i popraw, jeśli masz inny.\n"
    )
    entries = "\n".join(
        f'/ip firewall address-list add list={WINBOX_ADDRESS_LIST} address={p.wg_ip} '
        f'comment="MTM admin: {ros_quote(p.name)}"'
        for p in peers
    )
    return f"""{port_note}# 1) Adresy komputerów administracyjnych (peery WG portalu)
{entries}

# 2) Reguła wpuszczająca Winbox z tej listy, wyłącznie przez tunel
/ip firewall filter add chain=input protocol=tcp dst-port={port} \\
    src-address-list={WINBOX_ADDRESS_LIST} in-interface=wg-mt action=accept \\
    comment="MTM: Winbox dla adminow"
"""


def build_removal_script() -> str:
    # Reguły logowania zdejmujemy PRZED akcją — akcja z podpiętą regułą się nie usunie.
    return """/system logging remove [find action="mtmsyslog"]
/system logging action remove [find name="mtmsyslog"]
/ip firewall filter remove [find comment~"MTM:"]
/ip route remove [find comment~"MTM:"]
/ip service set www-ssl address="" certificate=none
/certificate remove [find name=mtm-cert]
/user remove [find name=mtm-api]
/user group remove [find name=mtm-api]
/interface wireguard peers remove [find interface=wg-mt]
/ip address remove [find interface=wg-mt]
/interface wireguard remove [find name=wg-mt]
"""


def script_for_device(device: Device) -> str:
    return build_routeros_script(
        device_name=device.name,
        client_private_key=decrypt(device.wg_private_key_encrypted),
        device_ip=str(device.wg_ip),
        api_username=device.api_username or "",
        api_password=decrypt(device.api_password_encrypted) if device.api_password_encrypted else "",
        preshared_key=decrypt(device.wg_preshared_key_encrypted) if device.wg_preshared_key_encrypted else "",
    )


@router.get("/new")
async def new_device_form(
    request: Request, location_id: str = "", session: AsyncSession = Depends(get_session)
):
    # Rejestracja to zapis tylko dla admina (middleware), wiec formularz tez: inaczej
    # operator widzial tu nazwy WSZYSTKICH lokalizacji, nie tylko swojej.
    require_admin(request)
    locations = await list_locations(session)
    return templates.TemplateResponse(
        "devices/new.html",
        {"request": request, "locations": locations, "nav_locations": locations, "selected_location_id": location_id},
    )


@router.post("")
async def create_device(
    request: Request,
    name: str = Form(...),
    location_id: str = Form(""),
    notes: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    device_ip = await allocate_ip(session)
    client_private_key, client_public_key = generate_wg_keypair()
    preshared_key = generate_preshared_key()
    api_username = "mtm-api"
    api_password = generate_api_password()

    device = Device(
        name=name.strip(),
        location_id=location_id or None,
        wg_public_key=client_public_key,
        wg_private_key_encrypted=encrypt(client_private_key),
        wg_preshared_key_encrypted=encrypt(preshared_key),
        wg_ip=device_ip,
        api_username=api_username,
        api_password_encrypted=encrypt(api_password),
        notes=notes.strip() or None,
    )
    session.add(device)

    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        locations = await list_locations(session)
        return templates.TemplateResponse(
            "devices/new.html",
            {
                "request": request,
                "locations": locations,
                "nav_locations": locations,
                "selected_location_id": location_id,
                "error": f'Nie udało się zarejestrować "{name.strip()}" — nazwa jest już zajęta '
                "(albo wystąpił rzadki konflikt przydziału IP). Spróbuj ponownie.",
                "prefill_name": name,
                "prefill_notes": notes,
            },
            status_code=409,
        )

    await session.refresh(device)
    invalidate_device_map()

    peer_added, peer_error = await add_peer(device.wg_public_key, str(device.wg_ip), preshared_key)

    script = script_for_device(device)
    locations = await list_locations(session)

    context = {
        "request": request,
        "device": device,
        "script": script,
        "just_created": True,
        "locations": locations,
        "nav_locations": locations,
        "removal_script": build_removal_script(),
        "run": None,
        "backups": [],
    }
    if not peer_added:
        context["peer_warning"] = (
            f"Automatyczne dodanie peera po stronie serwera nie powiodło się ({peer_error}). "
            "Skrypt poniżej i tak trzeba wkleić na routerze — dodaj peera ręcznie na serwerze: "
            f'docker compose exec wireguard wg set wg-mt peer {device.wg_public_key} '
            f"allowed-ips {device.wg_ip}/32"
        )
    return templates.TemplateResponse("devices/detail.html", context)


@router.get("/{device_id}")
async def device_detail(request: Request, device_id: str, err: str = "",
                        session: AsyncSession = Depends(get_session)):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_location(request, device.location_id)

    script = script_for_device(device)
    locations = await list_locations(session)
    run = await latest_device_run(session, device.id)
    backups = await list_device_backups(session, device.id)
    ping_targets = await list_ping_targets(session, device.id)
    return templates.TemplateResponse(
        "devices/detail.html",
        {
            "request": request,
            "device": device,
            "script": script,
            "just_created": False,
            "locations": locations,
            "nav_locations": locations,
            "removal_script": build_removal_script(),
            "run": run,
            "backups": backups,
            "ping_targets": ping_targets,
            "peer_warning": err or None,
        },
    )


@router.get("/{device_id}/fragment/health")
async def device_health_fragment(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_location(request, device.location_id)
    # Zwolnij połączenie DB przed długim REST-em: dziesiątki równoczesnych żądań
    # czekających na semafor urządzenia wyczerpywały pulę SQLAlchemy (500-tki).
    await session.close()
    # Interfejsy maja wlasna sekcje, wiec kondycja ich nie pobiera — to trzy zapytania
    # mniej na urzadzenie, w tym kosztowny monitor wszystkich portow.
    health = await get_device_health(device, with_interfaces=False)
    return templates.TemplateResponse("_device_health.html", {"request": request, "device": device, "h": health})


@router.get("/{device_id}/fragment/interfaces")
async def device_interfaces_fragment(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_location(request, device.location_id)
    await session.close()  # jw. — nie trzymaj połączenia DB przez czas odczytu REST
    health = await get_device_health(device)
    return templates.TemplateResponse("_device_interfaces.html", {"request": request, "device": device, "h": health})


@router.get("/{device_id}/log-report")
async def device_log_report(
    request: Request, device_id: str, session: AsyncSession = Depends(get_session)
):
    """Pobiera ostrzeżenia/błędy z bufora routera i oddaje plik. Nie wymaga włączonego
    syslogu, niczego nie zapisuje i nie zmienia konfiguracji urządzenia."""
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_location(request, device.location_id)
    await session.close()  # odczyt bufora bywa wolny — nie trzymaj połączenia DB

    text = await build_report([device], scope_name=device.name)
    return Response(
        content=text.encode("utf-8"),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": content_disposition(device.name)},
    )


@router.post("/{device_id}/syslog")
async def toggle_syslog(
    request: Request,
    device_id: str,
    enable: str = Form(...),
    include_info: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    """Podpina/odpina urządzenie od syslogu — konfiguruje ROUTER przez API.
    Świadomie automatycznie (inaczej niż reguła Winbox): wpisy logowania nie mają
    kolejności w łańcuchu, więc nie da się nimi niczego przestawić, a przy 200–300
    urządzeniach ręczne wklejanie przestaje być przełącznikiem."""
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    user = request.state.user
    if not user or user.role != "admin":
        raise HTTPException(status_code=403, detail="Tylko administrator")

    globally_on = (await get_setting(session, "syslog_enabled")) == "1"
    want_on = enable == "1"
    want_info = bool(include_info)
    if want_on and not globally_on:
        # Gate: bez globalnego przelacznika nie ma sensu konfigurowac routera —
        # odbiornik i tak odrzucalby jego wpisy.
        return templates.TemplateResponse(
            "_device_syslog.html",
            {"request": request, "device": device, "entries": None, "globally_on": False,
             "result": {"ok": False, "error": "Odbiór zdarzeń jest wyłączony globalnie "
                        "— włącz go w Ustawieniach → Syslog."}},
        )
    if want_on:
        result = await configure_syslog(
            device, hub_ip=wg.server_ip, port=settings.syslog_port, include_info=want_info
        )
    else:
        result = await disable_syslog(device)

    if result.get("ok"):
        device.syslog_enabled = want_on
        device.syslog_info_enabled = want_on and want_info
        await session.commit()
        await session.refresh(device)

    return templates.TemplateResponse(
        "_device_syslog.html",
        {"request": request, "device": device, "result": result, "entries": None,
         "globally_on": globally_on},
    )


@router.post("/{device_id}/syslog/clear")
async def clear_device_syslog(
    request: Request, device_id: str, session: AsyncSession = Depends(get_session)
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    user = request.state.user
    if not user or user.role != "admin":
        raise HTTPException(status_code=403, detail="Tylko administrator")
    removed = await purge(session, device_id=device.id)
    return templates.TemplateResponse(
        "_device_syslog.html",
        {"request": request, "device": device, "result": None, "entries": [],
         "cleared": removed, "globally_on": (await get_setting(session, "syslog_enabled")) == "1"},
    )


@router.get("/{device_id}/fragment/notifications")
async def device_notifications_fragment(
    request: Request, device_id: str, session: AsyncSession = Depends(get_session)
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urzadzenia")
    require_location(request, device.location_id)
    ctx = await scope_view(session, device=device)
    return templates.TemplateResponse(
        "_notify_scope.html",
        {"request": request, "scope_url": f"/devices/{device.id}", **ctx},
    )


@router.post("/{device_id}/notifications")
async def set_device_notifications(
    request: Request, device_id: str, session: AsyncSession = Depends(get_session)
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urzadzenia")
    user = request.state.user
    if not user or user.role != "admin":
        raise HTTPException(status_code=403, detail="Tylko administrator")
    form = await request.form()
    await _apply_scope_form(session, "device", device.id, form)
    ctx = await scope_view(session, device=device)
    return templates.TemplateResponse(
        "_notify_scope.html",
        {"request": request, "scope_url": f"/devices/{device.id}", **ctx},
    )


@router.get("/{device_id}/fragment/syslog")
async def device_syslog_fragment(
    request: Request, device_id: str, session: AsyncSession = Depends(get_session)
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_location(request, device.location_id)
    entries = (await session.execute(
        select(DeviceLogEntry)
        .where(DeviceLogEntry.device_id == device.id)
        .order_by(DeviceLogEntry.received_at.desc())
        .limit(200)
    )).scalars().all()
    return templates.TemplateResponse(
        "_device_syslog.html",
        {
            "request": request, "device": device, "result": None, "entries": entries,
            "globally_on": (await get_setting(session, "syslog_enabled")) == "1",
        },
    )


@router.get("/{device_id}/fragment/winbox-rule")
async def device_winbox_rule_fragment(
    request: Request, device_id: str, session: AsyncSession = Depends(get_session)
):
    """Gotowa reguła firewalla otwierająca Winbox dla peerów admina — do skopiowania
    i wklejenia ręcznie. Admin-only, bo to element konfiguracji routera."""
    user = request.state.user
    if not user or user.role != "admin":
        raise HTTPException(status_code=403, detail="Tylko administrator")
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    peers = (await session.execute(select(AdminPeer).order_by(AdminPeer.name))).scalars().all()
    return templates.TemplateResponse(
        "_device_winbox_rule.html",
        {
            "request": request,
            "device": device,
            "peers": peers,
            "script": build_winbox_rule_script(device, peers) if peers else "",
        },
    )


@router.get("/{device_id}/fragment/leases")
async def device_leases_fragment(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_location(request, device.location_id)
    await session.close()  # jw. — nie trzymaj połączenia DB przez czas odczytu REST
    result = await get_dhcp_leases(device)
    return templates.TemplateResponse("_device_leases.html", {"request": request, "device": device, "r": result})


@router.get("/{device_id}/fragment/addresses")
async def device_addresses_fragment(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_location(request, device.location_id)
    can_pin = can_operate(request.state.user)
    await session.close()  # jw. — nie trzymaj połączenia DB przez czas odczytu REST
    result = await local_address.refresh(device)
    return templates.TemplateResponse(
        "_device_addresses.html",
        {"request": request, "device": device, "r": result, "can_pin": can_pin},
    )


@router.post("/{device_id}/addresses/pin")
async def pin_local_address(
    request: Request,
    device_id: str,
    interface: str = Form(...),
    address: str = Form(...),
    dynamic: str = Form("0"),
    session: AsyncSession = Depends(get_session),
):
    """Wskazanie adresu głównego. Zapisujemy też, czy adres jest dynamiczny — od tego
    zależy, jak go potem śledzimy (po interfejsie kontra po parze interfejs+adres)."""
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_operate_location(request, device.location_id)
    device.local_addr_interface = interface
    device.local_addr_value = address
    device.local_addr_dynamic = dynamic == "1"
    device.local_addr_note = None
    await session.commit()
    return await device_addresses_fragment(request, device_id, session)


@router.post("/{device_id}/addresses/unpin")
async def unpin_local_address(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_operate_location(request, device.location_id)
    device.local_addr_interface = None
    device.local_addr_value = None
    device.local_addr_dynamic = False
    device.local_addr_note = None
    await session.commit()
    return await device_addresses_fragment(request, device_id, session)


# ---- PoE ----

async def _poe_view(request: Request, device: Device, *, notice=None, error=None):
    """Odczyt PoE + blokady uplinku. Wlasna sesja, bo wolajacy zamyka swoja przed REST-em."""
    result = await get_poe(device)
    locks: dict[str, str | None] = {}
    async with async_session() as s:
        rows = (await s.execute(
            select(PoeLockedPort).where(PoeLockedPort.device_id == device.id)
        )).scalars().all()
        locks = {r.interface: r.note for r in rows}
        if result.get("ok"):
            count = len(result["rows"]) if result.get("supported") else 0
            fresh = await s.get(Device, device.id)
            if fresh is not None and fresh.poe_port_count != count:
                fresh.poe_port_count = count
                await s.commit()
    return templates.TemplateResponse(
        "_device_poe.html",
        {"request": request, "device": device, "r": result, "locks": locks,
         "can_operate": can_operate(request.state.user), "is_admin": is_admin(request.state.user),
         "notice": notice, "error": error},
    )


async def _poe_device(request: Request, device_id: str, session: AsyncSession, *, operate: bool) -> Device:
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    if operate:
        require_operate_location(request, device.location_id)
    else:
        require_location(request, device.location_id)
    return device


async def _poe_locked(device: Device, interface: str) -> bool:
    async with async_session() as s:
        return (await s.execute(
            select(PoeLockedPort).where(PoeLockedPort.device_id == device.id,
                                        PoeLockedPort.interface == interface)
        )).scalars().first() is not None


@router.get("/{device_id}/fragment/poe")
async def device_poe_fragment(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await _poe_device(request, device_id, session, operate=False)
    await session.close()  # jw. — nie trzymaj połączenia DB przez czas odczytu REST
    return await _poe_view(request, device)


@router.post("/{device_id}/poe/set")
async def device_poe_set(
    request: Request,
    device_id: str,
    port_id: str = Form(...),
    interface: str = Form(...),
    value: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    device = await _poe_device(request, device_id, session, operate=True)
    await session.close()
    # Blokada uplinku egzekwowana PO STRONIE SERWERA. Wyszarzony przycisk chroni przed
    # pomylka, ale nie przed powtorzeniem żądania — a stawka jest odciecie zasilania
    # urzadzeniu, przez ktore sie tu weszlo.
    if await _poe_locked(device, interface):
        return await _poe_view(request, device,
                               error=f"Port {interface} jest oznaczony jako uplink — sterowanie zablokowane.")
    res = await set_poe_out(device, port_id, value)
    if not res["ok"]:
        return await _poe_view(request, device, error=f"Nie udało się przestawić {interface}: {res['error']}")
    return await _poe_view(request, device, notice=f"Port {interface}: zasilanie ustawione na {value}.")


@router.post("/{device_id}/poe/cycle")
async def device_poe_cycle(
    request: Request,
    device_id: str,
    interface: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    device = await _poe_device(request, device_id, session, operate=True)
    await session.close()
    if await _poe_locked(device, interface):
        return await _poe_view(request, device,
                               error=f"Port {interface} jest oznaczony jako uplink — restart zablokowany.")
    res = await poe_power_cycle(device, interface)
    if not res["ok"]:
        return await _poe_view(request, device, error=f"Restart {interface} nie powiódł się: {res['error']}")
    return await _poe_view(request, device,
                           notice=f"Port {interface}: zasilanie odcięte na 5 s — urządzenie wstaje.")


@router.post("/{device_id}/poe/lock")
async def device_poe_lock(
    request: Request,
    device_id: str,
    interface: str = Form(...),
    note: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    device = await _poe_device(request, device_id, session, operate=True)
    if not await _poe_locked(device, interface):
        session.add(PoeLockedPort(device_id=device.id, interface=interface, note=note.strip() or None))
        await session.commit()
    await session.close()
    return await _poe_view(request, device, notice=f"Port {interface} oznaczony jako uplink.")


@router.post("/{device_id}/poe/unlock")
async def device_poe_unlock(
    request: Request,
    device_id: str,
    interface: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    device = await _poe_device(request, device_id, session, operate=True)
    await session.execute(delete(PoeLockedPort).where(
        PoeLockedPort.device_id == device.id, PoeLockedPort.interface == interface))
    await session.commit()
    await session.close()
    return await _poe_view(request, device, notice=f"Port {interface}: blokada uplinku zdjęta.")


@router.get("/{device_id}/fragment/updates")
async def device_updates_fragment(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_location(request, device.location_id)
    run = await latest_device_run(session, device.id)
    return templates.TemplateResponse("_device_updates.html", {"request": request, "device": device, "run": run})


@router.get("/{device_id}/fragment/backups")
async def device_backups_fragment(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_location(request, device.location_id)
    backups = await list_device_backups(session, device.id)
    return templates.TemplateResponse("_device_backups.html", {"request": request, "device": device, "backups": backups})


@router.post("/{device_id}/edit")
async def edit_device(
    request: Request,
    device_id: str,
    name: str = Form(...),
    location_id: str = Form(""),
    notes: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")

    device.name = name.strip()
    device.location_id = location_id or None
    device.notes = notes.strip() or None

    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        await session.refresh(device)
        script = script_for_device(device)
        locations = await list_locations(session)
        run = await latest_device_run(session, device.id)
        backups = await list_device_backups(session, device.id)
        return templates.TemplateResponse(
            "devices/detail.html",
            {
                "request": request,
                "device": device,
                "script": script,
                "just_created": False,
                "locations": locations,
                "nav_locations": locations,
                "removal_script": build_removal_script(),
                "run": run,
                "backups": backups,
                "error": f'Nazwa "{name.strip()}" jest już zajęta przez inne urządzenie.',
            },
            status_code=409,
        )

    await session.refresh(device)

    script = script_for_device(device)
    locations = await list_locations(session)
    run = await latest_device_run(session, device.id)
    backups = await list_device_backups(session, device.id)
    return templates.TemplateResponse(
        "devices/detail.html",
        {
            "request": request,
            "device": device,
            "script": script,
            "just_created": False,
            "locations": locations,
            "nav_locations": locations,
            "removal_script": build_removal_script(),
            "run": run,
            "backups": backups,
        },
    )


@router.post("/{device_id}/generate-api-credentials")
async def generate_api_credentials(
    request: Request, device_id: str, session: AsyncSession = Depends(get_session)
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")

    device.api_username = "mtm-api"
    device.api_password_encrypted = encrypt(generate_api_password())
    await session.commit()
    await session.refresh(device)

    script = script_for_device(device)
    locations = await list_locations(session)
    run = await latest_device_run(session, device.id)
    backups = await list_device_backups(session, device.id)
    return templates.TemplateResponse(
        "devices/detail.html",
        {
            "request": request,
            "device": device,
            "script": script,
            "just_created": False,
            "locations": locations,
            "nav_locations": locations,
            "removal_script": build_removal_script(),
            "run": run,
            "backups": backups,
            "api_credentials_generated": True,
        },
    )


@router.post("/{device_id}/check-updates")
async def check_device_updates(
    request: Request, device_id: str, session: AsyncSession = Depends(get_session)
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_operate_location(request, device.location_id)

    update_info = await check_for_updates(device)
    if update_info["ok"]:
        device.available_routeros_version = update_info.get("latest_version")

    board_info = await get_routerboard_info(device)
    if board_info["ok"]:
        device.current_firmware = board_info.get("current_firmware")
        device.available_firmware = board_info.get("upgrade_firmware")

    await session.commit()
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)


@router.post("/{device_id}/update")
async def start_device_update(
    request: Request,
    device_id: str,
    mode: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_operate_location(request, device.location_id)
    if mode not in ("software", "firmware", "both"):
        raise HTTPException(status_code=400, detail="Nieprawidłowy tryb aktualizacji")

    request.app.state.scheduler.add_job(
        run_device_update, args=[device.id, mode], next_run_time=datetime.datetime.now()
    )
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)


@router.post("/{device_id}/reboot")
async def reboot_device(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_operate_location(request, device.location_id)

    # To zwykły restart, nie dotyka configu ani nie odpala sekwencji update.
    result = await reboot(device)
    if not result["ok"]:
        return RedirectResponse(url=f"/devices/{device_id}?err=" + quote(
            f"Restart nie został wykonany — {result['error']}"), status_code=303)
    if result.get("unconfirmed"):
        return RedirectResponse(url=f"/devices/{device_id}?err=" + quote(
            "Polecenie restartu wysłane, ale router nie potwierdził odbioru. Jeśli za ok. minutę "
            "czas pracy (uptime) się nie wyzeruje, restartu nie było."), status_code=303)
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)


@router.post("/{device_id}/ping-targets")
async def add_ping_target(
    request: Request,
    device_id: str,
    ip: str = Form(...),
    label: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_operate_location(request, device.location_id)
    if not ip.strip():
        return HTMLResponse("")
    target = PingTarget(device_id=device.id, ip=ip.strip(), label=label.strip() or None)
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return templates.TemplateResponse(
        "_ping_target_row.html", {"request": request, "device": device, "t": target, "result": None}
    )


@router.post("/{device_id}/ping-targets/{target_id}/delete")
async def delete_ping_target(
    request: Request, device_id: str, target_id: str, session: AsyncSession = Depends(get_session)
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_operate_location(request, device.location_id)
    target = await session.get(PingTarget, _parse_uuid(target_id))
    if target is not None and target.device_id == device.id:
        await session.delete(target)
        await session.commit()
    return HTMLResponse("")  # pusta odpowiedź + hx-swap outerHTML -> wiersz znika


@router.post("/{device_id}/ping-targets/{target_id}/test")
async def test_ping_target(
    request: Request, device_id: str, target_id: str, session: AsyncSession = Depends(get_session)
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_operate_location(request, device.location_id)
    target = await session.get(PingTarget, _parse_uuid(target_id))
    # Cel MUSI nalezec do tego urzadzenia: uprawnienia sprawdzamy na device_id z adresu, wiec
    # bez tego warunku operator z UUID-em celu innej lokalizacji dostawal jego nazwe i adres
    # i pingowal go ze swojego routera (wytkniete w drugiej recenzji; usuwanie mialo to od poczatku).
    if target is None or target.device_id != device.id:
        raise HTTPException(status_code=404, detail="Nie znaleziono celu")
    await session.close()  # jw. — nie trzymaj połączenia DB przez czas pingu
    result = await ping_from_device(device, target.ip)
    return templates.TemplateResponse(
        "_ping_target_row.html", {"request": request, "device": device, "t": target, "result": result}
    )


@router.post("/{device_id}/ping")
async def adhoc_ping(
    request: Request, device_id: str, address: str = Form(...), session: AsyncSession = Depends(get_session)
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_operate_location(request, device.location_id)
    await session.close()  # jw. — nie trzymaj połączenia DB przez czas pingu
    result = await ping_from_device(device, address.strip())
    return templates.TemplateResponse(
        "_ping_result.html", {"request": request, "result": result, "address": address.strip()}
    )


@router.post("/{device_id}/backup")
async def trigger_device_backup(
    request: Request, device_id: str, session: AsyncSession = Depends(get_session)
):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")

    request.app.state.scheduler.add_job(
        backup_device, args=[device.id], next_run_time=datetime.datetime.now()
    )
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)


@router.post("/{device_id}/delete")
async def delete_device(device_id: str, session: AsyncSession = Depends(get_session)):
    device = await session.get(Device, _parse_uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")

    # Kolejnosc ma znaczenie (wytkniete w recenzji zewnetrznej). Wczesniej: najpierw peer
    # z huba, potem DELETE — a kopie, cele pingow i kroki aktualizacji maja klucz obcy bez
    # kaskady, wiec baza odrzucala usuniecie kazdego urzadzenia z choc jedna kopia (czyli
    # praktycznie kazdego). Zostawal rekord w panelu i router bez tunelu.
    #
    # Teraz: (1) zaleznosci i urzadzenie usuwane w JEDNEJ transakcji, flush sprawdza klucze
    # obce bez zatwierdzania; (2) dopiero gdy baza sie zgodzi, peer z huba; (3) commit.
    # Hub nie odpowiada -> rollback, nic nie znika, uzytkownik dostaje komunikat.
    files = [b.file_path for b in (await session.execute(
        select(Backup).where(Backup.device_id == device.id))).scalars().all() if b.file_path]
    await session.execute(delete(Backup).where(Backup.device_id == device.id))
    await session.execute(delete(PingTarget).where(PingTarget.device_id == device.id))
    await session.execute(delete(UpdateRunStep).where(UpdateRunStep.device_id == device.id))
    await session.execute(delete(UpdateRun).where(UpdateRun.device_id == device.id))
    # Wyciszenia powiadomien wskazuja zakres BEZ klucza obcego (scope_id) — bez tego
    # zostalyby w zestawieniu „Wyjatki" i wskazywaly urzadzenie, ktorego nie ma.
    await session.execute(delete(NotificationOverride).where(
        NotificationOverride.scope_type == "device", NotificationOverride.scope_id == device.id))
    await session.delete(device)
    try:
        await session.flush()
    except Exception as e:
        await session.rollback()
        return RedirectResponse(url=f"/devices/{device_id}?err=" + quote(
            f"Nie udało się usunąć urządzenia z bazy: {type(e).__name__}. Nic nie zostało zmienione."),
            status_code=303)

    # Blokada od usuniecia peera do commitu: odtwarzanie kopii czyta urzadzenia z bazy i nie
    # moze trafic w chwile, gdy peera juz nie ma na hubie, a rekord jeszcze jest.
    async with hub_peers_lock:
        ok, error = await remove_peer(device.wg_public_key)
        if not ok:
            await session.rollback()
            return RedirectResponse(url=f"/devices/{device_id}?err=" + quote(
                f"Kanał sterujący WireGuard nie odpowiada ({error}) — peer został na hubie, więc "
                "urządzenia NIE usunięto. Spróbuj ponownie za chwilę."), status_code=303)
        await session.commit()
    # Adres w tunelu wroci do puli — odbiornik syslog nie moze dalej przypisywac go temu urzadzeniu.
    invalidate_device_map()
    for path in files:  # zaszyfrowane pliki kopii binarnych — dopiero po udanym commicie
        try:
            os.remove(path)
        except OSError:
            pass
    return RedirectResponse(url="/", status_code=303)
