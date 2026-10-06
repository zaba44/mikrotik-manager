"""WireGuard na zarzadzanych routerach — etap 1: monitor i config istniejacych peerow.

Uprawnienia (ustalone z uzytkownikiem):
  * monitor (bez kluczy) — kazdy, kto ma dostep do urzadzenia;
  * config i QR (zawieraja klucze prywatne klientow) — wylacznie administrator, tak jak
    skrypty z haslami. GET-y pilnuje tu `require_admin`; POST-y i tak przepuszcza tylko
    administratorowi middleware w main.py (nie sa akcjami operacyjnymi).

Wszystko, co niesie klucz prywatny, idzie z `Cache-Control: no-store` — config z kluczem
nie ma prawa zostac w pamieci podrecznej przegladarki.
"""
from __future__ import annotations

import ipaddress
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import is_admin, require_admin, require_location
from app.database import get_session
from app.filenames import content_disposition
from app.models import Device
from app.routerwg import client as wg_client
from app.routerwg import qr
from app.routerwg.conf import build_client_config
from app.routerwg.model import SUPPORT_BASIC, SUPPORT_NONE, default_interface, format_ago
from app.templating import templates

router = APIRouter(prefix="/devices", tags=["routerwg"])

_NO_STORE = {"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"}


def _uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")


async def _device(request: Request, device_id: str, session: AsyncSession) -> Device:
    device = await session.get(Device, _uuid(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia")
    require_location(request, device.location_id)
    # Zwolnij polaczenie DB przed REST-em — ten sam wzorzec co reszta fragmentow:
    # dziesiatki rownoczesnych odczytow czekajacych na semafor wyczerpywaly pule.
    await session.close()
    return device


def _host_key(peer):
    try:
        return (0, int(ipaddress.ip_address(peer.host_ip)), peer.display_name.lower())
    except (TypeError, ValueError):
        return (1, 0, peer.display_name.lower())


def _view(result: dict, iface_name: str | None) -> dict:
    """Wybrany interfejs i jego peery. BTH ma wlasne okno, wiec tu go pomijamy."""
    interfaces = [i for i in result.get("interfaces", []) if not i.is_bth]
    peers_all = result.get("peers", [])
    iface = next((i for i in interfaces if i.name == iface_name), None) if iface_name else None
    if iface is None:
        iface = default_interface(interfaces, peers_all)
    peers = sorted((p for p in peers_all if iface and p.interface == iface.name), key=_host_key)
    counts = {
        i.name: (
            sum(1 for p in peers_all if p.interface == i.name and p.status == "active"),
            sum(1 for p in peers_all if p.interface == i.name),
        )
        for i in interfaces
    }
    return {"interfaces": interfaces, "iface": iface, "peers": peers, "counts": counts}


@router.get("/{device_id}/wireguard", response_class=HTMLResponse)
async def wireguard_page(request: Request, device_id: str, iface: str = "",
                         session: AsyncSession = Depends(get_session)):
    device = await _device(request, device_id, session)
    result = await wg_client.load(device)
    return templates.TemplateResponse("routerwg/page.html", {
        "request": request, "device": device, "r": result,
        **(_view(result, iface or None) if result.get("ok") else {}),
        "is_admin": is_admin(request.state.user),
        "SUPPORT_NONE": SUPPORT_NONE, "SUPPORT_BASIC": SUPPORT_BASIC, "format_ago": format_ago,
    })


@router.get("/{device_id}/wireguard/table", response_class=HTMLResponse)
async def wireguard_table(request: Request, device_id: str, iface: str = "",
                          session: AsyncSession = Depends(get_session)):
    """Auto-odswiezanie: podmienia tylko <tbody> i licznik. filter.js sam ponownie stosuje
    filtr po podmianie, a sortable.js przywraca wybrana kolejnosc."""
    device = await _device(request, device_id, session)
    result = await wg_client.load(device)
    return templates.TemplateResponse("routerwg/_table.html", {
        "request": request, "device": device, "r": result,
        **(_view(result, iface or None) if result.get("ok") else {}),
        "is_admin": is_admin(request.state.user), "format_ago": format_ago, "oob": True,
    })


@router.get("/{device_id}/wireguard/config", response_class=HTMLResponse)
async def wireguard_config(request: Request, device_id: str, iface: str, pid: str,
                           session: AsyncSession = Depends(get_session)):
    require_admin(request)
    device = await _device(request, device_id, session)
    result = await wg_client.load(device)
    if not result.get("ok"):
        return HTMLResponse(f'<p class="error">Nie udało się odczytać routera: {result.get("error")}</p>',
                            headers=_NO_STORE)
    view = _view(result, iface)
    peer = next((p for p in view["peers"] if p.id == pid), None)
    if peer is None or view["iface"] is None:
        return HTMLResponse('<p class="error">Peer zniknął z routera — odśwież listę.</p>', headers=_NO_STORE)
    text, missing = build_client_config(peer, view["iface"])
    response = templates.TemplateResponse("routerwg/_config.html", {
        "request": request, "device": device, "peer": peer, "iface": view["iface"],
        "text": text, "missing": missing, "qr_svg": qr.svg(text),
        "basic": result.get("level") == SUPPORT_BASIC,
    })
    response.headers.update(_NO_STORE)
    return response


@router.post("/{device_id}/wireguard/qr", response_class=HTMLResponse)
async def wireguard_qr(request: Request, device_id: str, text: str = Form(""),
                       session: AsyncSession = Depends(get_session)):
    """Podglad QR na zywo z edytowanego tekstu. Tekst przychodzi od administratora, ktory
    i tak go wlasnie zobaczyl — serwer niczego tu nie odczytuje z routera ani nie zapisuje."""
    await _device(request, device_id, session)
    if not text.strip():
        return HTMLResponse('<span class="empty">Pusty config.</span>', headers=_NO_STORE)
    try:
        return HTMLResponse(qr.svg(text), headers=_NO_STORE)
    except Exception as e:  # np. tekst za dlugi na kod QR
        return HTMLResponse(f'<p class="error">Nie da się zrobić kodu QR: {e}</p>', headers=_NO_STORE)


@router.post("/{device_id}/wireguard/download")
async def wireguard_download(request: Request, device_id: str, text: str = Form(...),
                             name: str = Form("client"), fmt: str = Form("conf"),
                             session: AsyncSession = Depends(get_session)):
    """Pobiera to, co jest AKTUALNIE w oknie — z ewentualnymi recznymi poprawkami."""
    await _device(request, device_id, session)
    body = text.replace("\r\n", "\n")
    if fmt == "png":
        data, media, ext = qr.png(body), "image/png", "png"
    else:
        data, media, ext = body.encode("utf-8"), "text/plain; charset=utf-8", "conf"
    headers = {"Content-Disposition": content_disposition(f"{name}.{ext}"), **_NO_STORE}
    return Response(content=data, media_type=media, headers=headers)


@router.get("/{device_id}/fragment/wireguard", response_class=HTMLResponse)
async def wireguard_summary(request: Request, device_id: str,
                            session: AsyncSession = Depends(get_session)):
    """Podsumowanie na stronie urzadzenia — pelny monitor ma osobna strone, bo tabela na
    200+ wierszy nie miesci sie w zwijanej sekcji."""
    device = await _device(request, device_id, session)
    result = await wg_client.load(device)
    return templates.TemplateResponse("routerwg/_summary.html", {
        "request": request, "device": device, "r": result,
        **(_view(result, None) if result.get("ok") else {}),
        "SUPPORT_NONE": SUPPORT_NONE,
    })


# =========================================================================== BTH ====

import re as _re  # noqa: E402

from fastapi.responses import RedirectResponse  # noqa: E402

from app.routerwg import bth as bth_api  # noqa: E402
from app.routerwg import snapshot  # noqa: E402
from app.routerwg.client import RouterError  # noqa: E402
from app.routerwg.conf import bth_local_only  # noqa: E402

_BTH_NAME = _re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_BTH_EXPIRES = ("", "1d", "7d", "30d", "90d", "365d")


def _back(device: Device, *, msg: str = "", err: str = "", anchor: str = "") -> RedirectResponse:
    from urllib.parse import urlencode
    q = urlencode({k: v for k, v in (("msg", msg), ("err", err)) if v})
    return RedirectResponse(f"/devices/{device.id}/bth{'?' + q if q else ''}{anchor}", status_code=303)


async def _bth_snapshot(device: Device, operation: str, state: dict) -> None:
    """Zrzut przed zapisem: uzytkownicy BTH (bez kluczy i tokenow) + stan BTH/DDNS."""
    cloud = state.get("cloud", {})
    await snapshot.save(
        device.id, operation=operation, scope="back-to-home",
        items=[snapshot.bth_user_record(u) for u in state.get("users", [])],
        extra={k: cloud.get(k) for k in ("back-to-home-vpn", "ddns-enabled", "dns-name",
                                         "vpn-dns-name", "vpn-port")},
    )


@router.get("/{device_id}/bth", response_class=HTMLResponse)
async def bth_page(request: Request, device_id: str, msg: str = "", err: str = "",
                   session: AsyncSession = Depends(get_session)):
    device = await _device(request, device_id, session)
    state = await bth_api.load(device)
    return templates.TemplateResponse("routerwg/bth.html", {
        "request": request, "device": device, "s": state, "msg": msg, "err": err,
        "is_admin": is_admin(request.state.user), "expires_options": _BTH_EXPIRES,
    })


@router.post("/{device_id}/bth/enable")
async def bth_enable(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await _device(request, device_id, session)
    state = await bth_api.load(device)
    if not state.get("ok") or not state.get("supported"):
        return _back(device, err=state.get("error") or state.get("reason") or "Back To Home niedostępne.")
    if state.get("enabled"):
        return _back(device, msg="Back To Home jest już włączone.")
    ddns = str(state["cloud"].get("ddns-enabled") or "")
    await _bth_snapshot(device, "przed włączeniem Back To Home", state)
    try:
        await bth_api.enable(device, ddns)
    except (RouterError, Exception) as e:
        return _back(device, err=f"Nie udało się włączyć Back To Home: {e}")
    note = " DDNS był wyłączony — ustawiony na auto." if ddns == "no" else ""
    return _back(device, msg=f"Back To Home włączone.{note}")


@router.post("/{device_id}/bth/users/add")
async def bth_add_user(request: Request, device_id: str, name: str = Form(...),
                       allow_lan: str = Form(""), expires: str = Form(""),
                       session: AsyncSession = Depends(get_session)):
    device = await _device(request, device_id, session)
    name = name.strip()
    if not _BTH_NAME.match(name):
        return _back(device, err="Nazwa: litery, cyfry, kropka, minus i podkreślnik, do 64 znaków.")
    if expires not in _BTH_EXPIRES:
        return _back(device, err="Nieprawidłowy termin ważności.")
    state = await bth_api.load(device)
    if not state.get("ok") or not state.get("enabled"):
        return _back(device, err="Back To Home nie jest włączone na tym routerze.")
    if any(u.get("name") == name for u in state.get("users", [])):
        return _back(device, err=f"Użytkownik {name} już istnieje.")
    await _bth_snapshot(device, f"przed dodaniem użytkownika BTH {name}", state)
    try:
        user = await bth_api.add_user(device, name, allow_lan == "1", expires)
    except Exception as e:
        return _back(device, err=f"Nie udało się dodać użytkownika: {e}")
    warn = "" if user.get("public-key") else " Router jeszcze nie wygenerował kluczy — odśwież za chwilę."
    return _back(device, msg=f"Dodano użytkownika {name}.{warn}")


@router.post("/{device_id}/bth/users/comment")
async def bth_user_comment(request: Request, device_id: str, uid: str = Form(...),
                           comment: str = Form(""), session: AsyncSession = Depends(get_session)):
    device = await _device(request, device_id, session)
    state = await bth_api.load(device)
    user = next((u for u in state.get("users", []) if u.get(".id") == uid), None)
    if user is None:
        return _back(device, err="Ten użytkownik zniknął z routera — odśwież stronę.")
    await _bth_snapshot(device, f"przed zmianą komentarza użytkownika BTH {user.get('name')}", state)
    try:
        await bth_api.set_user_comment(device, uid, comment.strip())
    except Exception as e:
        return _back(device, err=f"Nie udało się zmienić komentarza: {e}")
    return _back(device, msg=f"Komentarz użytkownika {user.get('name')} zapisany.")


@router.get("/{device_id}/bth/config", response_class=HTMLResponse)
async def bth_config(request: Request, device_id: str, uid: str, mode: str = "full",
                     session: AsyncSession = Depends(get_session)):
    require_admin(request)
    device = await _device(request, device_id, session)
    state = await bth_api.load(device)
    is_default = uid == bth_api.DEFAULT_UID
    if is_default:
        # Konfiguracja „zerowa" nie jest wpisem na liscie uzytkownikow — nie ma allow-lan,
        # wiec ostrzezenie o allow-lan=no jej nie dotyczy.
        user = {".id": bth_api.DEFAULT_UID, "name": "domyślny (z włączenia BTH)", "allow-lan": "true",
                "client-address": "192.168.216.2"}
    else:
        user = next((u for u in state.get("users", []) if u.get(".id") == uid), None)
    if user is None:
        return HTMLResponse('<p class="error">Ten użytkownik zniknął z routera — odśwież stronę.</p>',
                            headers=_NO_STORE)
    # Zaznaczone podsieci przychodza jako powtarzany parametr `subnets`. Znacznik `picked`
    # odroznia „uzytkownik odznaczyl wszystko" od „wlasnie przelaczyl na tryb LAN" — przy
    # pierwszym przelaczeniu nie ma jeszcze zadnych pol, a pusta lista znaczylaby ostrzezenie
    # zamiast sensownego domyslnego wyboru (wszystkie podsieci routera).
    lans = state.get("lan_subnets", [])
    if mode == "lan" and "picked" not in request.query_params:
        chosen = list(lans)
    else:
        chosen = [s for s in request.query_params.getlist("subnets") if s in lans]
    try:
        original = await (bth_api.default_config(device) if is_default else bth_api.user_config(device, uid))
    except Exception as e:
        return HTMLResponse(f'<p class="error">{e}</p>', headers=_NO_STORE)

    warnings: list[str] = []
    if mode == "lan":
        if not chosen:
            text = original
            warnings.append("Zaznacz przynajmniej jedną podsieć — do tego czasu pokazuję config pełny.")
        else:
            text = bth_local_only(original, chosen)
        if str(user.get("allow-lan")) not in ("true", "yes"):
            warnings.append("Ten użytkownik ma allow-lan=no — router nie wpuści go do sieci lokalnej, "
                            "więc config „tylko LAN” nie zadziała.")
        common = [s for s in chosen if s in bth_api.COMMON_SUBNETS]
        if common:
            warnings.append(f"{', '.join(common)} to popularne podsieci domowe — jeśli klient siedzi w takiej "
                            "samej sieci lokalnie, ruch do niej nie pójdzie przez tunel.")
    else:
        text = original

    response = templates.TemplateResponse("routerwg/_bth_config.html", {
        "request": request, "device": device, "user": user, "mode": mode, "text": text,
        "qr_svg": qr.svg(text), "lan_subnets": state.get("lan_subnets", []), "chosen": chosen,
        "warnings": warnings,
    })
    response.headers.update(_NO_STORE)
    return response
