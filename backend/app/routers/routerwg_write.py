"""WireGuard na routerach — zapisy (etap 3): komentarze, dodawanie peerow, nowy tunel, ZIP.

Kazdy zapis przechodzi trzy bramki:
  1. podglad z potwierdzeniem (nic jeszcze nie jest zapisane),
  2. przy zatwierdzeniu SWIEZY odczyt routera i ponowne sprawdzenie, ze plan jest nadal
     aktualny — miedzy podgladem a klikniecim ktos mogl dodac peera w Winboksie,
  3. zrzut stanu przed zmiana.
Ograniczenia z zasad: tylko RouterOS 7.21+, tylko interfejsy zapisywalne (nigdy tunel
portalu ani uplink), operacje zbiorcze w obrebie JEDNEGO interfejsu. Komentarz wolno
zmieniac wszedzie.

GET-y pilnuje `require_admin`; POST-y i tak przepuszcza tylko administratorowi middleware.
"""
from __future__ import annotations

import io
import ipaddress
import re
import zipfile

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.ros_text import ros_ascii
from app.auth import require_admin
from app.database import get_session
from app.filenames import content_disposition
from app.routers.routerwg import _NO_STORE, _device, _view
from app.routerwg import client as wg_client
from app.routerwg import qr, snapshot, writes
from app.routerwg.conf import build_client_config
from app.routerwg.model import (
    SUPPORT_FULL, check_new_tunnel, defaults, first_active_drop, free_ips, peer_name,
)
from app.templating import templates

router = APIRouter(prefix="/devices", tags=["routerwg-write"])

_PREFIX = re.compile(r"^[A-Za-z0-9_.-]{0,32}$")
_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_IFNAME = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")


# ------------------------------------------------------------------- pomocnicze ----

def _writable(result: dict, iface) -> str:
    """Powod odmowy zapisu albo pusty napis."""
    if not result.get("ok"):
        return f"Nie udało się odczytać routera: {result.get('error')}"
    if result.get("level") != SUPPORT_FULL:
        return (f"Dodawanie peerów wymaga RouterOS 7.21+ (router ma {result.get('version')}). "
                "Starsze routery nie dostają nowych configów — rozwiązaniem jest aktualizacja.")
    if iface is None:
        return "Nie ma takiego interfejsu."
    if iface.readonly:
        return f"Interfejs {iface.name} jest tylko do odczytu: {iface.readonly_reason}."
    if iface.tunnel is None:
        return f"Interfejs {iface.name} nie ma adresu IPv4 — nie da się przydzielić adresów."
    return ""


def _parse_peer_params(form: dict) -> tuple[dict, list[str]]:
    errors = []
    try:
        count = int(form.get("count") or "0")
    except ValueError:
        count = -1
    if not 0 <= count <= 250:
        errors.append("Liczba peerów: od 0 do 250.")
    prefix = (form.get("prefix") or "").strip()
    if not _PREFIX.match(prefix):
        errors.append("Prefiks nazwy: litery, cyfry, _ . - (do 32 znaków).")
    endpoint = (form.get("endpoint") or "").strip()
    if count and not endpoint:
        errors.append("Podaj adres serwera (client-endpoint) — bez niego config klienta nie zadziała.")
    elif endpoint and not _HOST.match(endpoint):
        errors.append("Adres serwera: sam host albo IP, bez portu i bez http:// — port to listen-port interfejsu.")
    dns = (form.get("dns") or "").strip()
    for d in [x.strip() for x in dns.split(",") if x.strip()]:
        try:
            ipaddress.ip_address(d)
        except ValueError:
            errors.append(f"DNS: „{d}” to nie jest adres IP.")
    allowed = (form.get("client_allowed") or "").strip()
    for a in [x.strip() for x in allowed.split(",") if x.strip()]:
        try:
            ipaddress.ip_network(a, strict=False)
        except ValueError:
            errors.append(f"AllowedIPs klienta: „{a}” to nie jest sieć.")
    try:
        keepalive = int(form.get("keepalive") or "0")
    except ValueError:
        keepalive = -1
    if not 0 <= keepalive <= 3600:
        errors.append("Keepalive: od 0 do 3600 sekund.")
    params = {
        "count": max(count, 0), "prefix": prefix, "endpoint": endpoint, "dns": dns,
        "client_allowed": allowed, "keepalive": max(keepalive, 0),
        "psk": form.get("psk") == "1", "responder": form.get("responder") == "1",
    }
    return params, errors


def _plan(iface, peers, params: dict) -> tuple[list[dict], str]:
    want = params["count"]
    ips = []
    for ip in free_ips(iface, peers):
        ips.append(ip)
        if len(ips) == want:
            break
    if len(ips) < want:
        return [], f"W podsieci {iface.tunnel.network} zostało tylko {len(ips)} wolnych adresów."
    taken = {p.name.lower() for p in peers if p.interface == iface.name and p.name}
    prefixlen = iface.tunnel.network.prefixlen
    return [{"ip": str(ip), "prefixlen": prefixlen,
             "name": peer_name(params["prefix"], ip, prefixlen, taken)} for ip in ips], ""


async def _endpoint_choices(device) -> list[tuple[str, str]]:
    """Gotowe adresy serwera do wpisania jednym kliknieciem — z /ip/cloud routera, czyli
    ze zrodla prawdy. DDNS tylko gdy router faktycznie ma nazwe; adres publiczny z dopiskiem,
    gdy router stoi za NAT-em (wtedy zadziala dopiero z przekierowaniem portu UDP).
    Nazwa *.vpn.mynetname.net z Back To Home celowo NIE — ona prowadzi do BTH, nie do
    tego serwera WireGuard."""
    try:
        (cloud,) = await writes.read_rows(device, "/rest/ip/cloud")
    except Exception:
        return []
    cloud = cloud if isinstance(cloud, dict) else {}
    out = []
    if cloud.get("dns-name"):
        out.append(("DDNS MikroTika", str(cloud["dns-name"])))
    pub = str(cloud.get("public-address") or "")
    if pub and pub != "0.0.0.0":
        nat = " (za NAT — potrzebne przekierowanie portu)" if getattr(device, "public_behind_nat", None) else ""
        out.append((f"Adres publiczny{nat}", pub))
    return out


async def _render_form(request: Request, name: str, ctx: dict, *, no_store: bool = False):
    """Jak _render, ale na kroku formularza dokłada adresy serwera do wyboru."""
    if ctx.get("step") == "form" and ctx.get("device") is not None and not ctx.get("reason"):
        ctx = {**ctx, "endpoint_choices": await _endpoint_choices(ctx["device"])}
    return _render(request, name, ctx, no_store=no_store)


def _render(request: Request, name: str, ctx: dict, *, no_store: bool = False):
    resp = templates.TemplateResponse(name, {"request": request, **ctx})
    if no_store:
        resp.headers.update(_NO_STORE)
    return resp


# ------------------------------------------------------------------- komentarz ----

@router.get("/{device_id}/wireguard/comment", response_class=HTMLResponse)
async def comment_form(request: Request, device_id: str, iface: str, pid: str,
                       session: AsyncSession = Depends(get_session)):
    require_admin(request)
    device = await _device(request, device_id, session)
    result = await wg_client.load(device)
    view = _view(result, iface) if result.get("ok") else {"peers": []}
    peer = next((p for p in view["peers"] if p.id == pid), None)
    return _render(request, "routerwg/_comment.html", {"device": device, "iface": iface, "peer": peer})


@router.post("/{device_id}/wireguard/comment", response_class=HTMLResponse)
async def comment_save(request: Request, device_id: str, iface: str = Form(...), pid: str = Form(...),
                       comment: str = Form(""), session: AsyncSession = Depends(get_session)):
    """Komentarz wolno zmieniac WSZEDZIE, takze na tunelu portalu i uplinkach — to notatka
    uzytkownika, nie konfiguracja tunelu."""
    device = await _device(request, device_id, session)
    result = await wg_client.load(device)
    view = _view(result, iface) if result.get("ok") else {"peers": []}
    peer = next((p for p in view["peers"] if p.id == pid), None)
    ctx = {"device": device, "iface": iface, "peer": peer}
    if peer is None:
        return _render(request, "routerwg/_comment.html", {**ctx, "error": "Peer zniknął z routera."})
    await snapshot.save(device.id, operation=f"przed zmianą komentarza peera {peer.display_name} na {iface}",
                        scope=f"wireguard:{iface}",
                        items=[snapshot.peer_record(p) for p in view["peers"]])
    sent = ros_ascii(comment)  # RouterOS gubi/psuje polskie znaki — zob. app/ros_text.py
    try:
        await writes.set_peer_comment(device, pid, sent)
    except Exception as e:
        return _render(request, "routerwg/_comment.html", {**ctx, "error": f"Nie udało się zapisać: {e}"})
    peer.comment = sent
    notice = "Komentarz zapisany." + (f" Na routerze bez polskich znaków: „{sent}”." if sent != comment.strip() else "")
    resp = _render(request, "routerwg/_comment.html", {**ctx, "notice": notice})
    resp.headers["HX-Trigger"] = "wg-refresh"  # tabela odswiezy sie od razu, nie po 15 s
    return resp


# ------------------------------------------------------------------- dodawanie peerow ----

@router.get("/{device_id}/wireguard/add", response_class=HTMLResponse)
async def add_form(request: Request, device_id: str, iface: str,
                   session: AsyncSession = Depends(get_session)):
    require_admin(request)
    device = await _device(request, device_id, session)
    result = await wg_client.load(device)
    view = _view(result, iface) if result.get("ok") else {"iface": None, "peers": []}
    reason = _writable(result, view["iface"])
    d = defaults(view["iface"], result.get("peers", [])) if not reason else {}
    preview_ips = []
    if not reason:
        for ip in free_ips(view["iface"], result["peers"]):
            preview_ips.append(str(ip))
            if len(preview_ips) == 5:
                break
    return await _render_form(request, "routerwg/add.html", {
        "device": device, "r": result, "iface": view["iface"], "reason": reason, "step": "form",
        "p": {"count": 1, "prefix": "Client_", "endpoint": d.get("endpoint", ""), "dns": d.get("dns", ""),
              "client_allowed": d.get("client_allowed", ""), "keepalive": d.get("keepalive", 25),
              "psk": d.get("psk", True), "responder": True},
        "free_preview": preview_ips,
    })


@router.post("/{device_id}/wireguard/add/preview", response_class=HTMLResponse)
async def add_preview(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await _device(request, device_id, session)
    form = dict(await request.form())
    iface_name = form.get("iface", "")
    result = await wg_client.load(device)
    view = _view(result, iface_name) if result.get("ok") else {"iface": None, "peers": []}
    reason = _writable(result, view["iface"])
    params, errors = _parse_peer_params(form)
    if not params["count"]:
        errors.append("Podaj liczbę peerów do dodania.")
    plan, plan_err = ([], "") if (reason or errors) else _plan(view["iface"], result["peers"], params)
    if plan_err:
        errors.append(plan_err)
    return await _render_form(request, "routerwg/add.html", {
        "device": device, "r": result, "iface": view["iface"], "reason": reason,
        "step": "form" if (errors or reason) else "preview", "errors": errors, "p": params, "plan": plan,
    })


@router.post("/{device_id}/wireguard/add/apply", response_class=HTMLResponse)
async def add_apply(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await _device(request, device_id, session)
    form = dict(await request.form())
    iface_name = form.get("iface", "")
    planned = [x for x in (form.get("planned") or "").split(",") if x]
    result = await wg_client.load(device)
    view = _view(result, iface_name) if result.get("ok") else {"iface": None, "peers": []}
    reason = _writable(result, view["iface"])
    params, errors = _parse_peer_params(form)
    plan, plan_err = ([], "") if (reason or errors) else _plan(view["iface"], result["peers"], params)
    # Plan liczony od nowa na swiezym odczycie MUSI byc identyczny z tym z podgladu —
    # inaczej ktos zmienil router w miedzyczasie i dodalibysmy co innego, niz zatwierdzono.
    if not (reason or errors or plan_err) and [x["ip"] for x in plan] != planned:
        plan_err = ("Stan routera zmienił się od podglądu (ktoś dodał albo zmienił peera) — "
                    "przygotuj podgląd jeszcze raz.")
    if reason or errors or plan_err:
        return await _render_form(request, "routerwg/add.html", {
            "device": device, "r": result, "iface": view["iface"], "reason": reason, "step": "form",
            "errors": errors + ([plan_err] if plan_err else []), "p": params,
        })
    await snapshot.save(device.id, operation=f"przed dodaniem {len(plan)} peerów na {iface_name}",
                        scope=f"wireguard:{iface_name}",
                        items=[snapshot.peer_record(p) for p in view["peers"]])
    results = await writes.add_peers(device, iface_name, plan, params)
    return await _render_form(request, "routerwg/add.html", {
        "device": device, "r": result, "iface": view["iface"], "step": "done", "p": params,
        "results": results, "ok_ids": ",".join(x["id"] for x in results if x.get("ok") and x.get("id")),
    })


# ------------------------------------------------------------------- ZIP ----

def _zip_name(name: str, used: set[str]) -> str:
    base = re.sub(r'[\\/:*?"<>|\s]+', "_", name).strip("._") or "client"
    unique, n = base, 2
    while unique.lower() in used:
        unique, n = f"{base}_{n}", n + 1
    used.add(unique.lower())
    return unique


@router.get("/{device_id}/wireguard/zip")
async def configs_zip(request: Request, device_id: str, iface: str, ids: str,
                      session: AsyncSession = Depends(get_session)):
    """ZIP z <nazwa>.conf + <nazwa>.png. Budowany ze SWIEZEGO odczytu routera — portal nie
    trzyma kluczy nowych peerow ani chwili dluzej, niz trwa to zadanie. PNG powstaja
    synchronicznie, wiec ZIP jest kompletny z definicji."""
    require_admin(request)
    device = await _device(request, device_id, session)
    result = await wg_client.load(device)
    view = _view(result, iface) if result.get("ok") else {"iface": None, "peers": []}
    wanted = [x for x in ids.split(",") if x]
    by_id = {p.id: p for p in view["peers"]}
    buf, used = io.BytesIO(), set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for pid in wanted:
            peer = by_id.get(pid)
            if peer is None or view["iface"] is None:
                continue
            text, _ = build_client_config(peer, view["iface"])
            name = _zip_name(peer.display_name, used)
            z.writestr(f"{name}.conf", text)
            z.writestr(f"{name}.png", qr.png(text))
    headers = {"Content-Disposition": content_disposition(f"{device.name}-{iface}.zip"), **_NO_STORE}
    return Response(content=buf.getvalue(), media_type="application/zip", headers=headers)


# ------------------------------------------------------------------- nowy tunel ----

async def _tunnel_context(device, result) -> dict:
    rules, bridges, lists, addrs = await writes.read_rows(
        device, "/rest/ip/firewall/filter", "/rest/interface/bridge", "/rest/interface/list", "/rest/ip/address")
    builtin = {"all", "none", "dynamic", "static"}
    return {
        "rules": rules, "addr_rows": addrs,
        "bridges": [b.get("name") for b in bridges if b.get("name")],
        "lists": [x.get("name") for x in lists if x.get("name") and x.get("name") not in builtin],
        "used_ports": {i.listen_port for i in result.get("interfaces", [])},
    }


def _parse_tunnel(form: dict) -> tuple[dict, list[str]]:
    errors = []
    name = (form.get("name") or "").strip()
    if not _IFNAME.match(name):
        errors.append("Nazwa interfejsu: litery, cyfry, _ . - (do 40 znaków).")
    port = (form.get("port") or "").strip()
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        errors.append("Port: liczba od 1 do 65535.")
    network = None
    try:
        network = ipaddress.ip_network((form.get("network") or "").strip(), strict=False)
        if network.version != 4 or network.prefixlen > 30:
            errors.append("Podsieć tunelu: IPv4, maska najwyżej /30.")
            network = None
    except ValueError:
        errors.append("Podsieć tunelu: np. 10.20.30.0/24.")
    t = {"name": name, "port": port, "network": network,
         "firewall": form.get("firewall") == "1", "masquerade": form.get("masquerade") == "1",
         "bridge": (form.get("bridge") or "").strip(), "iflist": form.get("iflist") == "1",
         "list_name": (form.get("list_name") or "").strip()}
    return t, errors


@router.get("/{device_id}/wireguard/new", response_class=HTMLResponse)
async def new_form(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    require_admin(request)
    device = await _device(request, device_id, session)
    result = await wg_client.load(device)
    reason = "" if result.get("ok") and result.get("level") == SUPPORT_FULL else (
        result.get("error") or f"Nowy tunel wymaga RouterOS 7.21+ (router ma {result.get('version')}).")
    ctx = await _tunnel_context(device, result) if not reason else {"bridges": [], "lists": []}
    return await _render_form(request, "routerwg/new.html", {
        "device": device, "r": result, "reason": reason, "step": "form", **ctx,
        "t": {"name": "WG_VPN", "port": "", "network": "", "firewall": True, "masquerade": False,
              "bridge": (ctx["bridges"] or [""])[0], "iflist": False, "list_name": (ctx["lists"] or [""])[0]},
        "p": {"count": 1, "prefix": "Client_", "endpoint": "", "dns": "", "client_allowed": "",
              "keepalive": 25, "psk": True, "responder": True},
    })


async def _check_tunnel(device, form):
    result = await wg_client.load(device)
    if not result.get("ok") or result.get("level") != SUPPORT_FULL:
        return result, {}, None, {}, [result.get("error") or "Nowy tunel wymaga RouterOS 7.21+."]
    ctx = await _tunnel_context(device, result)
    t, errors = _parse_tunnel(form)
    p, perr = _parse_peer_params(form)
    errors += perr
    if t["network"] is not None and not errors:
        errors += check_new_tunnel(t["name"], t["port"], t["network"], result["interfaces"], ctx["addr_rows"])
    if t["masquerade"] and t["bridge"] not in ctx["bridges"]:
        errors.append("Wybierz bridge do maskarady.")
    if t["iflist"] and t["list_name"] not in ctx["lists"]:
        errors.append("Wybierz listę interfejsów.")
    return result, ctx, t, p, errors


@router.post("/{device_id}/wireguard/new/preview", response_class=HTMLResponse)
async def new_preview(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await _device(request, device_id, session)
    form = dict(await request.form())
    result, ctx, t, p, errors = await _check_tunnel(device, form)
    drop = first_active_drop(ctx.get("rules", [])) if t and t["firewall"] else None
    hosts = []
    if t and t["network"] is not None and not errors:
        it = t["network"].hosts()
        next(it)  # .1 to serwer
        for ip in it:
            if len(hosts) == p["count"]:
                break
            hosts.append(str(ip))
    return await _render_form(request, "routerwg/new.html", {
        "device": device, "r": result, "reason": "", "step": "form" if errors else "preview",
        "errors": errors, **ctx, "t": t or {}, "p": p, "drop": drop, "hosts": hosts,
    })


@router.post("/{device_id}/wireguard/new/apply", response_class=HTMLResponse)
async def new_apply(request: Request, device_id: str, session: AsyncSession = Depends(get_session)):
    device = await _device(request, device_id, session)
    form = dict(await request.form())
    result, ctx, t, p, errors = await _check_tunnel(device, form)
    if errors:
        return await _render_form(request, "routerwg/new.html", {
            "device": device, "r": result, "reason": "", "step": "form", "errors": errors,
            **ctx, "t": t or {}, "p": p,
        })
    drop = first_active_drop(ctx["rules"]) if t["firewall"] else None
    # Pozycja reguly firewalla zatwierdzona w podgladzie musi byc ta sama co teraz.
    if t["firewall"] and (drop or {}).get(".id", "") != form.get("drop_id", ""):
        return await _render_form(request, "routerwg/new.html", {
            "device": device, "r": result, "reason": "", "step": "form", **ctx, "t": t, "p": p,
            "errors": ["Firewall routera zmienił się od podglądu — przygotuj podgląd jeszcze raz."],
        })
    await snapshot.save(
        device.id, operation=f"przed utworzeniem tunelu {t['name']}", scope="wireguard:nowy-tunel",
        items=[snapshot.peer_record(x) for x in result["peers"]],
        extra={"interfaces": [{"name": i.name, "listen_port": i.listen_port} for i in result["interfaces"]],
               "firewall_input": [{"id": r.get(".id"), "action": r.get("action"), "comment": r.get("comment"),
                                   "disabled": r.get("disabled")} for r in ctx["rules"] if r.get("chain") == "input"]},
    )
    report, ok = await writes.create_tunnel(device, t, (drop or {}).get(".id"))
    results, ok_ids = [], ""
    if ok and p["count"]:
        fresh = await wg_client.load(device)
        view = _view(fresh, t["name"]) if fresh.get("ok") else {"iface": None, "peers": []}
        if view["iface"] is None:
            report.append("BŁĄD — nowy interfejs nie pojawił się w odczycie, peerów nie dodano.")
        else:
            plan, perr = _plan(view["iface"], fresh["peers"], p)
            if perr:
                report.append(f"BŁĄD — {perr}")
            else:
                results = await writes.add_peers(device, t["name"], plan, p)
                ok_ids = ",".join(x["id"] for x in results if x.get("ok") and x.get("id"))
    return await _render_form(request, "routerwg/new.html", {
        "device": device, "r": result, "reason": "", "step": "done", "t": t, "p": p,
        "report": report, "results": results, "ok_ids": ok_ids, **ctx,
    })


# ------------------------------------------------------------------- import .conf (etap 4) ----

import secrets  # noqa: E402
import time  # noqa: E402

from fastapi import File, UploadFile  # noqa: E402

from app.routerwg import importer  # noqa: E402
from app.routerwg.model import SUPPORT_NONE  # noqa: E402

# Wgrane pliki (z kluczami prywatnymi klientow) czekaja na zatwierdzenie W PAMIECI procesu,
# pod losowym tokenem, najwyzej 15 minut. Nie odsylamy ich do przegladarki w ukrytym polu —
# klucze nie wracaja na strone tylko po to, zeby za chwile znow przyjsc. Restart backendu
# je gubi: wtedy po prostu wgrywa sie pliki jeszcze raz.
_IMPORT_TTL = 15 * 60
_pending: dict[str, dict] = {}


def _purge_pending() -> None:
    now = time.monotonic()
    for token in [t for t, v in _pending.items() if v["expires"] < now]:
        _pending.pop(token, None)


def _importable(result: dict, iface) -> str:
    if not result.get("ok"):
        return f"Nie udało się odczytać routera: {result.get('error')}"
    if result.get("level") == SUPPORT_NONE:
        return f"RouterOS {result.get('version')} nie jest obsługiwany (wymagane 7.15+)."
    if iface is None:
        return "Nie ma takiego interfejsu."
    if iface.readonly:
        return f"Interfejs {iface.name} jest tylko do odczytu: {iface.readonly_reason}."
    return ""


def _display(changes: dict) -> list[tuple[str, str]]:
    """Zmiany do pokazania — klucz prywatny nigdy nie trafia na strone."""
    return [(k, "zgodny z kluczem publicznym peera (sprawdzone X25519)" if k == "private-key" else v)
            for k, v in changes.items()]


@router.get("/{device_id}/wireguard/import", response_class=HTMLResponse)
async def import_form(request: Request, device_id: str, iface: str,
                      session: AsyncSession = Depends(get_session)):
    require_admin(request)
    device = await _device(request, device_id, session)
    result = await wg_client.load(device)
    view = _view(result, iface) if result.get("ok") else {"iface": None, "peers": []}
    reason = _importable(result, view["iface"])
    missing = 0
    if not reason:
        missing = sum(1 for p in view["peers"] if not p.has_private_key or not p.client_endpoint)
    return _render(request, "routerwg/import.html", {
        "device": device, "r": result, "iface": view["iface"], "reason": reason, "step": "form",
        "peer_count": len(view["peers"]), "missing": missing,
    })


@router.post("/{device_id}/wireguard/import/preview", response_class=HTMLResponse)
async def import_preview(request: Request, device_id: str, iface: str = Form(...),
                         mode: str = Form("fill"), files: list[UploadFile] = File(...),
                         session: AsyncSession = Depends(get_session)):
    device = await _device(request, device_id, session)
    result = await wg_client.load(device)
    view = _view(result, iface) if result.get("ok") else {"iface": None, "peers": []}
    reason = _importable(result, view["iface"])
    ctx = {"device": device, "r": result, "iface": view["iface"], "reason": reason}
    if reason:
        return _render(request, "routerwg/import.html", {**ctx, "step": "form"})
    try:
        uploads = [(f.filename or "plik", await f.read()) for f in files]
        confs, notes = importer.load_uploads(uploads)
    except ValueError as e:
        return _render(request, "routerwg/import.html", {**ctx, "step": "form", "errors": [str(e)]})
    if not confs:
        return _render(request, "routerwg/import.html", {**ctx, "step": "form", "notes": notes,
                                                         "errors": ["Nie znalazłem żadnego configu WireGuard."]})
    overwrite = mode == "overwrite"
    items = importer.plan(view["iface"], result["peers"], confs, overwrite, result["level"])
    _purge_pending()
    token = secrets.token_urlsafe(24)
    _pending[token] = {"device_id": str(device.id), "user_id": str(request.state.user.id), "iface": iface,
                       "confs": confs, "overwrite": overwrite, "expires": time.monotonic() + _IMPORT_TTL}
    resp = _render(request, "routerwg/import.html", {
        **ctx, "step": "preview", "items": items, "notes": notes, "token": token, "overwrite": overwrite,
        "display": _display,
    }, no_store=True)
    return resp


@router.post("/{device_id}/wireguard/import/apply", response_class=HTMLResponse)
async def import_apply(request: Request, device_id: str, token: str = Form(...),
                       session: AsyncSession = Depends(get_session)):
    device = await _device(request, device_id, session)
    _purge_pending()
    pending = _pending.pop(token, None)
    if (pending is None or pending["device_id"] != str(device.id)
            or pending["user_id"] != str(request.state.user.id)):
        return _render(request, "routerwg/import.html", {
            "device": device, "r": {}, "iface": None, "reason": "",
            "step": "form", "errors": ["Podgląd wygasł albo nie należy do Ciebie — wgraj pliki jeszcze raz."],
        })
    iface = pending["iface"]
    # Plan liczony OD NOWA na swiezym odczycie: miedzy podgladem a zatwierdzeniem ktos mogl
    # zmienic peera w Winboksie. Zapisujemy to, co wynika z aktualnego stanu routera.
    result = await wg_client.load(device)
    view = _view(result, iface) if result.get("ok") else {"iface": None, "peers": []}
    reason = _importable(result, view["iface"])
    if reason:
        return _render(request, "routerwg/import.html", {"device": device, "r": result, "iface": view["iface"],
                                                         "reason": reason, "step": "form"})
    items = importer.plan(view["iface"], result["peers"], pending["confs"], pending["overwrite"], result["level"])
    to_apply = [x for x in items if x["status"] == "apply"]
    report = []
    if to_apply:
        await snapshot.save(device.id, operation=f"przed uzupełnieniem {len(to_apply)} peerów z plików .conf na {iface}",
                            scope=f"wireguard:{iface}", items=[snapshot.peer_record(p) for p in view["peers"]])
        report = await writes.apply_import(device, to_apply)
    return _render(request, "routerwg/import.html", {
        "device": device, "r": result, "iface": view["iface"], "reason": "", "step": "done",
        "report": report, "skipped": [x for x in items if x["status"] != "apply"],
    })
