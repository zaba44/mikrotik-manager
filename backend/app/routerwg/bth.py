"""Back To Home przez REST.

Empiria z Krok 0 na `Router` (hAP ax², arm64, RouterOS 7.24.2) — trzy cykle wlacz/wylacz,
DDNS za kazdym razem bez zmian:

* Menu uzytkownikow to **`/ip/cloud/back-to-home-user`** — w liczbie pojedynczej.
  `back-to-home-users` (tak mowila specyfikacja i implementacja referencyjna) w RouterOS
  nie istnieje: `print` daje „no such command prefix", a GET zwraca mylace HTTP 500
  zamiast 404 — latwo wziac to za awarie routera.
* `POST .../add` zwraca `{"ret": "*1"}`; klucze uzytkownika router generuje z malym
  opoznieniem — odczyt tuz po dodaniu potrafi oddac puste `private-key`/`public-key`.
* `show-client-config` z parametrem `.id` (NIE `numbers`) zwraca `[{"conf": ..., "qr": ...}]`,
  gdzie `qr` to kod narysowany znakami `#`. Ignorujemy go — QR robimy sami z configu,
  ktory uzytkownik widzi (np. po przerobce na „tylko LAN").
* `/ip/cloud` po wlaczeniu oddaje m.in. `vpn-status`, `vpn-dns-name`, `vpn-port`, stan
  relayow — ale tez klucze prywatne i gotowy config z QR. Wszystko wrazliwe odcinamy
  na wejsciu, zanim dotrze do szablonu.
* Wlaczenie BTH samo dodaje dynamiczna regule `accept` w firewallu i adres
  192.168.216.1/24 na interfejsie `back-to-home-vpn` — niczego nie trzeba dokladac.
* Router bez wsparcia (mAP lite, `mipsbe`) w ogole nie ma pola `back-to-home-vpn`.
"""
from __future__ import annotations

import asyncio
import ipaddress

import httpx

from app.models import Device
from app.routeros_client import _auth, _base_url, _device_sem, _json
from app.routerwg.client import RouterError, _get
from app.routerwg.model import format_ago, peer_from_row, version_tuple

USERS = "/rest/ip/cloud/back-to-home-user"
SUPPORTED_ARCH = ("arm", "arm64", "tile")

# Popularne podsieci domowe — klient w takiej sieci ma ta sama podsiec lokalnie, wiec
# trasa przez tunel moze kolidowac z jego wlasnym LAN-em. Ostrzezenie, nie blokada.
COMMON_SUBNETS = ("192.168.0.0/24", "192.168.1.0/24", "192.168.88.0/24")

# Pola /ip/cloud, ktore NIGDY nie wychodza poza ten modul.
_CLOUD_SECRET = ("vpn-private-key", "vpn-peer-private-key", "vpn-wireguard-client-config",
                 "vpn-wireguard-client-config-qrcode")


def _sanitize_cloud(cloud: dict) -> dict:
    return {k: v for k, v in cloud.items() if k not in _CLOUD_SECRET}


def _sanitize_user(u: dict) -> dict:
    return {k: v for k, v in u.items() if k not in ("private-key", "file-access-token")}


def support(version: str, arch: str, cloud: dict) -> tuple[bool, str]:
    """Konkretny powod zamiast ogolnego „nie dziala". Architekture bierzemy z
    `architecture-name`, NIGDY z nazwy modelu: „hEX" i „hEX S" wystepuja i jako MMIPS,
    i jako ARM (nowy hEX S E60iUGS raportuje `arm`)."""
    if version_tuple(version) < (7, 15, 0):
        return False, f"RouterOS {version} — moduł obsługuje Back To Home od 7.15."
    if arch.lower() not in SUPPORTED_ARCH:
        return False, (f"Architektura „{arch}” nie obsługuje Back To Home "
                       f"(wymagane ARM, ARM64 albo TILE).")
    if "back-to-home-vpn" not in cloud:
        return False, "Router nie udostępnia Back To Home (brak pola back-to-home-vpn w /ip cloud)."
    return True, ""


def lan_subnets(addr_rows: list[dict], wg_names: set[str]) -> list[str]:
    """Podsieci do zaznaczenia w trybie „tylko LAN": prywatne IPv4 z /ip/address, bez
    interfejsow WireGuard (w tym samego back-to-home-vpn). Czytane przy kazdym otwarciu."""
    seen: list[str] = []
    for a in addr_rows:
        if a.get("interface") in wg_names or str(a.get("disabled")) == "true":
            continue
        try:
            iface = ipaddress.ip_interface(str(a.get("address") or ""))
        except ValueError:
            continue
        if iface.version != 4 or not iface.ip.is_private:
            continue
        net = str(iface.network)
        if net not in seen:
            seen.append(net)
    return seen


async def load(device: Device) -> dict:
    if not device.api_username or not device.api_password_encrypted:
        return {"ok": False, "error": "Brak danych API dla tego urządzenia."}
    try:
        async with _device_sem(device):
            async with httpx.AsyncClient(verify=False, timeout=25.0, auth=_auth(device)) as client:
                base = _base_url(device)
                res = await _get(client, f"{base}/rest/system/resource") or {}
                cloud = await _get(client, f"{base}/rest/ip/cloud") or {}
                version, arch = str(res.get("version") or ""), str(res.get("architecture-name") or "")
                ok, reason = support(version, arch, cloud)
                info = {"version": version, "arch": arch, "board": str(res.get("board-name") or "")}
                if not ok:
                    return {"ok": True, **info, "supported": False, "reason": reason,
                            "cloud": _sanitize_cloud(cloud)}

                enabled = cloud.get("back-to-home-vpn") == "enabled"
                users: list[dict] = []
                conn: dict[str, dict] = {}
                if enabled:
                    users = [_sanitize_user(u) for u in (await _get(client, f"{base}{USERS}") or [])
                             if isinstance(u, dict)]
                    # Stan POLACZENIA bierzemy z peerow interfejsu back-to-home-vpn, dopasowanych
                    # po kluczu publicznym. Pole `active` uzytkownika tego nie mowi — jest `true`
                    # od razu po utworzeniu, bez zadnego polaczenia (sprawdzone na sprzecie),
                    # czyli znaczy „konto aktywne", nie „polaczony". Klient domyslny to peer
                    # z kluczem `vpn-peer-public-key` z /ip/cloud.
                    for row in await _get(client, f"{base}/rest/interface/wireguard/peers") or []:
                        if not isinstance(row, dict) or row.get("interface") != cloud.get("vpn-interface", "back-to-home-vpn"):
                            continue
                        p = peer_from_row(row)
                        if p.public_key:
                            conn[p.public_key] = {"status": p.status, "ago": format_ago(p.handshake),
                                                  "endpoint": p.current_endpoint, "rx": p.rx, "tx": p.tx}
                    for u in users:
                        u["conn"] = conn.get(str(u.get("public-key") or ""))
                wg_names = {str(i.get("name")) for i in (await _get(client, f"{base}/rest/interface/wireguard") or [])
                            if isinstance(i, dict)}
                addrs = await _get(client, f"{base}/rest/ip/address") or []
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    return {
        "ok": True, **info, "supported": True, "reason": "",
        "cloud": _sanitize_cloud(cloud), "enabled": enabled, "users": users,
        "default_conn": conn.get(str(cloud.get("vpn-peer-public-key") or "")) if enabled else None,
        "lan_subnets": lan_subnets([a for a in addrs if isinstance(a, dict)], wg_names),
    }


def _client(device: Device) -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=False, timeout=30.0, auth=_auth(device))


async def _check(resp: httpx.Response, what: str):
    if resp.status_code >= 400:
        try:
            data = _json(resp)
            detail = data.get("detail") or data.get("message")
        except Exception:
            detail = resp.text[:200]
        raise RouterError(f"{what}: HTTP {resp.status_code} — {detail}")
    return resp


async def enable(device: Device, ddns_before: str) -> None:
    """BTH wymaga DDNS. Gdy DDNS jest wylaczony, ustawiamy `auto` — DDNS dziala wtedy
    tylko dopoki potrzebuje go BTH. `yes` i `auto` zostawiamy w spokoju: specyfikacja
    mowila o `ddns-enabled=yes`, ale to trwale zmienialoby ustawienie uzytkownika,
    ktory DDNS MikroTika uzywa swiadomie."""
    body = {"back-to-home-vpn": "enabled"}
    if ddns_before == "no":
        body["ddns-enabled"] = "auto"
    async with _device_sem(device):
        async with _client(device) as client:
            await _check(await client.post(f"{_base_url(device)}/rest/ip/cloud/set", json=body),
                         "Włączenie Back To Home")


async def add_user(device: Device, name: str, allow_lan: bool, expires: str) -> dict:
    body = {"name": name, "allow-lan": "yes" if allow_lan else "no"}
    if expires:
        body["expires"] = expires
    async with _device_sem(device):
        async with _client(device) as client:
            base = _base_url(device)
            resp = await _check(await client.post(f"{base}{USERS}/add", json=body), "Dodanie użytkownika BTH")
            new_id = (_json(resp) or {}).get("ret")
            # Klucze pojawiaja sie z opoznieniem — czekamy chwile, zanim uznamy, ze ich nie ma.
            for _ in range(10):
                rows = await _get(client, f"{base}{USERS}") or []
                row = next((u for u in rows if u.get(".id") == new_id), None)
                if row and row.get("public-key"):
                    return _sanitize_user(row)
                await asyncio.sleep(0.5)
            return _sanitize_user(row or {".id": new_id, "name": name})


async def set_user_comment(device: Device, user_id: str, comment: str) -> None:
    async with _device_sem(device):
        async with _client(device) as client:
            await _check(await client.patch(f"{_base_url(device)}{USERS}/{user_id}",
                                            json={"comment": comment}),
                         "Zmiana komentarza użytkownika BTH")


async def user_config(device: Device, user_id: str) -> str:
    async with _device_sem(device):
        async with _client(device) as client:
            resp = await _check(
                await client.post(f"{_base_url(device)}{USERS}/show-client-config", json={".id": user_id}),
                "Odczyt configu BTH")
    data = _json(resp)
    rows = data if isinstance(data, list) else [data]
    for row in rows:
        if isinstance(row, dict) and "[Interface]" in str(row.get("conf", "")):
            return str(row["conf"]).replace("\r\n", "\n")
    raise RouterError("Router nie zwrócił configu użytkownika BTH (brak pola „conf”).")


DEFAULT_UID = "default"


async def default_config(device: Device) -> str:
    """Konfiguracja „zerowa" — ta, ktora router tworzy sam przy wlaczeniu BTH i trzyma
    w /ip/cloud (`vpn-wireguard-client-config`), niezaleznie od listy uzytkownikow.
    Ma wlasny klucz, wiec to pelnoprawny dostep do sieci. Wychodzi tylko przez okno
    configu (administrator, no-store) — `load()` dalej odcina ja na wejsciu."""
    async with _device_sem(device):
        async with _client(device) as client:
            cloud = await _get(client, f"{_base_url(device)}/rest/ip/cloud") or {}
    text = str(cloud.get("vpn-wireguard-client-config") or "").replace("\r\n", "\n")
    if "[Interface]" not in text:
        raise RouterError("Router nie zwrócił konfiguracji domyślnej (czy Back To Home jest włączone?).")
    return text
