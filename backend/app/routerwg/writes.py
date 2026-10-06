"""Zapisy WireGuarda na routerach — WYLACZNIE z listy dozwolonych (specyfikacja, zasada 2):
nowy tunel z peerami, dodanie N peerow, uzupelnienie pol client-* z plikow .conf, komentarz.
Wylaczanie, usuwanie, wymiana kluczy i inna edycja — poza zakresem.

Empiria z Krok 0 na punkcie dostepowym wAP ax (7.23.2), na tymczasowym interfejsie testowym:
  * `PUT` interfejsu bez private-key -> router sam generuje pare kluczy (pasujaca, X25519).
  * peer z `private-key=auto` ma klucz OD RAZU, a public-key do niego pasuje.
  * `client-endpoint` przyjmuje i host, i host:port — zapisuje dokladnie to, co dostal.
  * **Zapis NIEPASUJACEGO private-key na istniejacym peerze po cichu przelicza jego
    public-key** (HTTP 200, zero ostrzezen). Prawdziwy klient traci polaczenie w tej samej
    sekundzie. Dlatego klucz z pliku zapisujemy tylko po kontroli X25519 (import.py),
    a po zapisie sprawdzamy jeszcze raz.
  * Cofniecie dziala: `PATCH public-key=<stary>` przywraca klucz i sam czysci bledny
    private-key.
  * `place-before=<.id>` w `PUT` reguly firewalla wstawia ja we wskazane miejsce.
"""
from __future__ import annotations

import base64
import ipaddress
import os

import httpx

from app.models import Device
from app.routeros_client import _auth, _base_url, _device_sem, _json
from app.routerwg.client import RouterError

PEERS = "/rest/interface/wireguard/peers"


def new_psk() -> str:
    """PSK to po prostu 32 losowe bajty w base64 — zadnej kryptografii po stronie portalu."""
    return base64.b64encode(os.urandom(32)).decode()


def _client(device: Device) -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=False, timeout=30.0, auth=_auth(device))


def _err(resp: httpx.Response) -> str:
    try:
        data = _json(resp)
        return str(data.get("detail") or data.get("message") or resp.text[:200])
    except Exception:
        return resp.text[:200]


async def set_peer_comment(device: Device, peer_id: str, comment: str) -> None:
    async with _device_sem(device):
        async with _client(device) as c:
            r = await c.patch(f"{_base_url(device)}{PEERS}/{peer_id}", json={"comment": comment})
            if r.status_code >= 400:
                raise RouterError(f"HTTP {r.status_code}: {_err(r)}")


async def add_peers(device: Device, iface_name: str, plan: list[dict], p: dict) -> list[dict]:
    """Dodaje peery po kolei. Przy bledzie przerywamy BEZ cofania (usuwanie jest poza
    zakresem) — raport pokazuje dokladnie, co zostalo dodane, a co nie."""
    results = []
    async with _device_sem(device):
        async with _client(device) as c:
            base = _base_url(device)
            for item in plan:
                body = {
                    "interface": iface_name,
                    "allowed-address": f"{item['ip']}/32",
                    "client-address": f"{item['ip']}/{item['prefixlen']}",
                    "private-key": "auto",
                    "name": item["name"],
                    "comment": item["name"],
                }
                if p.get("psk"):
                    body["preshared-key"] = new_psk()
                if p.get("dns"):
                    body["client-dns"] = p["dns"]
                if p.get("endpoint"):
                    body["client-endpoint"] = p["endpoint"]
                if p.get("keepalive"):
                    body["client-keepalive"] = f"{int(p['keepalive'])}s"
                if p.get("client_allowed"):
                    body["client-allowed-address"] = p["client_allowed"]
                if p.get("responder"):
                    body["responder"] = "yes"
                try:
                    r = await c.put(f"{base}{PEERS}", json=body)
                except Exception as e:
                    results.append({**item, "ok": False, "error": f"{type(e).__name__}: {e}"})
                    break
                if r.status_code >= 400:
                    results.append({**item, "ok": False, "error": _err(r)})
                    break
                row = _json(r) or {}
                results.append({**item, "ok": True, "id": row.get(".id"),
                                "has_key": bool(row.get("private-key")), "error": None})
    return results


async def create_tunnel(device: Device, t: dict, firewall_before: str | None) -> tuple[list[str], bool]:
    """Interfejs (klucz generuje router), adres, opcjonalnie: regula accept PRZED pierwszym
    dropem, maskarada do bridge'a, czlonkostwo w liscie interfejsow. Zwraca raport krokow;
    pierwszy blad przerywa — bez cofania, jak przy peerach."""
    report = []
    async with _device_sem(device):
        async with _client(device) as c:
            base = _base_url(device)

            async def put(path: str, body: dict, label: str):
                r = await c.put(f"{base}{path}", json=body)
                if r.status_code >= 400:
                    raise RouterError(f"{label}: HTTP {r.status_code} — {_err(r)}")
                report.append(f"{label}: OK")
                return _json(r) or {}

            net: ipaddress.IPv4Network = t["network"]
            server = f"{next(net.hosts())}/{net.prefixlen}"
            try:
                await _steps(put, t, net, server, firewall_before)
            except (RouterError, httpx.HTTPError) as e:
                report.append(f"BŁĄD — {e}")
                return report, False
    return report, True


async def _steps(put, t: dict, net: ipaddress.IPv4Network, server: str, firewall_before: str | None) -> None:
    await put("/rest/interface/wireguard", {"name": t["name"], "listen-port": t["port"]},
              f"interfejs {t['name']} (port {t['port']})")
    await put("/rest/ip/address", {"address": server, "interface": t["name"]}, f"adres {server}")
    if t.get("firewall"):
        rule = {"chain": "input", "action": "accept", "protocol": "udp",
                "dst-port": t["port"], "comment": f"accept {t['name']}"}
        if firewall_before:
            rule["place-before"] = firewall_before
        await put("/rest/ip/firewall/filter", rule,
                  "reguła accept UDP " + ("przed pierwszym drop" if firewall_before else "na końcu łańcucha input"))
    if t.get("masquerade") and t.get("bridge"):
        await put("/rest/ip/firewall/nat", {"chain": "srcnat", "src-address": str(net),
                                            "out-interface": t["bridge"], "action": "masquerade",
                                            "comment": f"Masquerade {t['name']} to LAN"},
                  f"maskarada {net} → {t['bridge']}")
    if t.get("iflist") and t.get("list_name"):
        await put("/rest/interface/list/member", {"interface": t["name"], "list": t["list_name"]},
                  f"członkostwo w liście {t['list_name']}")


async def read_rows(device: Device, *paths: str) -> list:
    """Pomocniczy odczyt kilku menu naraz (firewall, bridge, listy) do formularzy."""
    out = []
    async with _device_sem(device):
        async with _client(device) as c:
            for path in paths:
                r = await c.get(f"{_base_url(device)}{path}")
                out.append(_json(r) if r.status_code < 400 else [])
    return out


async def apply_import(device: Device, items: list[dict]) -> list[dict]:
    """Zapisuje pola client-* (i private-key, gdy go brak) peer po peerze. Po wpisaniu
    klucza prywatnego czytamy peera jeszcze raz: gdyby public-key mimo kontroli X25519 sie
    zmienil, natychmiast przywracamy stary — sprawdzone na sprzecie, ze `PATCH public-key`
    przywraca klucz i sam czysci bledny private-key."""
    report = []
    async with _device_sem(device):
        async with _client(device) as c:
            base = _base_url(device)
            for item in items:
                peer, changes = item["peer"], item["changes"]
                entry = {"label": item["label"], "peer": peer.display_name, "fields": list(changes), "ok": False}
                try:
                    r = await c.patch(f"{base}{PEERS}/{peer.id}", json=changes)
                    if r.status_code >= 400:
                        entry["error"] = _err(r)
                        report.append(entry)
                        continue
                    if "private-key" in changes:
                        rows = _json(await c.get(f"{base}{PEERS}")) or []
                        now = next((x for x in rows if x.get(".id") == peer.id), {})
                        if now.get("public-key") and now.get("public-key") != peer.public_key:
                            await c.patch(f"{base}{PEERS}/{peer.id}", json={"public-key": peer.public_key})
                            entry["error"] = ("router zmienił klucz publiczny — PRZYWRÓCONO poprzedni "
                                              "(klucz prywatny wyczyszczony); sprawdź peera")
                            report.append(entry)
                            continue
                    entry["ok"] = True
                except httpx.HTTPError as e:
                    entry["error"] = f"{type(e).__name__}: {e}"
                report.append(entry)
    return report
