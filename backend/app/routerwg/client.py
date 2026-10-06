"""Odczyt WireGuarda z routera przez REST.

REST, a nie binarne API RouterOS (8728/8729), z ktorego korzystala implementacja
referencyjna: nasze routery wystawiaja na tunelu wylacznie `www-ssl`, a otwarcie portu API
oznaczaloby zmiane firewalla na calej flocie. REST z obecnym kontem oddaje pola wrazliwe
(sprawdzone: `preshared-key` przychodzi w calosci), wiec `show-sensitive` nie jest potrzebne.
"""
from __future__ import annotations

import httpx

from app.models import Device
from app.routeros_client import _auth, _base_url, _device_sem, _json
from app.routerwg.model import (
    SUPPORT_NONE,
    build_interfaces,
    peer_from_row,
    support_level,
)


class RouterError(Exception):
    pass


async def _get(client: httpx.AsyncClient, url: str):
    """GET z jawnym sprawdzeniem kodu. Samo `_json()` przyjmie odpowiedz bledu jako
    slownik, a iteracja po nim dalaby pusta liste — blad routera wygladalby jak „brak
    interfejsow WireGuard", czyli jak prawda."""
    resp = await client.get(url)
    if resp.status_code >= 400:
        try:
            detail = _json(resp).get("detail") or _json(resp).get("message")
        except Exception:
            detail = resp.text[:200]
        raise RouterError(f"HTTP {resp.status_code} przy {url.split('/rest', 1)[-1]}: {detail}")
    return _json(resp)


async def load(device: Device) -> dict:
    """Jeden spojny odczyt: wersja, interfejsy, peery, adresy. Cztery zapytania w jednej
    sesji HTTP, pod semaforem urzadzenia — przy 200+ peerach to nadal jedno GET na peery."""
    if not device.api_username or not device.api_password_encrypted:
        return {"ok": False, "error": "Brak danych API dla tego urządzenia."}
    try:
        async with _device_sem(device):
            async with httpx.AsyncClient(verify=False, timeout=25.0, auth=_auth(device)) as client:
                base = _base_url(device)
                res = await _get(client, f"{base}/rest/system/resource") or {}
                version = str(res.get("version") or "")
                level = support_level(version)
                info = {
                    "version": version,
                    "arch": str(res.get("architecture-name") or ""),
                    "board": str(res.get("board-name") or ""),
                    "level": level,
                }
                if level == SUPPORT_NONE:
                    return {"ok": True, **info, "interfaces": [], "peers": []}

                if_rows = await _get(client, f"{base}/rest/interface/wireguard") or []
                peer_rows = await _get(client, f"{base}/rest/interface/wireguard/peers") or []
                addr_rows = await _get(client, f"{base}/rest/ip/address") or []
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    peers = [peer_from_row(r) for r in peer_rows if isinstance(r, dict)]
    interfaces = build_interfaces(
        [r for r in if_rows if isinstance(r, dict)], peers,
        [r for r in addr_rows if isinstance(r, dict)], str(device.wg_ip),
    )
    return {"ok": True, **info, "interfaces": interfaces, "peers": peers}
