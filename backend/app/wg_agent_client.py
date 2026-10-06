import asyncio

import httpx

from app.config import settings

# Zestaw peerow na hubie zmieniaja: odtwarzanie kopii (dokladanie wszystkich z bazy),
# usuwanie urzadzenia i usuwanie peera administracyjnego. Bez wspolnej blokady odtwarzanie
# czytalo liste z bazy, admin w tym czasie usuwal peera (z huba i z bazy), a odtwarzanie
# dokladalo go z powrotem — odebrany dostep wracal (wytkniete w trzeciej recenzji).
# Kto usuwa: blokada od remove_peer do commitu bazy. Odtwarzanie: od odczytu bazy do
# ostatniego add_peer. Jeden proces uvicorna, wiec asyncio.Lock wystarcza.
hub_peers_lock = asyncio.Lock()

_BASE_URL = "http://wireguard:9090"
_HEADERS = {"X-Agent-Token": settings.wg_agent_token}
_TIMEOUT = 5.0


async def add_peer(public_key: str, allowed_ip: str, preshared_key: str | None = None) -> tuple[bool, str | None]:
    body = {"public_key": public_key, "allowed_ip": allowed_ip}
    if preshared_key:
        body["preshared_key"] = preshared_key
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(f"{_BASE_URL}/peers", json=body, headers=_HEADERS)
            resp.raise_for_status()
            return True, None
    except Exception as e:
        return False, str(e)


async def remove_peer(public_key: str) -> tuple[bool, str | None]:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.request(
                "DELETE", f"{_BASE_URL}/peers", json={"public_key": public_key}, headers=_HEADERS
            )
            resp.raise_for_status()
            return True, None
    except Exception as e:
        return False, str(e)


async def get_peers() -> tuple[list[dict] | None, str | None]:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{_BASE_URL}/peers", headers=_HEADERS)
            resp.raise_for_status()
            return resp.json(), None
    except Exception as e:
        return None, str(e)


async def get_interface_status() -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{_BASE_URL}/status", headers=_HEADERS)
            resp.raise_for_status()
            return resp.json()
    except Exception:
        return None


async def setup_interface(subnet: str, server_ip: str, private_key: str | None = None) -> tuple[str | None, str | None]:
    """Prosi agenta o postawienie wg-mt (podsieć + opcjonalnie odtworzony klucz).
    Zwraca (public_key, error). Timeout wydłużony — wg-quick up bywa wolne."""
    payload = {"subnet": subnet, "server_ip": server_ip}
    if private_key:
        payload["private_key"] = private_key
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{_BASE_URL}/setup", json=payload, headers=_HEADERS)
            resp.raise_for_status()
            return resp.json().get("public_key"), None
    except Exception as e:
        return None, str(e)


async def get_private_key() -> str | None:
    """Klucz prywatny huba wg-mt — potrzebny do kopii całego portalu."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{_BASE_URL}/privatekey", headers=_HEADERS)
            resp.raise_for_status()
            return resp.json().get("private_key")
    except Exception:
        return None
