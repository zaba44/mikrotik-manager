"""Zmiana adresu tunelu DZIALAJACEGO urzadzenia — przeniesienie do bloku administracyjnego
albo z powrotem, bez ponownej rejestracji i bez wizyty na miejscu.

Kolejnosc jest tak ulozona, zeby w zadnej chwili router nie zostal bez drogi do portalu:

1. router dostaje DRUGI adres na wg-mt (po starym nadal odpowiada),
2. hub przelacza peera na nowy adres (stary przestaje dzialac — to jedyny krok bez odwrotu
   w locie, dlatego nastepny go sprawdza),
3. portal pyta router PO NOWYM adresie; dopiero gdy odpowie, stary adres znika z routera
   i z bazy.

Gdy krok 3 sie nie uda, hub wraca na stary adres i drugi adres jest zdejmowany z routera.
"""
import asyncio
import ipaddress

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app import admin_block
from app.models import Device
from app.routeros_client import _auth, _device_sem
from app.security import allocate_admin_ip, allocate_ip, decrypt
from app.wg_agent_client import add_peer, hub_peers_lock
from app.wg_config import wg

COMMENT = "MTM: adres tunelu"


class ReaddressError(Exception):
    pass


async def _answers(client: httpx.AsyncClient, ip: str, attempts: int = 8) -> bool:
    for _ in range(attempts):
        try:
            if (await client.get(f"https://{ip}/rest/system/identity")).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        await asyncio.sleep(2)
    return False


async def _wg_addresses(client: httpx.AsyncClient, ip: str) -> list[dict]:
    resp = await client.get(f"https://{ip}/rest/ip/address")
    resp.raise_for_status()
    return [a for a in resp.json() if a.get("interface") == "wg-mt"]


async def is_admin_device(session: AsyncSession, device: Device) -> bool:
    return ipaddress.ip_address(device.wg_ip) in await admin_block.get_block(session)


async def move(session: AsyncSession, device: Device, to_admin: bool) -> str:
    """Przenosi urzadzenie do bloku administracyjnego (albo poza niego). Zwraca nowy adres.
    Wolajacy zatwierdza transakcje — przydzial adresu trzyma blokade puli do commitu."""
    if not device.api_username or not device.api_password_encrypted:
        raise ReaddressError("Urządzenie nie ma danych API — zmiana adresu wymaga działającego API.")
    old = str(device.wg_ip)
    new = await (allocate_admin_ip if to_admin else allocate_ip)(session)
    psk = decrypt(device.wg_preshared_key_encrypted) if device.wg_preshared_key_encrypted else None

    async with _device_sem(device), httpx.AsyncClient(verify=False, timeout=10.0, auth=_auth(device)) as client:
        try:
            before = await _wg_addresses(client, old)
        except httpx.HTTPError as e:
            raise ReaddressError(f"Router nie odpowiada przez API ({type(e).__name__}) — nic nie zmieniono.")
        if not any(a.get("address", "").split("/")[0] == new for a in before):
            resp = await client.put(f"https://{old}/rest/ip/address", json={
                "address": f"{new}/{wg.mask}", "interface": "wg-mt", "comment": COMMENT})
            if resp.status_code >= 400:
                raise ReaddressError(f"Router odrzucił nowy adres (HTTP {resp.status_code}) — nic nie zmieniono.")

        async with hub_peers_lock:
            ok, error = await add_peer(device.wg_public_key, new, psk)
            if not ok:
                await _drop_address(client, old, new)
                raise ReaddressError(f"Hub nie przyjął nowego adresu ({error}) — nic nie zmieniono.")
            if not await _answers(client, new):
                back, back_error = await add_peer(device.wg_public_key, old, psk)
                if back:
                    await _drop_address(client, old, new)
                    raise ReaddressError("Router nie odpowiedział po nowym adresie — przywrócono stary, "
                                         "nic nie zmieniono.")
                raise ReaddressError(
                    f"Router nie odpowiedział po nowym adresie, a hub nie wrócił na stary ({back_error}). "
                    f"Przywróć ręcznie: wg set wg-mt peer {device.wg_public_key} allowed-ips {old}/32")
            device.wg_ip = new
        # Stary adres zdejmujemy juz po nowym. Gdyby sie nie udalo — zostaje nieszkodliwy
        # drugi adres na routerze; hub i tak kieruje do niego tylko nowy.
        await _drop_address(client, new, old)
    return new


async def _drop_address(client: httpx.AsyncClient, via: str, address: str) -> None:
    try:
        for a in await _wg_addresses(client, via):
            if a.get("address", "").split("/")[0] == address:
                await client.delete(f"https://{via}/rest/ip/address/{a['.id']}")
    except httpx.HTTPError:
        pass
