"""Zmiana adresu tunelu dzialajacego urzadzenia (zwykle <-> administracyjne): kolejnosc krokow
i cofanie, gdy router nie odpowie po nowym adresie."""
import asyncio
import types

import httpx
import pytest

from app import readdress

OLD, NEW = "10.77.0.7", "10.77.3.250"


def _setup(monkeypatch, *, new_answers=True, hub_ok=True):
    log, addresses = [], [{".id": "*1", "address": f"{OLD}/22", "interface": "wg-mt"}]
    hub = {"ip": OLD}

    def handler(request):
        ip, path = request.url.host, request.url.path
        if ip != hub["ip"] or (ip == NEW and not new_answers):
            raise httpx.ConnectError("brak trasy", request=request)
        if path == "/rest/ip/address" and request.method == "GET":
            return httpx.Response(200, json=addresses)
        if path == "/rest/ip/address" and request.method == "PUT":
            addresses.append({".id": "*2", "address": f"{NEW}/22", "interface": "wg-mt"})
            log.append("router+nowy")
            return httpx.Response(201, json={})
        if path.startswith("/rest/ip/address/") and request.method == "DELETE":
            gone = next(a for a in addresses if a[".id"] == path.rsplit("/", 1)[1])
            addresses.remove(gone)
            log.append("router-" + ("stary" if gone["address"].startswith(OLD) else "nowy"))
            return httpx.Response(204)
        return httpx.Response(200, json={"name": "r"})

    real = httpx.AsyncClient
    monkeypatch.setattr(readdress.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler)))

    async def add_peer(key, ip, psk=None):
        if not hub_ok:
            return False, "agent nie odpowiada"
        hub["ip"] = ip
        log.append(f"hub->{'nowy' if ip == NEW else 'stary'}")
        return True, None

    async def alloc(session):
        return NEW

    async def no_sleep(_):
        return None
    monkeypatch.setattr(readdress, "add_peer", add_peer)
    monkeypatch.setattr(readdress, "allocate_admin_ip", alloc)
    monkeypatch.setattr(readdress, "_auth", lambda d: None)
    monkeypatch.setattr(readdress.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(readdress.wg, "subnet", "10.77.0.0/22")
    device = types.SimpleNamespace(id=1, wg_ip=OLD, wg_public_key="PUB", api_username="u",
                                   api_password_encrypted="x", wg_preshared_key_encrypted=None)
    return device, log, addresses


def test_move_adds_second_address_switches_hub_then_drops_old(monkeypatch):
    device, log, addresses = _setup(monkeypatch)
    assert asyncio.run(readdress.move(None, device, True)) == NEW
    assert log == ["router+nowy", "hub->nowy", "router-stary"]
    assert device.wg_ip == NEW and [a["address"] for a in addresses] == [f"{NEW}/22"]


def test_router_silent_on_new_address_rolls_everything_back(monkeypatch):
    device, log, addresses = _setup(monkeypatch, new_answers=False)
    with pytest.raises(readdress.ReaddressError, match="przywrócono stary"):
        asyncio.run(readdress.move(None, device, True))
    assert log == ["router+nowy", "hub->nowy", "hub->stary", "router-nowy"]
    assert device.wg_ip == OLD and [a["address"] for a in addresses] == [f"{OLD}/22"]


def test_hub_refusal_leaves_router_untouched(monkeypatch):
    device, log, addresses = _setup(monkeypatch, hub_ok=False)
    with pytest.raises(readdress.ReaddressError, match="Hub nie przyjął"):
        asyncio.run(readdress.move(None, device, True))
    assert log == ["router+nowy", "router-nowy"] and device.wg_ip == OLD
