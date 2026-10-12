"""Interfejsy WiFi capow na routerze z CAPsMAN-em: ruch obsluguje cap, wiec running=false —
portal pokazywal je jako „down". Dane z zywego routera (RouterOS 7.24, wifi/CAPsMAN), z REST:
pole nazywa sie tam `.about`, nie `about` (0.7.9 szukala `about` i nic nie zmienila)."""
from app.routeros_client import on_cap
from app.templating import templates

CAP_IFACE = {"name": "BUDEX_WIFI1-2-ax", "type": "wifi", "running": "false", "disabled": "false", "dynamic": "true",
             ".about": "operated by CAP 192.168.55.6, traffic processing on CAP"}


def test_cap_interface_recognised():
    assert on_cap(CAP_IFACE)
    assert not on_cap({"name": "ether1", "running": "false"})
    assert not on_cap({"name": "x", ".about": "managed by CAPsMAN"})
    assert on_cap({"name": "y", "about": CAP_IFACE[".about"]})  # postac z terminala


def test_cap_interface_rendered_as_on_cap_not_down():
    row = {"name": CAP_IFACE["name"], "comment": None, "type": "wifi", "running": False, "disabled": False,
           "on_cap": True, "about": CAP_IFACE[".about"], "mtu": None, "rate": None, "rx_byte": 0, "tx_byte": 0}
    down = dict(row, name="ether9", on_cap=False, about=None, type="ether")
    html = templates.get_template("_device_interfaces.html").render(h={"ok": True, "interfaces": [row, down]})
    cap_row, eth_row = html.split("BUDEX_WIFI1-2-ax")[1].split("ether9")
    assert "na CAP" in cap_row and "down" not in cap_row
    assert "operated by CAP 192.168.55.6" in cap_row
    assert "down" in eth_row
    assert "None" not in html  # brak MTU (interfejs capa) jako „—", nie „None"


def test_rest_payload_flows_to_interface_row(monkeypatch):
    """Cala sciezka od odpowiedzi REST (klucz `.about`) do wiersza tabeli."""
    import asyncio
    import types
    from app import routeros_client

    class _Resp:
        def __init__(self, data):
            self._data = data

        def raise_for_status(self):
            pass

        def json(self):
            return self._data

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, *a, **kw):
            if url.endswith("/rest/interface"):
                return _Resp([CAP_IFACE, {"name": "ether1", "type": "ether", "running": "true", "disabled": "false"}])
            if url.endswith("/system/resource"):
                return _Resp({"version": "7.24.5"})
            return _Resp([])

        async def post(self, url, *a, **kw):
            return _Resp([])

    monkeypatch.setattr(routeros_client.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(routeros_client, "_auth", lambda d: None)
    device = types.SimpleNamespace(id=1, wg_ip="10.77.0.7", api_username="u", api_password_encrypted="x")
    h = asyncio.run(routeros_client._get_device_health_once(device, True))
    rows = {i["name"]: i for i in h["interfaces"]}
    assert rows["BUDEX_WIFI1-2-ax"]["on_cap"] and rows["BUDEX_WIFI1-2-ax"]["about"].startswith("operated by CAP")
    assert not rows["ether1"]["on_cap"]
