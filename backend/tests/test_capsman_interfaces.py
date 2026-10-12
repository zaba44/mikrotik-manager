"""Interfejsy WiFi capow na routerze z CAPsMAN-em: ruch obsluguje cap, wiec running=false —
portal pokazywal je jako „down". Dane z zywego routera (RouterOS 7.24, wifi/CAPsMAN)."""
from app.routeros_client import on_cap
from app.templating import templates

CAP_IFACE = {"name": "BUDEX_WIFI1-2-ax", "type": "wifi", "running": "false", "disabled": "false", "dynamic": "true",
             "about": "operated by CAP 192.168.55.6, traffic processing on CAP"}


def test_cap_interface_recognised():
    assert on_cap(CAP_IFACE)
    assert not on_cap({"name": "ether1", "running": "false"})
    assert not on_cap({"name": "x", "about": "managed by CAPsMAN"})


def test_cap_interface_rendered_as_on_cap_not_down():
    row = {"name": CAP_IFACE["name"], "comment": None, "type": "wifi", "running": False, "disabled": False,
           "on_cap": True, "about": CAP_IFACE["about"], "mtu": None, "rate": None, "rx_byte": 0, "tx_byte": 0}
    down = dict(row, name="ether9", on_cap=False, about=None, type="ether")
    html = templates.get_template("_device_interfaces.html").render(h={"ok": True, "interfaces": [row, down]})
    cap_row, eth_row = html.split("BUDEX_WIFI1-2-ax")[1].split("ether9")
    assert "na CAP" in cap_row and "down" not in cap_row
    assert "operated by CAP 192.168.55.6" in cap_row
    assert "down" in eth_row
