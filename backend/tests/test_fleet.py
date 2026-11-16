"""Flota: ostrzezenia o stanie, skrypty akcji przez API, klienci WiFi, strona zbiorcza."""
import asyncio
import datetime
import types
import uuid

import httpx

from app import fleet_actions, fleet_health
from app.routeros_client import parse_wifi_clients
from app.templating import templates

NOW = datetime.datetime(2026, 11, 14, 12, 0, 0)


def dev(name, **kw):
    base = dict(id=uuid.uuid4(), name=name, location=None, location_id=None, routeros_version="7.24.5 (stable)",
                available_routeros_version=None, current_firmware="7.24.5", available_firmware="7.24.5",
                wg_reachable=True, api_reachable=True, last_polled_at=NOW, last_handshake_at=NOW,
                cert_expires_at=NOW + datetime.timedelta(days=3000), board_name="hAP ax2", has_lte=False,
                wg_ip="10.77.0.9", api_username="u", api_password_encrypted="x")
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_warnings_cover_what_used_to_surface_by_symptoms():
    devices = [
        dev("ok"),
        dev("stary-7.13", routeros_version="7.13.5 (stable)"),
        dev("bth-7.16", routeros_version="7.16.2 (stable)"),
        dev("port-www", api_reachable=False),
        dev("zniknal", wg_reachable=False, api_reachable=False, last_handshake_at=NOW - datetime.timedelta(days=20)),
        dev("chwilowo", wg_reachable=False, api_reachable=False, last_handshake_at=NOW - datetime.timedelta(hours=3)),
        dev("nowy", wg_reachable=False, api_reachable=False, last_handshake_at=None, last_polled_at=None),
        dev("cert", cert_expires_at=NOW + datetime.timedelta(days=100)),
        dev("kopie"),
    ]
    found = {w.key: [d.name for d in w.devices]
             for w in fleet_health.warnings(devices, {devices[-1].id: 3}, now=NOW)}
    assert found == {"too_old": ["stary-7.13"], "old": ["bth-7.16"], "api_down": ["port-www"],
                     "offline": ["zniknal"], "never": ["nowy"], "cert": ["cert"], "backup": ["kopie"]}
    assert fleet_health.warnings([dev("ok")], {}, now=NOW) == []


def test_summary_counts():
    devices = [dev("a"), dev("b", api_reachable=False), dev("c", wg_reachable=False, api_reachable=False),
               dev("d", available_routeros_version="7.25"), dev("e", routeros_version="7.16.2 (stable)")]
    s = fleet_health.summary(devices, {devices[0].id: 1})
    assert (s["total"], s["online"], s["wg_only"], s["offline"], s["updates"], s["backup_failures"]) == (5, 3, 1, 1, 1, 1)
    assert s["versions"][0] == ("7.24.5", 4) and s["versions"][1] == ("7.16.2", 1)


def test_cert_date_formats():
    assert fleet_health.parse_cert_date("2036-10-09 15:05:32") == datetime.datetime(2036, 10, 9, 15, 5, 32)
    assert fleet_health.parse_cert_date("oct/09/2036 15:05:32") == datetime.datetime(2036, 10, 9, 15, 5, 32)
    assert fleet_health.parse_cert_date("") is None and fleet_health.parse_cert_date("bzdura") is None


def test_action_scripts_are_single_idempotent_blocks():
    for script in (fleet_actions.log_tidy_script(), fleet_actions.log_clear_script(),
                   fleet_actions.cert_renew_script("10.77.0.9")):
        assert script.startswith("{\n") and script.endswith("}\n") and script.count("{") == script.count("}")
    tidy = fleet_actions.log_tidy_script()
    assert 'find where topics~"info" and action=memory' in tidy      # `find topics=info` zwraca 0 regul
    assert '= "info") do={/system logging set $r topics=info,!account}' in tidy   # cudzych regul nie rusza
    assert 'regex=\\"via (winbox|ssh|web|telnet|ftp)\\"' in tidy and "on-error={}" in tidy
    assert f'find comment="{fleet_actions.LOG_RULE_COMMENT}"' in tidy  # bez dubla przy powtorce
    renew = fleet_actions.cert_renew_script("10.77.0.9")
    assert renew.index("certificate=mtm-cert-new") < renew.index("/certificate remove [find name=mtm-cert]")
    assert set(fleet_actions.ACTIONS) == {"winbox", "log_tidy", "log_clear", "cert_renew"}


def test_run_script_reports_router_error_and_output(monkeypatch):
    def handler(request):
        if request.url.host == "10.77.0.66":
            return httpx.Response(400, json={"detail": "expected end of command (line 2 column 4)"})
        return httpx.Response(200, json={"ret": "progress: |\r\n\r\nprogress: done\r\n\r\nMTM: gotowe\r\n"})
    real = httpx.AsyncClient
    monkeypatch.setattr(fleet_actions.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(fleet_actions, "_auth", lambda d: None)
    good = asyncio.run(fleet_actions.run_script(dev("a"), "{}"))
    bad = asyncio.run(fleet_actions.run_script(dev("b", wg_ip="10.77.0.66"), "{}"))
    none = asyncio.run(fleet_actions.run_script(dev("c", api_username=None), "{}"))
    assert good == {"ok": True, "output": "MTM: gotowe"}
    assert bad == {"ok": False, "output": "expected end of command (line 2 column 4)"}
    assert none["ok"] is False


def test_wifi_clients_joined_with_leases_and_caps():
    rows = [{"mac-address": "aa:bb:cc:00:00:01", "interface": "BUDEX_WIFI1-5-ax", "ssid": "BUDEX", "signal": "-58",
             "uptime": "2h3m", "tx-rate": "270000000", "rx-rate": "130Mbps-20MHz/2S", "band": "5ghz-ax"},
            {"mac-address": "AA:BB:CC:00:00:02", "interface": "wlan1", "signal-strength": "-81dBm@6Mbps", "last-ip": "192.168.1.50"},
            {"interface": "bez-mac"}]
    clients = parse_wifi_clients(rows, {"AA:BB:CC:00:00:01": ("192.168.55.20", "laptop-jan")},
                                 {"BUDEX_WIFI1-5-ax": "operated by CAP 192.168.55.6, traffic processing on CAP"})
    assert len(clients) == 2
    a = next(c for c in clients if c["mac"].endswith("01"))
    assert (a["host"], a["address"], a["signal"], a["cap"][:15]) == ("laptop-jan", "192.168.55.20", -58, "operated by CAP")
    assert (a["tx_rate"], a["rx_rate"]) == ("270 Mbps", "130Mbps-20MHz/2S")  # bity/s z `wifi`, opis ze starego
    b = next(c for c in clients if c["mac"].endswith("02"))
    assert (b["signal"], b["address"], b["host"]) == (-81, "192.168.1.50", None)
    html = templates.get_template("_device_wifi_clients.html").render(r={"ok": True, "supported": True, "clients": clients})
    assert "laptop-jan" in html and "-58 dBm" in html and "pill-bad" in html


def test_fleet_page_renders_with_warnings():
    loc = types.SimpleNamespace(id=uuid.uuid4(), name="BUDEX")
    devices = [dev("ROUTER", location=loc), dev("SWITCH", routeros_version="7.16.2 (stable)", location=loc)]
    for d in devices:
        d.__dict__["location"] = loc
    req = types.SimpleNamespace(state=types.SimpleNamespace(user=types.SimpleNamespace(role="admin", username="a"),
                                                            nav_locations=[]), url=types.SimpleNamespace(path="/fleet"))
    html = templates.get_template("fleet.html").render(
        request=req, devices=devices, summary=fleet_health.summary(devices, {}),
        warnings=fleet_health.warnings(devices, {}, now=NOW), backup_failures={}, actions=fleet_actions.ACTIONS,
        jobs={"update": ("Aktualizuj", "opis")}, update_available=fleet_health.update_available, note=None, error=None)
    assert "BUDEX / SWITCH" in html and "RouterOS starszy niż 7.18" in html
    assert html.count('name="device_ids"') == 2 and 'value="log_tidy"' in html and 'value="update"' in html
