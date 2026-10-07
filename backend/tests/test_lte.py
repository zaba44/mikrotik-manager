"""Modem LTE/5G (app/lte.py) — na odpowiedzi REST z prawdziwego routera.

Probka: hAP ax lite LTE6 (Fibocom FG621-EA, RouterOS 7.24.5), `POST /rest/interface/lte/monitor`
z once. Identyfikatory abonenta i modemu ZASTAPIONE wymyslonymi — prawdziwe nie trafiaja do repo.
"""
import types

import pytest

from app import lte

REST_SAMPLE = [{
    "current-cellid": "2314010", "current-operator": "Play", "data-class": "LTE", "enb-id": "9039",
    "iccid": "ICCID-TESTOWY-0000", "imei": "IMEI-TESTOWY-0000", "imsi": "IMSI-TESTOWY-0000",
    "model": "FG621-EA", "phy-cellid": "345", "primary-band": "B3@15Mhz earfcn: 1875 phy-cellid: 345",
    "revision": "16121.1034.00.01.01.10", "rsrp": "-107", "rsrq": "-13.5", "rssi": "-79",
    "sector-id": "26", "session-uptime": "3m54s", "sinr": "1", "status": "running",
}]
SECRETS = ("ICCID-TESTOWY-0000", "IMEI-TESTOWY-0000", "IMSI-TESTOWY-0000")


def test_identifiers_never_leave_the_parser():
    parsed = lte.parse_monitor(REST_SAMPLE)
    assert not any(s in repr(parsed) for s in SECRETS)
    assert not any(k in repr(parsed).lower() for k in ("'imei'", "'imsi'", "'iccid'"))


def test_signal_values_and_ratings():
    sig = {s["key"]: s for s in lte.parse_monitor(REST_SAMPLE)["signals"]}
    assert sig["rsrp"]["value"] == -107 and sig["rsrp"]["rating"] == ("bad", "bardzo słaby")
    assert sig["sinr"]["value"] == 1 and sig["sinr"]["rating"] == ("warn", "słaby")
    assert sig["rsrq"]["value"] == -13.5 and sig["rsrq"]["rating"] == ("ok", "dobry")
    assert sig["rssi"]["rating"] is None  # RSSI w LTE malo mowi — bez oceny
    assert lte.parse_monitor(REST_SAMPLE)["worst"] == "bad"


@pytest.mark.parametrize("key,value,level", [
    ("rsrp", -79, "ok"), ("rsrp", -80, "ok"), ("rsrp", -95, "warn"), ("rsrp", -101, "bad"),
    ("sinr", 25, "ok"), ("sinr", 13, "ok"), ("sinr", 0, "warn"), ("sinr", -3, "bad"),
    ("rsrq", -9, "ok"), ("rsrq", -21, "bad"),
])
def test_rating_thresholds(key, value, level):
    assert lte.rate(key, value)[0] == level


@pytest.mark.parametrize("raw,num", [("-107", -107.0), ("-107dBm", -107.0), ("-13.5", -13.5), ("abc", None), (None, None)])
def test_number_with_or_without_unit(raw, num):
    assert lte.number(raw) == num


def test_fields_band_and_other():
    p = lte.parse_monitor(REST_SAMPLE)
    fields = dict(p["fields"])
    assert fields["Operator"] == "Play" and fields["Firmware modemu"] == "16121.1034.00.01.01.10"
    assert fields["Czas sesji"] == "3m54s" and fields["Technologia"] == "LTE"
    assert p["primary_band"] == {"band": "B3", "width": "15 MHz", "earfcn": "1875"}
    assert p["ca_bands"] == [] and p["other"] == []


@pytest.mark.parametrize("raw,expected", [
    ("B20@10Mhz earfcn: 6300 phy-cellid: 12,B1@20Mhz earfcn: 300 phy-cellid: 4", ["B20", "B1"]),
    ("n78@100Mhz arfcn: 650000", ["n78"]),
    ("B7@2.5Mhz", ["B7"]),
    ("nieznany format", ["nieznany format"]),
])
def test_bands_any_separator(raw, expected):
    assert [b["band"] for b in lte.bands(raw)] == expected


def test_unknown_5g_fields_go_to_other_and_missing_are_fine():
    p = lte.parse_monitor({"status": "running", "nr-rsrp": "-90", "nr-sinr": "15", "imsi": "X"})
    assert ("nr-rsrp", "-90") in p["other"] and ("nr-sinr", "15") in p["other"]
    assert p["signals"] == [] and p["primary_band"] is None and p["worst"] is None
    assert "X" not in repr(p)
    assert lte.parse_monitor([])["fields"] == []


def test_template_shows_signal_and_hides_identifiers():
    from app.templating import templates
    request = types.SimpleNamespace(state=types.SimpleNamespace(user=types.SimpleNamespace(role="admin")))
    r = {"ok": True, "modems": [{"name": "lte1", "running": True, "disabled": False, "network_mode": "3g,lte",
                                 "allow_roaming": "false", "error": None, "monitor": lte.parse_monitor(REST_SAMPLE)}]}
    html = templates.env.get_template("_device_lte.html").render(request=request, device=types.SimpleNamespace(id="x"), r=r)
    assert "-107 dBm" in html and "bardzo słaby" in html and "Play" in html and "B3" in html
    assert "Sprawdź firmware modemu" in html
    assert not any(s in html for s in SECRETS)


def test_template_without_modem():
    from app.templating import templates
    request = types.SimpleNamespace(state=types.SimpleNamespace(user=None))
    html = templates.env.get_template("_device_lte.html").render(request=request, device=types.SimpleNamespace(id="x"),
                                                                 r={"ok": True, "modems": []})
    assert "nie ma modemu" in html
