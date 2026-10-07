"""Skrypt rejestracji urzadzenia (wklejany na routerze)."""
from app.routers.devices import build_routeros_script


def _script(monkeypatch):
    from app.routers import devices
    monkeypatch.setattr(devices.wg, "subnet", "10.77.0.0/22")
    monkeypatch.setattr(devices.wg, "server_ip", "10.77.0.1")
    monkeypatch.setattr(devices.wg, "hub_endpoint", "hub.example.org")
    monkeypatch.setattr(devices.wg, "server_public_key", "PUBHUB=")
    return build_routeros_script(device_name="Biuro", client_private_key="PRIV=", device_ip="10.77.0.2",
                                 api_username="mtm-api", api_password="haslo", preshared_key="PSK=")


def test_certificate_signed_before_https_service_uses_it(monkeypatch):
    """`/ip service set www-ssl certificate=` przyjmuje tylko podpisany certyfikat — dawniej
    `sign` stal na koncu i na czesci routerow REST zostawal niedostepny."""
    last = [l for l in _script(monkeypatch).splitlines() if l.strip()][-1]
    assert last.index("/certificate sign mtm-cert") < last.index("/ip service set www-ssl")


def test_nothing_follows_certificate_sign(monkeypatch):
    """Terminal RouterOS w trakcie `sign` polyka reszte wklejonego tekstu — po linii z
    podpisem nie moze byc juz zadnego polecenia (wczesniej ginely usluga i firewall)."""
    lines = [l for l in _script(monkeypatch).splitlines() if l.strip()]
    sign_line = next(i for i, l in enumerate(lines) if "/certificate sign" in l)
    assert sign_line == len(lines) - 1
    firewall = [i for i, l in enumerate(lines) if "/ip firewall filter add" in l]
    assert len(firewall) == 2 and max(firewall) < sign_line


def test_firewall_rules_work_with_empty_filter_list(monkeypatch):
    """`place-before=0` przy pustej liscie regul to „no such item" — regula nie powstawala
    (switch CRS). Kazda regula ma galaz z place-before i bez, w jednej linii."""
    rules = [l for l in _script(monkeypatch).splitlines() if "/ip firewall filter add" in l]
    for line in rules:
        assert line.startswith(":if ([:len [/ip firewall filter find]] > 0) do={")
        do, other = line.split("} else={")
        assert "place-before=0" in do and "place-before" not in other
        assert do.split("do={")[1].replace(" place-before=0", "") == other.rstrip("}")


def test_certificate_line_waits_for_private_key(monkeypatch):
    last = [l for l in _script(monkeypatch).splitlines() if l.strip()][-1]
    assert ":while (([/certificate get [find name=mtm-cert] private-key] != true) && ($w < 60))" in last
    assert last.index(":while") < last.index("/ip service set www-ssl")


def test_script_uses_configured_hub(monkeypatch):
    s = _script(monkeypatch)
    assert "endpoint-address=hub.example.org" in s and "address=10.77.0.2/22 interface=wg-mt" in s
    assert "www-ssl address=10.77.0.1/32" in s and 'preshared-key="PSK="' in s
