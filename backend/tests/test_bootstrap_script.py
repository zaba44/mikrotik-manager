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
    lines = _script(monkeypatch).splitlines()
    sign = next(i for i, l in enumerate(lines) if l.startswith("/certificate sign mtm-cert"))
    service = next(i for i, l in enumerate(lines) if l.startswith("/ip service set www-ssl"))
    add = next(i for i, l in enumerate(lines) if l.startswith("/certificate add name=mtm-cert"))
    assert add < sign < service


def test_script_uses_configured_hub(monkeypatch):
    s = _script(monkeypatch)
    assert "endpoint-address=hub.example.org" in s and "address=10.77.0.2/22 interface=wg-mt" in s
    assert "www-ssl address=10.77.0.1/32" in s and 'preshared-key="PSK="' in s
