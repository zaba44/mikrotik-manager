"""Skrypt rejestracji urzadzenia (wklejany na routerze)."""
from app.routers.devices import _VERSION_CHECK, build_routeros_script


def _script(monkeypatch):
    from app.routers import devices
    monkeypatch.setattr(devices.wg, "subnet", "10.77.0.0/22")
    monkeypatch.setattr(devices.wg, "server_ip", "10.77.0.1")
    monkeypatch.setattr(devices.wg, "hub_endpoint", "hub.example.org")
    monkeypatch.setattr(devices.wg, "server_public_key", "PUB=")
    return build_routeros_script(device_name="Biuro", client_private_key="PRIV=", device_ip="10.77.0.2",
                                 api_username="mtm-api", api_password="haslo", preshared_key="PSK=")


def test_whole_script_is_one_block_starting_with_version_check(monkeypatch):
    """Caly skrypt to jeden blok: na RouterOS < 7.15 sprawdzenie wersji konczy `:error`,
    zanim cokolwiek sie zmieni (wczesniej linie szly po kolei i na 7.13 zostawala polowiczna
    konfiguracja). Bez pustych linii i kontynuacji `\\` — najprostsza postac dla terminala."""
    lines = _script(monkeypatch).splitlines()
    assert lines[0] == "{" and lines[-1] == "}"
    assert lines[1] == _VERSION_CHECK
    assert all(line.strip() for line in lines)
    assert not any(line.rstrip().endswith("\\") for line in lines)
    assert ':error "MTM: za stary RouterOS"' in _VERSION_CHECK and "($mn >= 15)" in _VERSION_CHECK


def test_certificate_signed_before_https_service_uses_it(monkeypatch):
    """`/ip service set www-ssl certificate=` przyjmuje tylko podpisany certyfikat."""
    sign = next(l for l in _script(monkeypatch).splitlines() if "/certificate sign" in l)
    assert sign.index("/certificate sign mtm-cert") < sign.index("/ip service set www-ssl")
    assert ":while (([/certificate get [find name=mtm-cert] private-key] != true) && ($w < 60))" in sign


def test_order_inside_block(monkeypatch):
    lines = _script(monkeypatch).splitlines()
    idx = {k: next(i for i, l in enumerate(lines) if k in l) for k in (
        "/interface wireguard add", "/interface wireguard peers add", "/user add", "/ip firewall filter add",
        "/certificate add", "/certificate sign", "MTM: gotowe")}
    order = ["/interface wireguard add", "/interface wireguard peers add", "/user add", "/ip firewall filter add",
             "/certificate add", "/certificate sign", "MTM: gotowe"]
    assert [idx[k] for k in order] == sorted(idx[k] for k in order)


def test_existing_group_does_not_abort(monkeypatch):
    """W bloku kazdy blad przerywa reszte — istniejaca grupa (wczesniejsza rejestracja) nie moze."""
    assert ":do {/user group add name=mtm-api" in _script(monkeypatch) and "on-error={}" in _script(monkeypatch)


def test_firewall_rules_work_with_empty_filter_list(monkeypatch):
    """`place-before=0` przy pustej liscie regul to „no such item" — kazda regula ma galaz
    z place-before i bez."""
    rules = [l for l in _script(monkeypatch).splitlines() if "/ip firewall filter add" in l]
    assert len(rules) == 2
    for line in rules:
        assert line.startswith(":if ([:len [/ip firewall filter find]] > 0) do={")
        do, other = line.split("} else={")
        assert "place-before=0" in do and "place-before" not in other
        assert do.split("do={")[1].replace(" place-before=0", "") == other.rstrip("}")


def test_script_uses_configured_hub(monkeypatch):
    s = _script(monkeypatch)
    assert "endpoint-address=hub.example.org" in s and "address=10.77.0.2/22 interface=wg-mt" in s
    assert "www-ssl address=10.77.0.1/32" in s and 'preshared-key="PSK="' in s
