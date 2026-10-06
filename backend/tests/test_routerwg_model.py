"""Model WireGuarda na routerach: czasy RouterOS, peery, interfejsy, config, wolne adresy.
Ksztalty wierszy wziete 1:1 z odpowiedzi REST zywych routerow w labie."""
import ipaddress

import pytest

from app.routerwg.conf import MISSING, MISSING_KEY, build_client_config
from app.routerwg.model import (
    READONLY_CLIENT, READONLY_MANAGER, build_interfaces, check_new_tunnel, default_interface, defaults,
    first_active_drop, free_ips, parse_duration, peer_from_row, peer_name, support_level,
)


@pytest.mark.parametrize("text,seconds", [
    ("51s", 51), ("1m3s", 63), ("2w1d27m21s", 2 * 604800 + 86400 + 27 * 60 + 21),
    ("2d00:01:18", 2 * 86400 + 78), ("00:01:18", 78), ("500ms", 0.5), ("", None), (None, None),
])
def test_parse_duration(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("version,level", [
    ("7.14.3", "none"), ("7.15", "basic"), ("7.20.8", "basic"), ("7.21", "full"),
    ("7.23.2 (stable)", "full"), ("6.49.10", "none"),
])
def test_support_level(version, level):
    assert support_level(version) == level


def test_host_is_first_slash32_not_first_entry():
    # Router w labie: siec site-to-site stoi PRZED adresem hosta.
    p = peer_from_row({".id": "*1", "interface": "WG", "allowed-address": "192.168.88.0/24,172.21.0.1/32",
                       "last-handshake": "1m6s", "current-endpoint-address": "203.0.113.91",
                       "current-endpoint-port": "43248", "rx": "2536747860"})
    assert p.host_ip == "172.21.0.1"
    assert p.routes == ["192.168.88.0/24"]
    assert p.kind == "site"
    assert p.status == "active"
    assert p.current_endpoint == "203.0.113.91:43248"
    assert p.rx == 2536747860


def test_peer_secrets_and_ipv6():
    p = peer_from_row({".id": "*3", "interface": "WG", "allowed-address": "10.9.0.5/32,fd00::5/128",
                       "private-key": "*****", "preshared-key": "auto"})
    assert p.routes == []          # IPv6 /128 to nie dodatkowa trasa
    assert p.private_key == ""     # ukryty = brak
    assert p.preshared_key == ""   # auto = brak
    assert p.status == "never"


@pytest.mark.parametrize("handshake,status", [("180s", "active"), ("181s", "idle")])
def test_active_threshold(handshake, status):
    assert peer_from_row({".id": "*1", "interface": "WG", "last-handshake": handshake}).status == status


def _lab_interfaces():
    site = peer_from_row({".id": "*1", "interface": "WG_BIURO", "allowed-address": "192.168.88.0/24,172.21.0.1/32"})
    up = peer_from_row({".id": "*2", "interface": "wg_backup", "endpoint-address": "backup.example.org"})
    mt = peer_from_row({".id": "*9", "interface": "wg-mt", "allowed-address": "172.16.0.0/16",
                        "endpoint-address": "192.168.88.66"})
    peers = [site, up, mt]
    ifs = build_interfaces(
        [{"name": "wg-mt", "listen-port": "13231"}, {"name": "wg_backup", "listen-port": "22489"},
         {"name": "WG_BIURO", "listen-port": "43249", "public-key": "PUBSRV"},
         {"name": "back-to-home-vpn", "listen-port": "0"}],
        peers,
        [{"address": "172.16.0.5/16", "interface": "wg-mt"}, {"address": "172.25.177.6/24", "interface": "wg_backup"},
         {"address": "172.21.0.2/24", "interface": "WG_BIURO"},
         {"address": "192.168.216.1/24", "interface": "back-to-home-vpn"}],
        "172.16.0.5")
    return {i.name: i for i in ifs}, peers


def test_readonly_rules():
    ifs, peers = _lab_interfaces()
    assert ifs["wg-mt"].readonly_reason == READONLY_MANAGER   # tunel portalu wygrywa z „uplinkiem"
    assert ifs["wg_backup"].readonly_reason == READONLY_CLIENT
    assert not ifs["WG_BIURO"].readonly
    assert ifs["back-to-home-vpn"].is_bth
    assert default_interface(list(ifs.values()), peers).name == "WG_BIURO"


def test_client_config_generator_format():
    ifs, _ = _lab_interfaces()
    p = peer_from_row({".id": "*7", "interface": "WG_BIURO", "name": "Client_5", "allowed-address": "172.21.0.5/32",
                       "private-key": "PRIV5=", "public-key": "PUB5=", "preshared-key": "PSK5=",
                       "client-address": "172.21.0.5/24", "client-dns": "1.1.1.1", "client-endpoint": "vpn.example.pl",
                       "client-keepalive": "25s", "client-allowed-address": "192.168.88.0/24"})
    text, missing = build_client_config(p, ifs["WG_BIURO"])
    assert text == ("[Interface]\n## Client_5\nAddress = 172.21.0.5/24\nPrivateKey = PRIV5=\n"
                    "## PublicKey = PUB5=\nDNS = 1.1.1.1\n[Peer]\nEndpoint = vpn.example.pl:43249\n"
                    "PublicKey = PUBSRV\nPreSharedKey = PSK5=\nAllowedIPs = 192.168.88.0/24\n"
                    "PersistentKeepalive = 25\n")
    assert missing == []


def test_client_config_placeholders():
    ifs, _ = _lab_interfaces()
    bare = peer_from_row({".id": "*8", "interface": "WG_BIURO", "comment": "stary_reczny",
                          "allowed-address": "172.21.0.9/32", "public-key": "PUB9="})
    text, missing = build_client_config(bare, ifs["WG_BIURO"])
    assert "Address = 172.21.0.9/24" in text
    assert f"PrivateKey = {MISSING_KEY}" in text
    assert f"Endpoint = {MISSING}:43249" in text
    assert "AllowedIPs = 172.21.0.2/32" in text
    assert "## stary_reczny" in text
    assert len(missing) == 2
    text, _ = build_client_config(bare, ifs["WG_BIURO"], allowed_override="10.0.0.0/8")
    assert "AllowedIPs = 10.0.0.0/8" in text


def test_free_ips_and_names():
    addr = [{"address": "10.9.0.1/24", "interface": "WG"}, {"address": "10.40.0.1/22", "interface": "BIG"}]
    peers = [
        peer_from_row({".id": "*1", "interface": "WG", "allowed-address": "10.9.0.2/32", "name": "Client_2",
                       "client-dns": "1.1.1.1", "client-endpoint": "vpn.firma.pl", "client-keepalive": "25s",
                       "preshared-key": "PSK="}),
        peer_from_row({".id": "*2", "interface": "WG", "allowed-address": "10.9.0.3/32,192.168.50.0/24",
                       "client-endpoint": "vpn.firma.pl:51820"}),
        peer_from_row({".id": "*3", "interface": "WG", "allowed-address": "10.9.0.8/30"}),
        peer_from_row({".id": "*4", "interface": "INNY", "allowed-address": "10.9.0.4/32"}),
    ]
    ifs = {i.name: i for i in build_interfaces(
        [{"name": "WG", "listen-port": "51820"}, {"name": "BIG", "listen-port": "51821"}], peers, addr, None)}
    free = [str(x) for x, _ in zip(free_ips(ifs["WG"], peers), range(6))]
    assert free == ["10.9.0.4", "10.9.0.5", "10.9.0.6", "10.9.0.7", "10.9.0.12", "10.9.0.13"]
    assert [str(x) for x, _ in zip(free_ips(ifs["BIG"], peers), range(2))] == ["10.40.0.2", "10.40.0.3"]
    taken = {"client_2"}
    assert peer_name("Client_", ipaddress.ip_address("10.9.0.4"), 24, taken) == "Client_4"
    assert peer_name("Client_", ipaddress.ip_address("10.9.1.2"), 24, taken) == "Client_2_2"
    assert peer_name("Client_", ipaddress.ip_address("10.40.2.7"), 22, set()) == "Client_2_7"
    d = defaults(ifs["WG"], peers)
    assert (d["dns"], d["endpoint"], d["keepalive"], d["psk"]) == ("1.1.1.1", "vpn.firma.pl", 25, True)


def test_firewall_and_collisions():
    rules = [{".id": "*A", "chain": "forward", "action": "drop"},
             {".id": "*B", "chain": "input", "action": "accept"},
             {".id": "*C", "chain": "input", "action": "drop", "disabled": "true"},
             {".id": "*D", "chain": "input", "action": "drop"}]
    assert first_active_drop(rules)[".id"] == "*D"
    assert first_active_drop([{".id": "*R", "chain": "input", "action": "reject"}])[".id"] == "*R"
    assert first_active_drop([{".id": "*B", "chain": "input", "action": "accept"}]) is None
    addr = [{"address": "10.9.0.1/24", "interface": "WG"}]
    ifs = build_interfaces([{"name": "WG", "listen-port": "51820"}], [], addr, None)
    assert len(check_new_tunnel("wg", "51820", ipaddress.ip_network("10.9.0.0/25"), ifs, addr)) == 3
    assert check_new_tunnel("WG_NOWY", "40000", ipaddress.ip_network("10.77.0.0/24"), ifs, addr) == []
