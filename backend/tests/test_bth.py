"""Back To Home: przerobka „tylko LAN" na ukladach z routera, wsparcie, podsieci LAN."""
from app.routerwg.bth import lan_subnets, support
from app.routerwg.conf import bth_local_only

# Config uzytkownika 1:1 z routera (RouterOS 7.24.2), klucze podmienione. PRAWDZIWY peer
# stoi tu PIERWSZY, atrapa druga — odwrotnie niz w konfiguracji domyslnej.
USER_CONF = """# Name = mtm-krok0
# CloudDDNS = hx4k2m9q7tz.sn.mynetname.net

[Interface]
ListenPort = 51820
PrivateKey = PRIVKEY=
Address = 192.168.216.3/32, fc00:0:0:216::3/128
DNS = 192.168.216.1

[Peer]
PublicKey = ROUTERKEY=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = hx4k2m9q7tz.vpn.mynetname.net:31415
PersistentKeepalive = 30

[Peer]
PublicKey = DUMMYKEY=
AllowedIPs = 0.0.0.0/32
Endpoint = hx4k2m9q7tz.sn.mynetname.net:31415
PersistentKeepalive = 15

"""

USER_CONF_LAN = """# Name = mtm-krok0
# CloudDDNS = hx4k2m9q7tz.sn.mynetname.net

[Interface]
PrivateKey = PRIVKEY=
Address = 192.168.216.3/32

[Peer]
PublicKey = ROUTERKEY=
AllowedIPs = 192.168.88.0/24, 192.168.18.0/24
Endpoint = hx4k2m9q7tz.vpn.mynetname.net:31415
PersistentKeepalive = 30
"""

# Konfiguracja domyslna z /ip/cloud: atrapa PIERWSZA, adresy po przecinku bez spacji.
DEFAULT_CONF = """[Interface]
PrivateKey = PK=
Address = 192.168.216.2/24,fc00:0:0:216::2/64
DNS = 9.9.9.9,1.1.1.1
[Peer]
PublicKey = DUMMY=
AllowedIPs = 0.0.0.0/32
Endpoint = x.sn.mynetname.net:1234
PersistentKeepalive = 15
[Peer]
PublicKey = ROUTER=
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = x.vpn.mynetname.net:1234
PersistentKeepalive = 15
"""


def test_local_only_user_layout():
    assert bth_local_only(USER_CONF, ["192.168.88.0/24", "192.168.18.0/24"]) == USER_CONF_LAN


def test_local_only_default_layout_dummy_first():
    got = bth_local_only(DEFAULT_CONF, ["10.0.0.0/24"])
    assert "0.0.0.0/32" not in got and "DUMMY=" not in got
    assert "Address = 192.168.216.2/24\n" in got and "DNS" not in got
    assert "AllowedIPs = 10.0.0.0/24" in got and got.count("[Peer]") == 1


def test_support_reasons():
    assert not support("7.24.5", "mipsbe", {"ddns-enabled": "auto"})[0]
    assert "back-to-home-vpn" in support("7.24.2", "arm", {})[1]
    assert "7.15" in support("7.14.3", "arm", {"back-to-home-vpn": "disabled"})[1]
    assert support("7.24.2", "arm64", {"back-to-home-vpn": "revoked-and-disabled"}) == (True, "")


def test_lan_subnets_excludes_wg_public_disabled():
    subs = lan_subnets([
        {"address": "192.168.88.1/24", "interface": "LAN_BRIDGE"},
        {"address": "192.168.18.1/24", "interface": "LAN_BRIDGE"},
        {"address": "172.21.0.2/24", "interface": "WG_BIURO"},
        {"address": "192.168.216.1/24", "interface": "back-to-home-vpn"},
        {"address": "8.8.8.8/32", "interface": "pppoe-out1"},  # publiczny; 203.0.113.0/24 Python liczy jako prywatny
        {"address": "10.9.9.1/24", "interface": "ether5", "disabled": "true"},
    ], {"WG_BIURO", "back-to-home-vpn"})
    assert subs == ["192.168.88.0/24", "192.168.18.0/24"]
