"""Import plikow .conf: parser, X25519 i planer — wszystkie sciezki konfliktow, na prawdziwych
kluczach (cryptography). Kluczowa regula: private-key trafia na router TYLKO, gdy matematycznie
pasuje do public-key peera — inaczej RouterOS po cichu podmienia klucz publiczny i odcina
klienta (sprawdzone na sprzecie)."""
import base64
import io
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.routerwg.importer import derive_public, load_uploads, parse_conf, plan
from app.routerwg.model import build_interfaces, peer_from_row


def kp():
    k = X25519PrivateKey.generate()
    return (base64.b64encode(k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())).decode(),
            base64.b64encode(k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode())


SRV_PRIV, SRV_PUB = kp()


def conf_text(name, ip, priv, pub, srv=SRV_PUB, psk="PSKA=", dns="1.1.1.1", endpoint="vpn.firma.pl:51820",
              allowed="192.168.88.0/24", keepalive="25", pub_comment=True):
    lines = ["[Interface]", f"## {name}", f"Address = {ip}/24"]
    if priv:
        lines.append(f"PrivateKey = {priv}")
    if pub_comment:
        lines.append(f"## PublicKey = {pub}")
    if dns:
        lines.append(f"DNS = {dns}")
    lines += ["[Peer]", f"Endpoint = {endpoint}", f"PublicKey = {srv}"]
    if psk:
        lines.append(f"PreSharedKey = {psk}")
    lines.append(f"AllowedIPs = {allowed}")
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


@pytest.fixture(scope="module")
def setup():
    keys = {name: kp() for name in ("ok", "has", "full", "psk")}
    peers = [
        # „stary reczny" peer: tylko klucz publiczny, zero pol client-*
        peer_from_row({".id": "*1", "interface": "WG", "allowed-address": "10.9.0.2/32", "public-key": keys["ok"][1]}),
        peer_from_row({".id": "*2", "interface": "WG", "allowed-address": "10.9.0.3/32", "public-key": keys["has"][1],
                       "private-key": keys["has"][0]}),
        peer_from_row({".id": "*3", "interface": "WG", "allowed-address": "10.9.0.4/32", "public-key": keys["full"][1],
                       "client-address": "10.9.0.4/24", "client-dns": "8.8.8.8", "client-endpoint": "stary.host",
                       "client-keepalive": "10s"}),
        peer_from_row({".id": "*4", "interface": "WG", "allowed-address": "10.9.0.5/32", "public-key": keys["psk"][1],
                       "preshared-key": "ROUTERPSK="}),
    ]
    iface = build_interfaces([{"name": "WG", "listen-port": "51820", "public-key": SRV_PUB}], peers,
                             [{"address": "10.9.0.1/24", "interface": "WG"}], None)[0]
    return keys, peers, iface


def one(setup, text, overwrite=False, level="full"):
    _, peers, iface = setup
    return plan(iface, peers, [parse_conf(text, "t.conf")], overwrite, level)[0]


def test_parser():
    c = parse_conf(conf_text("Client_2", "10.9.0.2", "PRIV=", "PUB=")
                   .replace("Address", "address").replace("Endpoint", "ENDPOINT"), "a.conf")
    assert (c.address, c.endpoint) == ("10.9.0.2/24", "vpn.firma.pl:51820")   # klucze bez wielkosci liter
    assert (c.name, c.public_key_comment) == ("Client_2", "PUB=")
    bth = parse_conf("[Interface]\nPrivateKey = X=\nAddress = 1.2.3.4/32\n[Peer]\nPublicKey = A=\n"
                     "AllowedIPs = 0.0.0.0/0\n[Peer]\nPublicKey = B=\nAllowedIPs = 0.0.0.0/32\n", "b.conf")
    assert bth.server_public_key == "A="                                      # drugi [Peer] ignorowany
    assert parse_conf("hello", "x.conf") is None


def test_derive_public():
    priv, pub = kp()
    assert derive_public(priv) == pub
    assert derive_public("nie-base64!!") is None


def test_full_fill(setup):
    keys = setup[0]
    x = one(setup, conf_text("Client_2", "10.9.0.2", *keys["ok"]))
    assert x["status"] == "apply"
    assert sorted(x["changes"]) == sorted(["client-address", "client-dns", "client-endpoint", "client-keepalive",
                                           "client-allowed-address", "private-key"])
    assert x["changes"]["client-endpoint"] == "vpn.firma.pl"   # sam host
    assert x["changes"]["client-keepalive"] == "25s"


def test_other_server_skipped(setup):
    _, other_pub = kp()
    x = one(setup, conf_text("Client_2", "10.9.0.2", *setup[0]["ok"], srv=other_pub))
    assert x["status"] == "skip" and "innego serwera" in x["notes"][0]


def test_inconsistent_file_conflict(setup):
    wrong_priv, _ = kp()
    x = one(setup, conf_text("Client_2", "10.9.0.2", wrong_priv, setup[0]["ok"][1]))
    assert x["status"] == "conflict" and "niespójny" in x["notes"][0]


def test_foreign_private_key_never_written(setup):
    wrong_priv, _ = kp()
    x = one(setup, conf_text("Client_2", "10.9.0.2", wrong_priv, "", pub_comment=False))
    assert x["status"] == "skip" and x["peer"] is None


def test_address_mismatch_conflict(setup):
    x = one(setup, conf_text("Client_2", "10.9.0.77", *setup[0]["ok"]))
    assert x["status"] == "conflict"


def test_psk_mismatch_conflict(setup):
    x = one(setup, conf_text("Client_5", "10.9.0.5", *setup[0]["psk"], psk="INNYPSK="))
    assert x["status"] == "conflict" and "PreSharedKey" in x["notes"][0]


def test_without_private_key_fields_only(setup):
    x = one(setup, conf_text("Client_2", "10.9.0.2", None, setup[0]["ok"][1]))
    assert x["status"] == "apply" and "private-key" not in x["changes"]


def test_fill_vs_overwrite(setup):
    text = conf_text("Client_4", "10.9.0.4", *setup[0]["full"], dns="9.9.9.9", keepalive="30")
    x = one(setup, text)
    assert "client-dns" not in x["changes"] and "client-endpoint" not in x["changes"]
    x = one(setup, text, overwrite=True)
    assert (x["changes"]["client-dns"], x["changes"]["client-endpoint"], x["changes"]["client-keepalive"]) == \
        ("9.9.9.9", "vpn.firma.pl", "30s")


def test_notes_and_versions(setup):
    keys = setup[0]
    x = one(setup, conf_text("Client_2", "10.9.0.2", *keys["ok"], endpoint="vpn.firma.pl:9999"))
    assert any("9999" in n for n in x["notes"])                               # port inny niz listen-port
    x = one(setup, conf_text("Client_2", "10.9.0.2", *keys["ok"], dns=""))
    assert "client-dns" not in x["changes"]                                   # brak DNS = celowo puste
    x = one(setup, conf_text("Client_2", "10.9.0.2", *keys["ok"]), level="basic")
    assert "client-allowed-address" not in x["changes"] and any("7.21" in n for n in x["notes"])
    x = one(setup, conf_text("Client_2", "10.9.0.2", "to-nie-klucz=", keys["ok"][1]))
    assert x["status"] == "conflict"


def test_uploads_zip_and_loose():
    priv, pub = kp()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("klienci/Client_2.conf", conf_text("Client_2", "10.9.0.2", priv, pub))
        z.writestr("klienci/Client_2.png", b"\x89PNG")
        z.writestr("readme.txt", "x")
    confs, notes = load_uploads([("paczka.zip", buf.getvalue()),
                                 ("luzny.conf", conf_text("A", "10.9.0.3", None, pub).encode()),
                                 ("zdjecie.jpg", b"x"), ("pusty.conf", b"nic")])
    assert sorted(c.filename for c in confs) == ["Client_2.conf", "luzny.conf"]
    assert len(notes) == 2
