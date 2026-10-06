"""Uzupelnianie pol client-* peerow z plikow .conf uzytkownika (etap 4).

Zapisujemy WYLACZNIE pola informacyjne peera — client-address, client-dns,
client-listen-port, client-endpoint, client-keepalive, client-allowed-address (7.21+) —
oraz private-key, gdy go brak. Nie wplywaja na dzialanie tunelu, sluza do odtworzenia
configu i QR. NIGDY nie zmieniamy public-key, preshared-key, allowed-address, endpoint ani
keepalive peera. Nazwa i komentarz to notatki uzytkownika — ani ich nie porownujemy, ani
nie zapisujemy; „## Client_2" z pliku jest tylko etykieta w raporcie.

Dopasowanie pliku do peera (wszystkie warunki naraz):
  * [Peer] PublicKey pliku == klucz publiczny interfejsu (inaczej plik z innego serwera),
  * klucz publiczny klienta == public-key peera,
  * IP z Address == wpis /32 peera.

Klucz publiczny klienta bierzemy z linii „## PublicKey", a gdy plik ma PrivateKey,
dodatkowo WYLICZAMY go z klucza prywatnego (X25519). Wyliczony klucz wygrywa — linia
komentarza moze byc nieaktualna po recznej edycji, matematyka nie.

Kontrola X25519 przed zapisem private-key jest WARUNKIEM, nie dodatkiem. Sprawdzone na
sprzecie (wAP ax, 7.23.2): zapis niepasujacego private-key po cichu przelicza
public-key peera (HTTP 200, zero ostrzezen) — prawdziwy klient traci polaczenie w tej
samej sekundzie.
"""
from __future__ import annotations

import base64
import binascii
import io
import ipaddress
import zipfile
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.routerwg.model import SUPPORT_FULL, Interface, Peer, parse_duration

# Ochrona przed przypadkowym (albo zlosliwym) ZIP-em: configi maja po kilkaset bajtow.
MAX_FILES = 1000
MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024


@dataclass
class ConfFile:
    filename: str
    name: str = ""
    address: str = ""
    private_key: str = ""
    public_key_comment: str = ""
    dns: str = ""
    listen_port: str = ""
    endpoint: str = ""
    server_public_key: str = ""
    preshared_key: str = ""
    allowed_ips: str = ""
    keepalive: str = ""

    @property
    def label(self) -> str:
        return self.name or self.filename


def _kv(line: str) -> tuple[str, str]:
    key, sep, value = line.partition("=")
    return (key.strip(), value.strip()) if sep else (line.strip(), "")


def parse_conf(text: str, filename: str) -> ConfFile | None:
    """Nazwy kluczy bez rozrozniania wielkosci liter. Drugi [Peer] (np. atrapa BTH)
    jest ignorowany — config klienta naszego serwera ma jeden."""
    conf = ConfFile(filename=filename)
    section, peer_seen = "", False
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]").strip().lower()
            if section == "peer":
                if peer_seen:
                    section = "ignored"
                peer_seen = True
            continue
        if line.startswith("##"):
            body = line[2:].strip()
            if body.lower().startswith("publickey"):
                conf.public_key_comment = _kv(body)[1]
            elif section == "interface" and not conf.name:
                conf.name = body
            continue
        if line.startswith("#"):
            continue
        key, value = _kv(line)
        k = (section, key.lower())
        if k == ("interface", "privatekey"):
            conf.private_key = value
        elif k == ("interface", "address"):
            conf.address = value
        elif k == ("interface", "dns"):
            conf.dns = value
        elif k == ("interface", "listenport"):
            conf.listen_port = value
        elif k == ("peer", "publickey"):
            conf.server_public_key = value
        elif k == ("peer", "presharedkey"):
            conf.preshared_key = value
        elif k == ("peer", "endpoint"):
            conf.endpoint = value
        elif k == ("peer", "allowedips"):
            conf.allowed_ips = value
        elif k == ("peer", "persistentkeepalive"):
            conf.keepalive = value
    return conf if (conf.private_key or conf.address) else None


def load_uploads(files: list[tuple[str, bytes]]) -> tuple[list[ConfFile], list[str]]:
    """Pliki .conf i ZIP-y z .conf, czytane w pamieci — nic nie trafia na dysk."""
    confs, notes, total = [], [], 0

    def add(name: str, data: bytes):
        nonlocal total
        if len(confs) >= MAX_FILES:
            raise ValueError(f"Za dużo plików (limit {MAX_FILES}).")
        if len(data) > MAX_FILE_BYTES:
            notes.append(f"{name}: pominięty — za duży jak na config WireGuard.")
            return
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Łączny rozmiar plików przekracza limit.")
        conf = parse_conf(data.decode("utf-8", errors="replace"), name)
        if conf is None:
            notes.append(f"{name}: to nie wygląda na config WireGuard (brak PrivateKey i Address).")
        else:
            confs.append(conf)

    for name, data in files:
        lower = name.lower()
        if lower.endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for info in z.infolist():
                        if info.is_dir() or not info.filename.lower().endswith(".conf"):
                            continue
                        if info.file_size > MAX_FILE_BYTES:
                            notes.append(f"{info.filename}: pominięty — za duży.")
                            continue
                        add(info.filename.rsplit("/", 1)[-1], z.read(info))
            except zipfile.BadZipFile:
                notes.append(f"{name}: uszkodzony albo nie-ZIP.")
        elif lower.endswith(".conf"):
            add(name, data)
        else:
            notes.append(f"{name}: pominięty — oczekuję plików .conf albo .zip.")
    return confs, notes


def derive_public(private_key: str) -> str | None:
    """Klucz publiczny X25519 z prywatnego. None, gdy to nie jest poprawny klucz."""
    try:
        raw = base64.b64decode(private_key, validate=True)
        if len(raw) != 32:
            return None
        k = X25519PrivateKey.from_private_bytes(raw)
    except (binascii.Error, ValueError):
        return None
    return base64.b64encode(k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()


def _split(value: str) -> list[str]:
    return sorted(x.strip() for x in value.split(",") if x.strip())


def _host_port(endpoint: str) -> tuple[str, str]:
    if endpoint.startswith("["):  # [IPv6]:port
        host, _, port = endpoint[1:].partition("]")
        return host, port.lstrip(":")
    if endpoint.count(":") == 1:
        host, _, port = endpoint.partition(":")
        return host, port
    return endpoint, ""


def plan(iface: Interface, peers: list[Peer], confs: list[ConfFile], overwrite: bool, level: str) -> list[dict]:
    """Status kazdego pliku: apply (sa zmiany), skip (nic do zrobienia / nie nasz),
    conflict (cos sie nie zgadza — nie zapisujemy). Bez przegladu pole po polu: jedna opcja
    „uzupelnij tylko puste" albo „nadpisz wartosciami z plikow"."""
    mine = [p for p in peers if p.interface == iface.name]
    items = []
    for conf in confs:
        item = {"conf": conf, "label": conf.label, "file": conf.filename, "status": "skip",
                "peer": None, "changes": {}, "notes": []}
        items.append(item)
        notes = item["notes"]

        if conf.server_public_key != iface.public_key:
            notes.append("plik z innego serwera (klucz [Peer] ≠ klucz interfejsu)")
            continue

        derived = derive_public(conf.private_key) if conf.private_key else None
        if conf.private_key and derived is None:
            item["status"] = "conflict"
            notes.append("PrivateKey w pliku nie jest poprawnym kluczem WireGuard")
            continue
        if derived and conf.public_key_comment and derived != conf.public_key_comment:
            item["status"] = "conflict"
            notes.append("plik niespójny: „## PublicKey” nie pasuje do PrivateKey z tego samego pliku")
            continue
        client_key = derived or conf.public_key_comment
        if not client_key:
            notes.append("brak „## PublicKey” i brak PrivateKey — nie da się wskazać peera")
            continue

        peer = next((p for p in mine if p.public_key == client_key), None)
        if peer is None:
            notes.append("na interfejsie nie ma peera z tym kluczem (usunięty?)")
            continue
        item["peer"] = peer

        file_ip = None
        for a in conf.address.split(","):
            try:
                ip = ipaddress.ip_interface(a.strip())
            except ValueError:
                continue
            if ip.version == 4:
                file_ip = str(ip.ip)
                break
        if file_ip is None or file_ip != peer.host_ip:
            item["status"] = "conflict"
            notes.append(f"adres w pliku ({conf.address or 'brak'}) nie odpowiada peerowi ({peer.host_ip or 'brak /32'})")
            continue
        if peer.private_key and conf.private_key and peer.private_key != conf.private_key:
            item["status"] = "conflict"
            notes.append("klucz prywatny w pliku różni się od zapisanego na routerze")
            continue
        if peer.preshared_key and conf.preshared_key and peer.preshared_key != conf.preshared_key:
            item["status"] = "conflict"
            notes.append("PreSharedKey różni się od routera — plik nieaktualny?")
            continue

        changes = item["changes"]

        def consider(field_name: str, file_value: str, router_value: str, as_list: bool = False):
            if not file_value:
                return  # brak w pliku = celowo puste, nie konflikt
            same = (_split(file_value) == _split(router_value)) if as_list else file_value == router_value
            if not same and (not router_value or overwrite):
                changes[field_name] = file_value

        consider("client-address", ", ".join(_split(conf.address)), peer.client_address, as_list=True)
        consider("client-dns", conf.dns, peer.client_dns, as_list=True)
        consider("client-listen-port", conf.listen_port, peer.client_listen_port)
        if conf.endpoint:
            host, port = _host_port(conf.endpoint)
            consider("client-endpoint", host, peer.client_endpoint)
            if port and port != iface.listen_port:
                notes.append(f"port w Endpoint ({port}) inny niż listen-port interfejsu ({iface.listen_port})")
        if conf.keepalive.isdigit() and int(conf.keepalive) > 0:
            have = parse_duration(peer.client_keepalive)
            if not have or (overwrite and int(have) != int(conf.keepalive)):
                changes["client-keepalive"] = f"{int(conf.keepalive)}s"
        if level == SUPPORT_FULL:
            consider("client-allowed-address", conf.allowed_ips, peer.client_allowed, as_list=True)
        elif conf.allowed_ips:
            notes.append("AllowedIPs pominięte — wymaga RouterOS 7.21+")

        if not peer.private_key and conf.private_key:
            # Warunek konieczny: inaczej router po cichu podmieni klucz publiczny peera.
            if derived == peer.public_key:
                changes["private-key"] = conf.private_key
            else:
                item["status"] = "conflict"
                changes.clear()
                notes.append("klucz prywatny z pliku nie pasuje do klucza publicznego peera — "
                             "zapis podmieniłby klucz peera i odciął klienta")
                continue

        if changes:
            item["status"] = "apply"
        else:
            notes.append("nic do uzupełnienia")
    return items
