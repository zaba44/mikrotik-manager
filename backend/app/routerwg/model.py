"""Czysta logika WireGuarda na routerach — bez sieci i bez bazy, wiec testowalna wprost.

Empiria z labu (REST, RouterOS 7.23/7.24), ktora ksztaltuje ten kod:
  * pola `client-address`, `client-dns`, `client-keepalive`, `client-listen-port`
    i `responder` w ogole NIE przychodza, gdy sa nieustawione. Brak pola = puste,
    nigdy „ta wersja nie obsluguje" — wersje bierzemy wylacznie z /system/resource;
  * pola wrazliwe przychodza w calosci (konto ma polityke `sensitive` — PSK widac),
    wiec pusty `private-key` znaczy, ze klucza na routerze NAPRAWDE nie ma;
  * `last-handshake` w formacie jednostek: `51s`, `1m3s`, `2w1d27m21s`;
  * RouterOS 7.24 dokleja do peera `.about` z ostrzezeniem, np.
    „allowed-address match other peers" — pokazujemy to, bo to realny blad konfiguracji.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# Peer z handshake'iem mlodszym niz to jest „aktywny". WireGuard odnawia sesje co
# 2 minuty, wiec 180 s daje zapas na jedno spoznione odnowienie.
ACTIVE_SECONDS = 180

_UNIT = re.compile(r"(\d+(?:\.\d+)?)(ms|w|d|h|m|s)")
_CLOCK = re.compile(r"^(?:(\d+)w)?(?:(\d+)d)?(\d+):(\d+):(\d+)")
_UNIT_SECONDS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}


def parse_duration(text) -> float | None:
    """Czas w formacie RouterOS -> sekundy. Obsluguje `1w2d3h4m5s`, `2d00:01:18`,
    `00:01:18` i gole sekundy. Puste -> None (np. „nigdy nie bylo handshake'u")."""
    if text is None:
        return None
    text = str(text).strip()
    if not text:
        return None
    if ":" in text:
        m = _CLOCK.match(text)
        if not m:
            return None
        w, d, h, mi, s = (int(g) if g else 0 for g in m.groups())
        return w * 604800 + d * 86400 + h * 3600 + mi * 60 + s
    total, matched = 0.0, False
    for value, unit in _UNIT.findall(text):
        matched = True
        total += float(value) * _UNIT_SECONDS[unit]
    if matched:
        return total
    try:
        return float(text)
    except ValueError:
        return None


def format_ago(seconds: float | None) -> str:
    if seconds is None:
        return "nigdy"
    s = int(seconds)
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60} s"
    if s < 86400:
        return f"{s // 3600} h {(s % 3600) // 60} min"
    return f"{s // 86400} d {(s % 86400) // 3600} h"


# ---- wersje ----

def version_tuple(text) -> tuple[int, int, int]:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(text or ""))
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


SUPPORT_NONE, SUPPORT_BASIC, SUPPORT_FULL = "none", "basic", "full"


def support_level(version) -> str:
    """< 7.15: nic (brak pol client-*), 7.15–7.20: monitor i config istniejacych peerow,
    7.21+: pelna obsluga (od 7.21 router trzyma client-allowed-address)."""
    v = version_tuple(version)
    if v < (7, 15, 0):
        return SUPPORT_NONE
    if v < (7, 21, 0):
        return SUPPORT_BASIC
    return SUPPORT_FULL


# ---- peery ----

def _secret(value) -> str:
    """Ukryte (`*****`) albo nieustawione (`none`, `auto`) wartosci wrazliwe traktujemy
    jak brak — inaczej `auto` trafiloby do configu jako „klucz"."""
    v = str(value or "")
    if not v or v.startswith("*") or v in ("none", "auto"):
        return ""
    return v


def _is_true(value) -> bool:
    return str(value).lower() in ("true", "yes")


def _split(value) -> list[str]:
    return [x.strip() for x in str(value or "").split(",") if x.strip()]


def _int(value) -> int:
    try:
        return int(str(value or "0"))
    except ValueError:
        return 0


@dataclass
class Peer:
    id: str
    interface: str
    name: str = ""
    comment: str = ""
    public_key: str = ""
    private_key: str = ""
    preshared_key: str = ""
    allowed: list[str] = field(default_factory=list)
    endpoint_address: str = ""
    current_endpoint: str = ""
    handshake: float | None = None
    rx: int = 0
    tx: int = 0
    disabled: bool = False
    client_address: str = ""
    client_dns: str = ""
    client_endpoint: str = ""
    client_keepalive: str = ""
    client_listen_port: str = ""
    client_allowed: str = ""
    about: str = ""
    host_ip: str | None = None
    routes: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.handshake is None:
            return "never"
        return "active" if self.handshake <= ACTIVE_SECONDS else "idle"

    @property
    def kind(self) -> str:
        """Tylko do wyswietlania i domyslnego zaznaczenia — NIGDY twarda regula."""
        if self.endpoint_address:
            return "uplink"
        if self.routes:
            return "site"
        return "client"

    @property
    def host_sort(self) -> int:
        """Klucz sortowania po adresie — tekstowo 10.0.0.10 wypadaloby przed 10.0.0.9."""
        try:
            return int(ipaddress.ip_address(self.host_ip)) if self.host_ip else 0
        except ValueError:
            return 0

    @property
    def has_private_key(self) -> bool:
        return bool(self.private_key)

    @property
    def display_name(self) -> str:
        if self.name:
            return self.name
        if self.comment:
            return self.comment
        return (self.public_key[:10] + "…") if len(self.public_key) > 10 else self.public_key


def peer_from_row(row: dict) -> Peer:
    def g(key):
        return str(row.get(key) or "")

    p = Peer(
        id=g(".id"),
        interface=g("interface"),
        name=g("name"),
        comment=g("comment"),
        public_key=g("public-key"),
        private_key=_secret(row.get("private-key")),
        preshared_key=_secret(row.get("preshared-key")),
        allowed=_split(row.get("allowed-address")),
        endpoint_address=g("endpoint-address"),
        handshake=parse_duration(row.get("last-handshake")),
        rx=_int(row.get("rx")),
        tx=_int(row.get("tx")),
        disabled=_is_true(row.get("disabled")),
        client_address=g("client-address"),
        client_dns=g("client-dns"),
        client_endpoint=g("client-endpoint"),
        client_keepalive=g("client-keepalive"),
        client_listen_port=g("client-listen-port"),
        client_allowed=g("client-allowed-address"),
        about=g(".about"),
    )
    current = g("current-endpoint-address")
    if current:
        port = g("current-endpoint-port")
        p.current_endpoint = f"{current}:{port}" if port and port != "0" else current

    # Adres hosta to PIERWSZY wpis /32 — nie pierwszy wpis w ogole. Na routerze z labu
    # peer ma `192.168.88.0/24,172.21.0.1/32`: siec site-to-site stoi przed adresem hosta.
    for entry in p.allowed:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            p.routes.append(entry)
            continue
        if net.version == 4 and net.prefixlen == 32 and p.host_ip is None:
            p.host_ip = str(net.network_address)
        elif net.version == 6 and net.prefixlen == 128:
            continue  # adres hosta IPv6 to nie dodatkowa trasa
        else:
            p.routes.append(entry)
    return p


# ---- interfejsy ----

READONLY_MANAGER = "przez ten tunel łączy się portal"
READONLY_CLIENT = "router jest tu klientem (uplink)"


@dataclass
class Interface:
    id: str
    name: str
    listen_port: str = ""
    public_key: str = ""
    disabled: bool = False
    addresses: list[ipaddress.IPv4Interface] = field(default_factory=list)
    router_is_client: bool = False
    carries_manager: bool = False

    @property
    def is_bth(self) -> bool:
        return self.name.lower().startswith("back-to-home")

    @property
    def readonly_reason(self) -> str:
        # Kolejnosc ma znaczenie: tunel managera jest najwazniejszym powodem — jego
        # zepsucie odcina portal od routera i nie da sie tego cofnac tym samym kanalem.
        if self.carries_manager:
            return READONLY_MANAGER
        if self.router_is_client:
            return READONLY_CLIENT
        return ""

    @property
    def readonly(self) -> bool:
        return bool(self.readonly_reason)

    @property
    def tunnel(self) -> ipaddress.IPv4Interface | None:
        return self.addresses[0] if self.addresses else None


def build_interfaces(if_rows: list[dict], peers: list[Peer], addr_rows: list[dict],
                     manager_ip: str | None) -> list[Interface]:
    """`manager_ip` to adres urzadzenia w tunelu portalu (device.wg_ip). Interfejs, ktory
    go nosi, jest galezia, na ktorej siedzimy — odpowiednik `CarriesApi` z implementacji
    referencyjnej, tylko ze tam portal laczyl sie po API, a tu przez wlasny tunel."""
    by_iface: dict[str, list[ipaddress.IPv4Interface]] = {}
    for a in addr_rows:
        try:
            iface = ipaddress.ip_interface(str(a.get("address") or ""))
        except ValueError:
            continue
        if iface.version == 4:
            by_iface.setdefault(str(a.get("interface") or ""), []).append(iface)

    try:
        mgr = ipaddress.ip_address(manager_ip) if manager_ip else None
    except ValueError:
        mgr = None

    result = []
    for r in if_rows:
        name = str(r.get("name") or "")
        addrs = by_iface.get(name, [])
        result.append(Interface(
            id=str(r.get(".id") or ""),
            name=name,
            listen_port=str(r.get("listen-port") or ""),
            public_key=str(r.get("public-key") or ""),
            disabled=_is_true(r.get("disabled")),
            addresses=addrs,
            router_is_client=any(p.interface == name and p.endpoint_address for p in peers),
            carries_manager=bool(mgr and any(a.ip == mgr for a in addrs)),
        ))
    return result


def default_interface(interfaces: list[Interface], peers: list[Peer]) -> Interface | None:
    """Domyslnie pokazujemy to, co najciekawsze: serwer dla klientow (zapisywalny,
    z peerami). Tunel managera i uplinki sa na koncu kolejki."""
    visible = [i for i in interfaces if not i.is_bth]
    if not visible:
        return None
    count = {i.name: sum(1 for p in peers if p.interface == i.name) for i in visible}
    return sorted(visible, key=lambda x: (x.readonly, -count[x.name], x.name.lower()))[0]


# ---- etap 3: dodawanie peerow i nowy tunel ----

def free_ips(iface: Interface, peers: list[Peer]):
    """Kolejne wolne adresy w RZECZYWISTEJ podsieci interfejsu (z /ip/address, nie na sztywno
    /24). Zajete: adresy samego interfejsu + allowed-address wszystkich jego peerow; wpisy
    szersze niz /32, ktore nachodza na podsiec (np. site-to-site), wylaczaja caly zakres."""
    tunnel = iface.tunnel
    if tunnel is None:
        return
    net = tunnel.network
    used = {a.ip for a in iface.addresses}
    ranges = []
    for p in peers:
        if p.interface != iface.name:
            continue
        for entry in p.allowed:
            try:
                n = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if n.version != 4 or not n.overlaps(net):
                continue
            if n.prefixlen == 32:
                used.add(n.network_address)
            else:
                ranges.append(n)
    for ip in net.hosts():
        if ip not in used and not any(ip in r for r in ranges):
            yield ip


def peer_name(prefix: str, ip: ipaddress.IPv4Address, prefixlen: int, taken: set[str]) -> str:
    """Konwencja z generatora: prefiks + ostatni oktet (Client_5). Przy podsieci szerszej
    niz /24 sam ostatni oktet przestaje byc unikalny — wtedy dwa ostatnie (Client_1_5)."""
    o = str(ip).split(".")
    suffix = o[3] if prefixlen >= 24 else f"{o[2]}_{o[3]}"
    name, n = f"{prefix}{suffix}", 2
    while name.lower() in taken:
        name, n = f"{prefix}{suffix}_{n}", n + 1
    taken.add(name.lower())
    return name


def _most_common(values: list[str]) -> str:
    values = [v for v in values if v]
    return max(set(values), key=values.count) if values else ""


def defaults(iface: Interface, peers: list[Peer]) -> dict:
    """Podpowiedzi do formularza: najczestsze wartosci client-* na tym interfejsie. Endpoint
    zapisujemy jako sam host — port to listen-port interfejsu, a trzymanie go osobno
    rozjechaloby sie przy zmianie portu."""
    mine = [p for p in peers if p.interface == iface.name]
    endpoint = _most_common([p.client_endpoint for p in mine])
    if ":" in endpoint and not endpoint.startswith("["):
        endpoint = endpoint.rsplit(":", 1)[0]
    keepalive = parse_duration(_most_common([p.client_keepalive for p in mine]))
    return {
        "dns": _most_common([p.client_dns for p in mine]),
        "endpoint": endpoint,
        "keepalive": int(keepalive) if keepalive else 25,
        "client_allowed": _most_common([p.client_allowed for p in mine]),
        "psk": (not mine) or any(p.preshared_key for p in mine),
    }


def first_active_drop(rules: list[dict]) -> dict | None:
    """Pierwsza WLACZONA regula `drop` w lancuchu input. Generator robi `add` na koniec
    lancucha, a tam zwykle stoi drop — regula accept nigdy by nie zadzialala. Ograniczenie:
    drop schowany w lancuchu, do ktorego prowadzi `jump`, nie zostanie wykryty."""
    for r in rules:
        if r.get("chain") != "input" or str(r.get("disabled")) == "true":
            continue
        if r.get("action") in ("drop", "reject"):
            return r
    return None


def check_new_tunnel(name: str, port: str, network: ipaddress.IPv4Network,
                     interfaces: list[Interface], addr_rows: list[dict]) -> list[str]:
    errors = []
    if any(i.name.lower() == name.lower() for i in interfaces):
        errors.append(f"Interfejs {name} już istnieje.")
    clash = next((i for i in interfaces if i.listen_port == port), None)
    if clash:
        errors.append(f"Port {port} jest już używany przez {clash.name}.")
    for a in addr_rows:
        try:
            have = ipaddress.ip_interface(str(a.get("address") or ""))
        except ValueError:
            continue
        if have.version == 4 and have.network.overlaps(network):
            errors.append(f"Podsieć {network} koliduje z adresem {have} na {a.get('interface')}.")
    return errors
