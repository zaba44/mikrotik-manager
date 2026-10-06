"""Config klienta WireGuard w formacie generatora uzytkownika (wgconfigmt).

Swiadomie NIE uzywamy `/interface/wireguard/peers/show-client-config` z RouterOS.
Sprawdzone na sprzecie: dla peera z labu zwrocil `ListenPort = 51820`, wymyslony
`Address = 192.168.177.2/24`, `AllowedIPs = 0.0.0.0/0` i brak Endpointu — czyli config,
ktory wyglada wiarygodnie, a prowadzi donikad. Skladamy go sami z pol peera.

Format (zgodny z generatorem co do linijki, bez pustych linii miedzy sekcjami):

    [Interface]
    ## <nazwa>
    Address = <client-address>
    PrivateKey = <private-key peera>
    ## PublicKey = <public-key peera>
    DNS = <client-dns>                 (gdy jest)
    ListenPort = <client-listen-port>  (gdy jest — generator go nie zna, ale import .conf
                                        moze go zapisac na routerze, wiec nie wolno go gubic)
    [Peer]
    Endpoint = <client-endpoint>:<listen-port>
    PublicKey = <klucz publiczny interfejsu>
    PreSharedKey = <psk>               (gdy jest; generator pisze wlasnie „PreSharedKey")
    AllowedIPs = <client-allowed-address; gdy brak: IP serwera/32>
    PersistentKeepalive = <sekundy>    (gdy jest)
"""
from __future__ import annotations

from app.routerwg.model import Interface, Peer, parse_duration

# Brakujace pola zostawiamy jako widoczne wypelniacze, a nie puste linie: config z pustym
# PrivateKey importuje sie w kliencie bez bledu i dopiero nie dziala, wiec lepiej, zeby
# brak byl oczywisty od pierwszego spojrzenia.
MISSING_KEY = "BRAK_KLUCZA_NA_ROUTERZE"
MISSING = "UZUPELNIJ"


def build_client_config(peer: Peer, iface: Interface, allowed_override: str = "") -> tuple[str, list[str]]:
    """Zwraca (tekst configu, lista brakujacych elementow do pokazania uzytkownikowi).

    `allowed_override` to AllowedIPs podane jednorazowo w oknie configu — na RouterOS
    7.15–7.20, gdzie router nie trzyma `client-allowed-address`. Niczego nie zapisujemy."""
    missing: list[str] = []
    tunnel = iface.tunnel
    prefix = tunnel.network.prefixlen if tunnel else 24

    if peer.client_address:
        address = peer.client_address
    elif peer.host_ip:
        # Regula z generatora: adres klienta /24 odpowiada wpisowi /32 na routerze.
        address = f"{peer.host_ip}/{prefix}"
    else:
        address = MISSING
        missing.append("adres klienta (peer nie ma wpisu /32 w allowed-address)")

    private_key = peer.private_key or MISSING_KEY
    if not peer.private_key:
        missing.append("klucz prywatny — router go nie przechowuje dla tego peera")

    endpoint = peer.client_endpoint
    if not endpoint:
        endpoint = MISSING
        missing.append("adres serwera (client-endpoint)")
    if ":" not in endpoint and iface.listen_port:
        endpoint = f"{endpoint}:{iface.listen_port}"

    allowed = allowed_override.strip() or peer.client_allowed
    if not allowed:
        allowed = f"{tunnel.ip}/32" if tunnel else MISSING
        if not tunnel:
            missing.append("AllowedIPs (interfejs nie ma adresu IPv4)")

    lines = [
        "[Interface]",
        f"## {peer.display_name}",
        f"Address = {address}",
        f"PrivateKey = {private_key}",
        f"## PublicKey = {peer.public_key}",
    ]
    if peer.client_dns:
        lines.append(f"DNS = {peer.client_dns}")
    if peer.client_listen_port and peer.client_listen_port != "0":
        lines.append(f"ListenPort = {peer.client_listen_port}")
    lines += [
        "[Peer]",
        f"Endpoint = {endpoint}",
        f"PublicKey = {iface.public_key}",
    ]
    if peer.preshared_key:
        lines.append(f"PreSharedKey = {peer.preshared_key}")
    lines.append(f"AllowedIPs = {allowed}")
    keepalive = parse_duration(peer.client_keepalive)
    if keepalive and keepalive > 0:
        lines.append(f"PersistentKeepalive = {int(keepalive)}")
    return "\n".join(lines) + "\n", missing


# ---- Back To Home: tryb „tylko siec lokalna" ----

def _kv(line: str) -> tuple[str, str]:
    key, sep, value = line.partition("=")
    return (key.strip(), value.strip()) if sep else (line.strip(), "")


def bth_local_only(config: str, subnets: list[str]) -> str:
    """Przerabia config uzytkownika BTH tak, zeby przez tunel szedl tylko ruch do LAN-u.
    Router tego nie zapisze — robimy to w portalu, a QR powstaje z wyniku.

    Uklad z routera (RouterOS 7.24, sprawdzony na sprzecie) rozni sie od przykladu ze
    specyfikacji: PRAWDZIWY peer stoi PIERWSZY, atrapa druga, adresy sa rozdzielone ", "
    i jest `ListenPort = 51820`. Dlatego atrape rozpoznajemy po `AllowedIPs = 0.0.0.0/32`,
    nigdy po kolejnosci.

    Zmiany (zgodne z reczna przerobka uzytkownika, ktora dziala):
      * peer-atrapa (AllowedIPs 0.0.0.0/32) — usuniety,
      * [Interface] Address — tylko IPv4,
      * [Interface] DNS — usuniety (DNS w tunelu ma sens tylko przy calym ruchu przez tunel),
      * [Interface] ListenPort — usuniety: klient ma brac losowy port; staly 51820 gryzie
        sie z innym tunelem WireGuard na tej samej maszynie,
      * AllowedIPs prawdziwego peera — wybrane podsieci LAN.
    Komentarze na poczatku (`# Name = ...`, `# CloudDDNS = ...`) zostaja — identyfikuja config.
    """
    preamble: list[str] = []
    sections: list[tuple[str, list[str]]] = []
    for raw in config.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if line.strip().startswith("["):
            sections.append((line.strip(), []))
        elif not sections:
            if line.strip():
                preamble.append(line)
        elif line.strip():
            sections[-1][1].append(line)

    out: list[str] = list(preamble)
    if preamble:
        out.append("")
    for header, lines in sections:
        is_peer = header.lower() == "[peer]"
        if is_peer:
            allowed = next((v for k, v in map(_kv, lines) if k.lower() == "allowedips"), "")
            if allowed.replace(" ", "") == "0.0.0.0/32":
                continue  # atrapa
        out.append(header)
        for line in lines:
            key, value = _kv(line)
            k = key.lower()
            if not is_peer and k in ("dns", "listenport"):
                continue
            if not is_peer and k == "address":
                v4 = [a.strip() for a in value.split(",") if a.strip() and ":" not in a]
                out.append(f"Address = {', '.join(v4)}")
                continue
            if is_peer and k == "allowedips":
                out.append(f"AllowedIPs = {', '.join(subnets)}")
                continue
            out.append(line)
        out.append("")
    return "\n".join(out).rstrip() + "\n"
