#!/usr/bin/env python3
"""Control-channel HTTP wewnątrz kontenera wireguard.
Osiągalny tylko na wewnętrznej sieci docker (bez publikacji portu na hosta) —
jedyny klient to backend, przez `http://wireguard:9090`.

Zarządza całym cyklem życia interfejsu wg-mt:
- przy starcie: jeśli konfiguracja istnieje (istniejący/przywrócony stack) — podnosi
  tunel; jeśli nie — czeka na /setup od kreatora (świeża instalacja).
- /setup: tworzy interfejs z podaną podsiecią i (opcjonalnie odtworzonym) kluczem.
"""
import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# UWAGA: `get(KEY) or "domyslna"`, NIE `get(KEY, "domyslna")`. Docker compose przekazuje
# kazda zmienna z `environment:`, a gdy nie ma jej w .env — wstawia PUSTY CIAG. Wtedy klucz
# istnieje i drugi argument get() nigdy nie zadziala. Efekt przy pustym WG_INTERFACE byl
# spektakularny: agent tworzyl plik "/etc/wireguard/.conf" i wolal `wg-quick up ""`.
WG_INTERFACE = os.environ.get("WG_INTERFACE") or "wg-mt"
WG_PORT = os.environ.get("WG_PORT") or "51820"
BACKUP_SFTP_PORT = os.environ.get("BACKUP_SFTP_PORT") or "2222"
CADDY_PORT = os.environ.get("CADDY_PORT") or "8443"
SYSLOG_PORT = os.environ.get("SYSLOG_PORT") or "5514"


def _agent_token() -> str:
    """Token wspoldzielony z backendem przez wolumen. Plik ma pierwszenstwo przed env,
    bo to backend go generuje przy pierwszym starcie (patrz backend/entrypoint.sh)."""
    for _ in range(60):
        try:
            with open("/data/agent/token") as f:
                value = f.read().strip()
            if value:
                return value
        except OSError:
            pass
        if os.environ.get("WG_AGENT_TOKEN"):
            return os.environ["WG_AGENT_TOKEN"]
        __import__("time").sleep(1)
    return os.environ.get("WG_AGENT_TOKEN", "")


AGENT_TOKEN = _agent_token()
CONF_DIR = "/etc/wireguard"
CONF_FILE = f"{CONF_DIR}/{WG_INTERFACE}.conf"
KEY_FILE = f"{CONF_DIR}/{WG_INTERFACE}.key"
PORT = 9090


def run(cmd: list[str], check: bool = True) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.strip()}")
    return result.stdout


def interface_up() -> bool:
    return subprocess.run(["wg", "show", WG_INTERFACE], capture_output=True).returncode == 0


def public_key() -> str | None:
    if not interface_up():
        return None
    return run(["wg", "show", WG_INTERFACE, "public-key"]).strip()


def _iptables_ensure(table: str, chain: str, rule: list[str]) -> None:
    """Idempotentne dodanie reguły: najpierw -C (czy jest), dodaj -A tylko gdy brak.
    UWAGA na kolejność: `-t <table>` MUSI być przed `-C/-A <chain>`."""
    check = ["iptables", "-t", table, "-C", chain, *rule]
    if subprocess.run(check, capture_output=True).returncode != 0:
        run(["iptables", "-t", table, "-A", chain, *rule])


def _iptables_replace(table: str, chain: str, match: list[str], rule: list[str]) -> None:
    """Usuwa WSZYSTKIE reguły pasujące do `match` (niezależnie od celu), potem dodaje `rule`.

    Samo `-C/-A` tu nie wystarcza, bo reguła zawiera adres kontenera, a ten zmienia się
    przy odtworzeniu stacka. Stara reguła zostawała wtedy w łańcuchu PRZED nową, a iptables
    bierze pierwszą pasującą — ruch z tunelu szedł do kontenera, którego już tam nie ma
    (albo, gorzej, do innego, który wskoczył na zwolniony adres). Objawiało się to panelem
    nieosiągalnym przez tunel po zwykłym `docker compose up -d`.
    """
    listing = run(["iptables", "-t", table, "-S", chain], check=False)
    for line in listing.splitlines():
        if not line.startswith(f"-A {chain} "):
            continue
        if all(token in line for token in match):
            spec = line.split(" ", 2)[2]  # bez wiodącego "-A <chain>"
            run(["iptables", "-t", table, "-D", chain, *spec.split()], check=False)
    run(["iptables", "-t", table, "-A", chain, *rule])


def tunnel_subnet() -> str | None:
    """Podsieć tunelu odczytana z adresu interfejsu (np. "10.77.0.0/22")."""
    for line in run(["ip", "-4", "-o", "addr", "show", WG_INTERFACE], check=False).splitlines():
        parts = line.split()
        if "inet" in parts:
            return str(ipaddress.ip_interface(parts[parts.index("inet") + 1]).network)
    return None


def _ensure_nat_dnat() -> None:
    """MASQUERADE dla ruchu wychodzącego przez wg-mt + DNAT portu SFTP na backend."""
    # Maskujemy tylko ruch SPOZA tunelu (backend z sieci dockera — routery nie znają do
    # niej trasy). Ruch peer -> hub -> peer zachowuje adres źródłowy: inaczej Winbox
    # z peera administracyjnego docierał do routera z adresem huba i reguła na liście
    # mtm-admin go nie łapała, a router innego klienta podszywał się pod hub.
    subnet = tunnel_subnet()
    rule = ["-o", WG_INTERFACE, "-j", "MASQUERADE"]
    if subnet:
        rule = ["!", "-s", subnet, *rule]
    else:
        print("[agent] WARNING: nie odczytano podsieci tunelu, MASQUERADE dla calego ruchu", flush=True)
    _iptables_replace("nat", "POSTROUTING", [f"-o {WG_INTERFACE}", "-j MASQUERADE"], rule)

    backend_ip = None
    for _ in range(30):
        try:
            backend_ip = socket.gethostbyname("backend")
            break
        except OSError:
            __import__("time").sleep(1)
    if backend_ip:
        _iptables_replace("nat", "PREROUTING",
            [f"-i {WG_INTERFACE}", f"--dport {BACKUP_SFTP_PORT}", "-j DNAT"],
            ["-i", WG_INTERFACE, "-p", "tcp", "--dport", BACKUP_SFTP_PORT,
             "-j", "DNAT", "--to-destination", f"{backend_ip}:{BACKUP_SFTP_PORT}"])
        print(f"[agent] DNAT SFTP {WG_INTERFACE}:{BACKUP_SFTP_PORT} -> {backend_ip}", flush=True)
        # Syslog: UDP, urządzenia pushują wpisy na hub. Ten sam wzorzec co SFTP —
        # port nigdzie nie publikowany na hosta, osiągalny wyłącznie przez tunel.
        _iptables_replace("nat", "PREROUTING",
            [f"-i {WG_INTERFACE}", f"--dport {SYSLOG_PORT}", "-j DNAT"],
            ["-i", WG_INTERFACE, "-p", "udp", "--dport", SYSLOG_PORT,
             "-j", "DNAT", "--to-destination", f"{backend_ip}:{SYSLOG_PORT}"])
        print(f"[agent] DNAT syslog {WG_INTERFACE}:{SYSLOG_PORT}/udp -> {backend_ip}", flush=True)

    # Panel przez tunel: peer administracyjny ma widziec portal pod adresem huba.
    # Bez tego łącznosc tunelem jest, ale panel nieosiagalny — Caddy stoi w innym
    # kontenerze i publikuje port na hoscie (przy CADDY_BIND=127.0.0.1 tylko na petli).
    caddy_ip = None
    for _ in range(30):
        try:
            caddy_ip = socket.gethostbyname("caddy")
            break
        except OSError:
            __import__("time").sleep(1)
    if caddy_ip:
        _iptables_replace("nat", "PREROUTING",
            [f"-i {WG_INTERFACE}", f"--dport {CADDY_PORT}", "-j DNAT"],
            ["-i", WG_INTERFACE, "-p", "tcp", "--dport", CADDY_PORT,
             "-j", "DNAT", "--to-destination", f"{caddy_ip}:{CADDY_PORT}"])
        # MASQUERADE WYLACZNIE dla tego strumienia. Caddy nie ma trasy do podsieci
        # tunelu (ma ja tylko backend), wiec bez podmiany adresu zrodlowego odpowiedzi
        # poleciałyby w bramę dockera i przepadly. Celowo waskie: przy SFTP i syslogu
        # adres zrodlowy MUSI zostac nietkniety, bo po nim rozpoznajemy urzadzenie.
        _iptables_replace("nat", "POSTROUTING",
            [f"--dport {CADDY_PORT}", "-j MASQUERADE"],
            ["-p", "tcp", "-d", caddy_ip, "--dport", CADDY_PORT, "-j", "MASQUERADE"])
        print(f"[agent] DNAT panel {WG_INTERFACE}:{CADDY_PORT} -> {caddy_ip}", flush=True)
    else:
        print("[agent] WARNING: nie rozwiazano 'caddy', panel przez tunel niedostepny", flush=True)
    if not backend_ip:
        print("[agent] WARNING: nie rozwiązano 'backend', DNAT SFTP/syslog pominięty", flush=True)


def bring_up() -> None:
    if not interface_up():
        run(["wg-quick", "up", WG_INTERFACE])
        print(f"[agent] {WG_INTERFACE} up, public key: {public_key()}", flush=True)
    _ensure_nat_dnat()


def setup_interface(subnet: str, server_ip: str, private_key: str | None) -> str:
    """Tworzy/przestawia wg-mt: zapisuje klucz (podany = restore, albo generuje),
    conf z podsiecią, podnosi. Zwraca klucz publiczny."""
    net = ipaddress.ip_network(subnet, strict=False)
    mask = net.prefixlen
    os.makedirs(CONF_DIR, exist_ok=True)

    if private_key:
        with open(KEY_FILE, "w") as f:
            f.write(private_key.strip())
    elif not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "w") as f:
            f.write(run(["wg", "genkey"]).strip())
    os.chmod(KEY_FILE, 0o600)

    with open(KEY_FILE) as f:
        priv = f.read().strip()
    with _CONF_LOCK:
        # Sekcje [Peer] z dotychczasowego pliku ZOSTAJA. Dawniej plik byl przepisywany
        # samym [Interface], wiec kazde przestawienie interfejsu kasowalo z dysku cala flote
        # — po nastepnym restarcie kontenera hub nie znal zadnego routera.
        peers = []
        if os.path.exists(CONF_FILE):
            with open(CONF_FILE) as f:
                peers = _peer_blocks(f.read())
        content = f"[Interface]\nAddress = {server_ip}/{mask}\nListenPort = {WG_PORT}\nPrivateKey = {priv}\n"
        _write_conf(content + "".join(f"\n{b}\n" for b in peers))

        if interface_up():
            run(["wg-quick", "down", WG_INTERFACE], check=False)
        bring_up()
    return public_key()


def get_peers() -> list[dict]:
    if not interface_up():
        return []
    lines = run(["wg", "show", WG_INTERFACE, "dump"]).strip().split("\n")
    saved = persisted_keys()
    peers = []
    for line in lines[1:]:
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pk, _psk, endpoint, allowed, handshake, rx, tx, _keep = parts
        peers.append({
            "public_key": pk,
            "endpoint": None if endpoint == "(none)" else endpoint,
            "allowed_ips": allowed,
            "latest_handshake": int(handshake),
            "transfer_rx": int(rx),
            "transfer_tx": int(tx),
            # Dziala w pamieci != przetrwa restart kontenera. Portal przy odtwarzaniu kopii
            # pomija tylko peery, ktore sa i tu, i w pliku.
            "persisted": pk in saved,
        })
    return peers


def add_peer(pubkey: str, allowed_ip: str, psk: str | None = None) -> None:
    """Peer w dzialajacym WireGuard I w pliku konfiguracyjnym — albo w zadnym z nich.
    Dawniej blad zapisu do pliku zostawial peera tylko w pamieci: dzialal do restartu
    kontenera, a portal (odtwarzanie kopii) widzial go na hubie i uznawal sprawe za
    zalatwiona (wytkniete w czwartej recenzji). Teraz nieudany zapis cofa peera z interfejsu
    i zwraca blad, a /peers mowi, czy peer jest zapisany (`persisted`)."""
    args = ["wg", "set", WG_INTERFACE, "peer", pubkey, "allowed-ips", f"{allowed_ip}/32"]
    tmp = None
    if psk:
        import tempfile
        fd, tmp = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write(psk)
        args += ["preshared-key", tmp]  # wg nie przyjmuje PSK inline — tylko z pliku
    with _CONF_LOCK:
        was_running = pubkey in {p["public_key"] for p in get_peers()}
        try:
            run(args)
        finally:
            if tmp:
                os.remove(tmp)
        try:
            _persist_add(pubkey, allowed_ip, psk)
        except Exception:
            if not was_running:
                run(["wg", "set", WG_INTERFACE, "peer", pubkey, "remove"], check=False)
            raise


def remove_peer(pubkey: str) -> None:
    with _CONF_LOCK:
        run(["wg", "set", WG_INTERFACE, "peer", pubkey, "remove"])
        _persist_remove(pubkey)


# Jeden zapis pliku naraz: serwer agenta jest wielowatkowy, a zapis to odczyt-zmiana-zapis
# — dwa rownolegle dodania gubily jeden z peerow.
_CONF_LOCK = threading.RLock()
_PEER_BLOCK = re.compile(r"\n?\[Peer\]\n(?:[^\[\n][^\n]*\n?)*")


def _write_conf(content: str) -> None:
    """Zapis atomowy: plik obok + fsync + rename. Przerwany zapis zostawia stary plik,
    nigdy pusty albo uciety (a ucieta konfiguracja to hub bez floty po restarcie)."""
    tmp = CONF_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF_FILE)


def _peer_blocks(content: str) -> list[str]:
    return [m.group(0).strip("\n") for m in _PEER_BLOCK.finditer(content)]


def persisted_keys() -> set[str]:
    try:
        with open(CONF_FILE) as f:
            content = f.read()
    except OSError:
        return set()
    return set(re.findall(r"^PublicKey = (\S+)$", content, re.M))


def _persist_add(pubkey: str, allowed_ip: str, psk: str | None = None) -> None:
    with open(CONF_FILE) as f:
        content = f.read()
    if f"PublicKey = {pubkey}\n" in content:
        return
    block = f"\n[Peer]\nPublicKey = {pubkey}\n"
    if psk:
        block += f"PresharedKey = {psk}\n"
    block += f"AllowedIPs = {allowed_ip}/32\n"
    _write_conf(content.rstrip("\n") + "\n" + block)


def _persist_remove(pubkey: str) -> None:
    with open(CONF_FILE) as f:
        content = f.read()
    pattern = re.compile(r"\n?\[Peer\]\nPublicKey = " + re.escape(pubkey) + r"\n(?:[^\[\n][^\n]*\n)*")
    _write_conf(pattern.sub("", content))


class Handler(BaseHTTPRequestHandler):
    def _authorized(self) -> bool:
        return not AGENT_TOKEN or self.headers.get("X-Agent-Token") == AGENT_TOKEN

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    def do_GET(self):
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        try:
            if self.path == "/peers":
                return self._send(200, get_peers())
            if self.path == "/status":
                return self._send(200, {
                    "configured": os.path.exists(CONF_FILE),
                    "up": interface_up(),
                    "public_key": public_key(),
                    "listen_port": WG_PORT,
                    "version": os.environ.get("MTM_BUILD_VERSION") or "dev",
                })
            if self.path == "/privatekey":
                if not os.path.exists(KEY_FILE):
                    return self._send(404, {"error": "brak klucza"})
                with open(KEY_FILE) as f:
                    return self._send(200, {"private_key": f.read().strip()})
        except Exception as e:
            self._log_exception("GET", self.path, e)
            return self._send(500, {"error": str(e)})
        return self._send(404, {"error": "not found"})

    def _log_exception(self, method: str, path: str, exc: Exception) -> None:
        """Bez tego 500 przepadal bez sladu — w logu byl tylko wiersz dostepu, a przyczyna
        znana wylacznie temu, kto recznie powtorzyl operacje w kontenerze."""
        import traceback
        print(f"[agent] BLAD {method} {path}: {type(exc).__name__}: {exc}", flush=True)
        traceback.print_exc()

    def do_POST(self):
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        try:
            if self.path == "/setup":
                b = self._body()
                subnet, server_ip = b.get("subnet"), b.get("server_ip")
                if not subnet or not server_ip:
                    return self._send(400, {"error": "subnet i server_ip wymagane"})
                pk = setup_interface(subnet, server_ip, b.get("private_key"))
                return self._send(200, {"status": "ok", "public_key": pk})
            if self.path == "/peers":
                b = self._body()
                pubkey, allowed_ip = b.get("public_key"), b.get("allowed_ip")
                if not pubkey or not allowed_ip:
                    return self._send(400, {"error": "public_key i allowed_ip wymagane"})
                add_peer(pubkey, allowed_ip, b.get("preshared_key"))
                return self._send(201, {"status": "ok"})
        except Exception as e:
            self._log_exception("POST", self.path, e)
            return self._send(500, {"error": str(e)})
        return self._send(404, {"error": "not found"})

    def do_DELETE(self):
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        if self.path == "/peers":
            b = self._body()
            pubkey = b.get("public_key")
            if not pubkey:
                return self._send(400, {"error": "public_key wymagany"})
            try:
                remove_peer(pubkey)
                return self._send(200, {"status": "ok"})
            except Exception as e:
                self._log_exception("DELETE", self.path, e)
                return self._send(500, {"error": str(e)})
        return self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        print(f"[agent] {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    # Istniejący/przywrócony stack: konfiguracja już jest -> podnieś tunel.
    # Świeża instalacja: czekaj na /setup od kreatora.
    if os.path.exists(CONF_FILE):
        try:
            bring_up()
        except Exception as e:
            print(f"[agent] bring_up przy starcie nieudane: {e}", flush=True)
    else:
        print("[agent] brak konfiguracji wg-mt — czekam na /setup (kreator)", flush=True)

    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"wg-agent listening on :{PORT}", flush=True)
    server.serve_forever()
