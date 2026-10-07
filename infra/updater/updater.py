#!/usr/bin/env python3
"""Usluga aktualizacji portalu — jedyny element stacka z dostepem do Dockera.

Po co osobno: zeby portal mogl sie zaktualizowac z przycisku, ktos musi pobrac nowe obrazy
i odtworzyc kontenery — a to wymaga gniazda Dockera, czyli w praktyce roota na hoscie.
Backend (aplikacja webowa z kluczami do calej floty) tego dostepu NIE dostaje. Ma go tylko
ta usluga, a ona umie dokladnie jedno: przestawic TEN stack na podana wersje.

Co wolno z zewnatrz (siec wewnetrzna stacka, token z wolumenu wspoldzielonego z backendem):
  GET  /status  — wersja uslugi, stan ostatniej aktualizacji, dziennik, kontenery stacka
  POST /update  — {"version": "X.Y.Z"}; wylacznie numer wydania, zadnych polecen ani nazw

Kroki aktualizacji (sztywne, bez parametrow z zewnatrz poza numerem wersji):
  1. MTM_VERSION w .env stacka -> nowy numer (stary plik zostaje jako .env.bak),
  2. `docker compose pull backend wireguard` — nieudany pull przywraca .env i konczy,
  3. `docker compose up -d --no-deps backend wireguard`,
  4. kontrola: oba kontenery dzialaja na obrazach z nowym numerem.
Sama usluga NIE aktualizuje sie w trakcie (zabilaby wlasny proces) — nowy obraz updatera
wchodzi przy nastepnym recznym `docker compose up -d`.

Katalog stacka jest zamontowany pod /stack. Docker rozwiazuje sciezki montowan (np.
./Caddyfile) po stronie HOSTA, wiec compose musi dostac prawdziwa sciezke katalogu na
hoscie — usluga odczytuje ja z opisu wlasnego kontenera (zrodlo montowania /stack).
"""
import json
import os
import re
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = os.environ.get("MTM_BUILD_VERSION") or "dev"
DATA_DIR = "/data/updater"
TOKEN_FILE = f"{DATA_DIR}/token"
STATUS_FILE = f"{DATA_DIR}/status.json"
STACK_DIR = "/stack"
PORT = 9091
SERVICES = ("backend", "wireguard")  # tylko obrazy portalu; postgres i caddy maja wlasne
_RELEASE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
_LOG_MAX = 300

_lock = threading.Lock()
_state: dict = {"state": "idle", "log": []}


# ---- pomocnicze ----

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _save() -> None:
    tmp = STATUS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(_state, f)
    os.replace(tmp, STATUS_FILE)


def _log(line: str) -> None:
    _state["log"] = (_state.get("log", []) + [f"{time.strftime('%H:%M:%S')} {line}"])[-_LOG_MAX:]
    print(f"[updater] {line}", flush=True)
    _save()


def _token() -> str:
    """Token generuje backend przy starcie (wolumen wspoldzielony) — czekamy na niego."""
    for _ in range(120):
        try:
            with open(TOKEN_FILE) as f:
                value = f.read().strip()
            if value:
                return value
        except OSError:
            pass
        time.sleep(1)
    raise SystemExit("[updater] brak tokenu od backendu — koncze")


def valid_version(value) -> bool:
    return isinstance(value, str) and bool(_RELEASE.match(value))


def set_env_version(content: str, version: str) -> str:
    """Podmienia (albo dopisuje) MTM_VERSION w tresci .env, reszta pliku bez zmian."""
    lines = content.splitlines()
    out, done = [], False
    for line in lines:
        if re.match(r"^\s*MTM_VERSION\s*=", line):
            out.append(f"MTM_VERSION={version}")
            done = True
        else:
            out.append(line)
    if not done:
        out.append(f"MTM_VERSION={version}")
    return "\n".join(out) + "\n"


def env_version(content: str) -> str | None:
    for line in content.splitlines():
        m = re.match(r"^\s*MTM_VERSION\s*=\s*(\S*)", line)
        if m:
            return m.group(1)
    return None


def stack_from_inspect(info: dict) -> dict:
    """Projekt compose i sciezka katalogu stacka NA HOSCIE z `docker inspect` wlasnego
    kontenera. Bez ktoregos z nich aktualizacja jest niemozliwa — mowimy dlaczego."""
    labels = (info.get("Config") or {}).get("Labels") or {}
    project = labels.get("com.docker.compose.project")
    host_dir = next((m.get("Source") for m in info.get("Mounts") or []
                     if m.get("Destination") == STACK_DIR and m.get("Type") == "bind"), None)
    if not project:
        return {"error": "usluga nie dziala w ramach docker compose (brak etykiety projektu)"}
    if not host_dir:
        return {"error": f"katalog stacka nie jest zamontowany pod {STACK_DIR}"}
    return {"project": project, "host_dir": host_dir}


def compose_base(stack: dict) -> list[str]:
    return ["docker", "compose", "-p", stack["project"], "--project-directory", stack["host_dir"],
            "-f", f"{STACK_DIR}/docker-compose.yml", "--env-file", f"{STACK_DIR}/.env"]


def _write_like(path: str, content: str, like: str) -> None:
    """Zapis atomowy z WLASCICIELEM i PRAWAMI pliku `like`. Usluga dziala jako root: zwykly
    zapis zostawial .env roota (kto uzywa Dockera bez sudo, tracil dostep do wlasnego .env),
    a .env.bak z haslem do bazy powstawal z prawami 644 — czytelny dla kazdego na serwerze
    (oba wyszly w tescie na labie)."""
    st = os.stat(like)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chown(tmp, st.st_uid, st.st_gid)
    os.chmod(tmp, st.st_mode & 0o777)
    os.replace(tmp, path)


def _run(cmd: list[str], timeout: int = 900) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def _stack() -> dict:
    try:
        rc, out = _run(["docker", "inspect", socket.gethostname()], timeout=30)
        if rc != 0:
            return {"error": f"docker inspect nie powiodl sie: {out[-200:]}"}
        return stack_from_inspect(json.loads(out)[0])
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def _containers(stack: dict) -> list[dict]:
    if "error" in stack:
        return []
    rc, out = _run(compose_base(stack) + ["ps", "-a", "--format", "json"], timeout=30)
    if rc != 0:
        return []
    rows = []
    for line in out.splitlines():  # compose v2+: jeden obiekt JSON na linie
        try:
            c = json.loads(line)
        except ValueError:
            continue
        rows.append({"service": c.get("Service"), "image": c.get("Image"), "state": c.get("State"),
                     "status": c.get("Status")})
    return sorted(rows, key=lambda r: r["service"] or "")


# ---- aktualizacja ----

def _update(target: str) -> None:
    stack = _stack()
    env_path = f"{STACK_DIR}/.env"
    try:
        if "error" in stack:
            raise RuntimeError(stack["error"])
        with open(env_path) as f:
            original = f.read()
        previous = env_version(original)
        _state.update({"from": previous})
        _log(f"stack {stack['project']} w {stack['host_dir']}: {previous or '?'} -> {target}")

        _write_like(env_path + ".bak", original, env_path)
        _write_like(env_path, set_env_version(original, target), env_path)
        _log("MTM_VERSION w .env ustawione (poprzednia tresc w .env.bak)")

        _log("pobieram obrazy...")
        rc, out = _run(compose_base(stack) + ["pull", *SERVICES])
        for line in out.splitlines()[-15:]:
            _log("  " + line)
        if rc != 0:
            _write_like(env_path, original, env_path)
            raise RuntimeError(f"pobranie obrazow {target} nie powiodlo sie — .env przywrocone, nic nie zmieniono")

        _log("odtwarzam kontenery backend i wireguard (tunel floty zerwie sie na kilka sekund)...")
        rc, out = _run(compose_base(stack) + ["up", "-d", "--no-deps", *SERVICES])
        for line in out.splitlines()[-15:]:
            _log("  " + line)
        if rc != 0:
            raise RuntimeError("docker compose up nie powiodl sie — szczegoly w dzienniku powyzej")

        time.sleep(5)
        wrong = [c for c in _containers(stack) if c["service"] in SERVICES
                 and (c["state"] != "running" or not (c["image"] or "").endswith(f":{target}"))]
        if wrong:
            raise RuntimeError("po aktualizacji kontenery nie dzialaja na nowej wersji: " +
                               ", ".join(f"{c['service']} {c['image']} {c['state']}" for c in wrong))
        _log(f"gotowe: backend i wireguard dzialaja na {target}")
        _state.update({"state": "done", "finished_at": _now()})
    except Exception as e:
        _log(f"BLAD: {e}")
        _state.update({"state": "failed", "error": str(e), "finished_at": _now()})
    finally:
        _save()
        _lock.release()


# ---- HTTP ----

class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return self.headers.get("X-Updater-Token") == TOKEN

    def do_GET(self):
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        if self.path == "/status":
            stack = _stack()
            return self._send(200, {**_state, "version": VERSION, "stack": stack,
                                    "containers": _containers(stack)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        if self.path != "/update":
            return self._send(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", 0))
            target = json.loads(self.rfile.read(length) or b"{}").get("version")
        except (ValueError, AttributeError):
            return self._send(400, {"error": "zle zadanie"})
        if not valid_version(target):
            return self._send(400, {"error": "wersja musi miec postac X.Y.Z"})
        if not _lock.acquire(blocking=False):
            return self._send(409, {"error": "aktualizacja juz trwa"})
        _state.clear()
        _state.update({"state": "running", "target": target, "started_at": _now(), "log": []})
        _save()
        threading.Thread(target=_update, args=(target,), daemon=True).start()
        return self._send(202, {"status": "started", "target": target})

    def log_message(self, fmt, *args):
        pass  # dziennik zapytan o status co kilka sekund tylko by zasmiecal logi


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        with open(STATUS_FILE) as f:
            _state.update(json.load(f))
        if _state.get("state") == "running":  # przerwane restartem uslugi
            _state.update({"state": "failed", "error": "przerwane restartem uslugi aktualizacji"})
    except (OSError, ValueError):
        pass
    TOKEN = _token()
    print(f"[updater] {VERSION} nasluchuje na :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
