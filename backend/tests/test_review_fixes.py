"""Poprawki po recenzji zewnetrznej (2026-10-03) — to, co da sie sprawdzic bez bazy i sprzetu.
Usuwanie urzadzen, retencja i odtwarzanie kopii portalu wymagaja bazy — sa w scenariuszach
na labie (tests/README.md)."""
import asyncio
import types

import httpx
import pytest

from app import setup_token
from app.auth import session_fingerprint
from app.routers.devices import ros_quote
from app.routers.setup import _validate_endpoint, _validate_network
from app.templating import _Templates, plural


# ---- skrypty RouterOS: tekst uzytkownika w cudzyslowie ----

@pytest.mark.parametrize("raw,quoted", [
    ('Biuro "Parter"', 'Biuro \\"Parter\\"'),
    ("koszt $5?", "koszt \\$5\\?"),
    ("C:\\dane", "C:\\\\dane"),
    ("dwie\nlinie", "dwie linie"),
    ("AP DÓŁ", "AP DÓŁ"),
])
def test_ros_quote(raw, quoted):
    assert ros_quote(raw) == quoted


# ---- kreator: siec i adres huba ----

@pytest.mark.parametrize("ip,mask", [
    ("127.0.0.1", "24"),     # is_private przepuszczal loopback
    ("169.254.1.1", "24"),   # ... i link-local
    ("fc00::1", "8"),        # ... i IPv6
    ("8.8.8.8", "24"),       # publiczny
    ("172.16.0.1", "11"),    # maska wyprowadza siec poza pule RFC 1918
    ("172.20.0.1", "24"),    # pula Dockera
    ("10.90.0.0", "22"),     # adres sieci
])
def test_wizard_rejects(ip, mask):
    net, error = _validate_network(ip, mask)
    assert net is None and error


@pytest.mark.parametrize("ip,mask", [("10.90.0.1", "22"), ("172.16.0.1", "16"), ("192.168.50.1", "24")])
def test_wizard_accepts(ip, mask):
    net, error = _validate_network(ip, mask)
    assert error is None and net is not None


@pytest.mark.parametrize("value,ok", [
    ("vpn.firma.pl", True), ("203.0.113.109", True), ("hx4k2m9q7tz.sn.mynetname.net", True),
    ('x" ; /system reset', False), ("host:51820", False), ("", False), ("-zly.pl", False),
])
def test_hub_endpoint(value, ok):
    assert (_validate_endpoint(value) is None) is ok


# ---- token instalacyjny ----

def test_setup_token(tmp_path, monkeypatch):
    monkeypatch.setattr(setup_token, "_SECRETS_DIR", str(tmp_path))
    monkeypatch.setattr(setup_token, "_PATH", str(tmp_path / "setup.token"))
    token = setup_token.ensure()
    assert setup_token.ensure() == token             # restart nie zmienia tokenu
    assert setup_token.check(token)
    assert setup_token.check(token.lower().replace("-", ""))   # wpisany bez myslnikow i malymi
    assert not setup_token.check("AAAA-BBBB-CCCC")
    assert not setup_token.check("")
    setup_token.consume()
    assert not setup_token.check(token)              # po zalozeniu portalu nie dziala


# ---- sesje ----

def test_session_fingerprint_changes_with_password():
    a, b = session_fingerprint("hash-1"), session_fingerprint("hash-2")
    assert a == session_fingerprint("hash-1") and a != b
    assert "hash-1" not in a                          # sam hash nie trafia do ciasteczka


# ---- odmiana i warstwa zgodnosci szablonow ----

@pytest.mark.parametrize("n,word", [(1, "peer"), (2, "peery"), (4, "peery"), (5, "peerów"),
                                    (12, "peerów"), (14, "peerów"), (22, "peery"), (25, "peerów")])
def test_plural(n, word):
    assert plural(n, "peer", "peery", "peerów") == word


def test_template_shim_old_and_new_style(tmp_path):
    from starlette.requests import Request
    (tmp_path / "t.html").write_text("{{ request.method }}:{{ x }}", encoding="utf-8")
    t = _Templates(directory=str(tmp_path))
    req = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})
    old = t.TemplateResponse("t.html", {"request": req, "x": 1}, status_code=400)
    new = t.TemplateResponse(req, "t.html", {"x": 1}, status_code=400)
    assert old.body == new.body == b"GET:1"
    assert old.status_code == new.status_code == 400


# ---- restart: kod HTTP ----

def _device():
    from app.models import Device
    from app.security import encrypt
    return Device(name="t", api_username="u", api_password_encrypted=encrypt("p"), wg_ip="10.0.0.2")


class _FakeClient:
    def __init__(self, outcome):
        self.outcome = outcome

    def __call__(self, *a, **kw):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return httpx.Response(self.outcome, text="odmowa")


@pytest.mark.parametrize("outcome,ok,unconfirmed", [
    (200, True, False),
    (403, False, False),                                        # wczesniej: ok=True
    # Polecenie nie wyszlo — druga recenzja: wczesniej kazdy wyjatek dawal ok=True
    (httpx.ConnectError("connection refused"), False, False),
    (httpx.ConnectTimeout("timeout zestawiania"), False, False),
    # Polecenie wyszlo, odpowiedz nie przyszla — typowe przy restarcie, ale niepotwierdzone
    (httpx.ReadTimeout("brak odpowiedzi"), True, True),
    (httpx.RemoteProtocolError("server disconnected"), True, True),
])
def test_reboot_outcomes(monkeypatch, outcome, ok, unconfirmed):
    from app import routeros_client
    monkeypatch.setattr(routeros_client.httpx, "AsyncClient", _FakeClient(outcome))
    result = asyncio.run(routeros_client.reboot(_device()))
    assert result["ok"] is ok
    assert bool(result.get("unconfirmed")) is unconfirmed


def test_reboot_fails_when_password_cannot_be_decrypted():
    from app import routeros_client
    from app.models import Device
    dev = Device(name="t", api_username="u", api_password_encrypted="to-nie-jest-token-fernet", wg_ip="10.0.0.2")
    result = asyncio.run(routeros_client.reboot(dev))
    assert result["ok"] is False


# ---- aktualizacje: powrot online to dopiero NOWA instancja ----

class _FakeSession:
    def add(self, obj):
        pass

    async def commit(self):
        pass


def _run_wait(monkeypatch, statuses, uptime_before):
    from app import update_orchestrator as o
    seq = iter(statuses)

    async def fake_status(device):
        return next(seq, statuses[-1])

    monkeypatch.setattr(o, "get_status", fake_status)
    monkeypatch.setattr(o, "_POLL_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(o, "settings", types.SimpleNamespace(update_wait_timeout_seconds=0.3))
    return asyncio.run(o._wait_until_online(_FakeSession(), None, types.SimpleNamespace(id=None), uptime_before))


def test_wait_ignores_old_instance_then_accepts_rebooted(monkeypatch):
    statuses = [{"reachable": True, "uptime": "1h40s"},     # jeszcze stara instancja
                {"reachable": False},                        # restart
                {"reachable": True, "uptime": "35s"}]        # nowa instancja
    assert _run_wait(monkeypatch, statuses, uptime_before=3600 + 30) is True


def test_wait_fails_when_router_never_rebooted(monkeypatch):
    statuses = [{"reachable": True, "uptime": "2h"}]         # odpowiada, ale ciagle stara instancja
    assert _run_wait(monkeypatch, statuses, uptime_before=7000) is False
