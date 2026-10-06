"""Poprawki po DRUGIEJ recenzji zewnetrznej — scenariusze awarii, ktorych nie da sie
bezpiecznie wywolac na zywym portalu: blad po commicie bazy, niedostepny agent WireGuard,
klucz Fernet z innej instalacji, kopia zrobiona w trakcie aktualizacji, wyscig przydzialu IP,
syslog po ponownym uzyciu adresu, cudzy cel pingu.

Baza i agent sa tu atrapami: liczy sie, CO funkcja robi z dyskiem, znacznikiem w bazie
i wynikiem, a to atrapy pokazuja dokladnie. Prawdziwa baza — w tests/lab/restore_isolated.py."""
import asyncio
import datetime
import io
import json
import os
import re
import tarfile
import types
import uuid

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from app import portal_backup as pb
from app import security
from app.models import AdminPeer, Device, DeviceLogEntry, PingTarget, Setting, UpdateRun, UpdateRunStep


# =====================================================================
# Odtwarzanie kopii portalu
# =====================================================================

class _R:
    def __init__(self, rows=(), scalar=None):
        self._rows, self._scalar = list(rows), scalar

    def scalars(self):
        return self

    def all(self):
        return self._rows

    def scalar(self):
        return self._scalar


class _FakeDB:
    """Baza z istotnym stanem: znacznik odtwarzania (zatwierdzony albo nie), urzadzenia
    i peery admina. Tryby awarii:
      fail_commit      — commit odrzucony, nic nie zapisane,
      commit_then_fail — commit ZAPISANY, ale potwierdzenie nie dochodzi (zerwane polaczenie),
      fail_finalize    — commit usuwajacy znacznik po dokonczeniu sie nie udaje,
      down             — baza nieosiagalna (kazde zapytanie)."""

    def __init__(self):
        self.marker = None
        self.fail_commit = self.commit_then_fail = self.fail_finalize = self.down = False
        self.commits = 0
        self.inserted: list = []
        self.devices: list = []
        self.admin_peers: list = []

    def session(self):
        return _FakeSession(self)


class _FakeSession:
    def __init__(self, db):
        self.db, self.marker, self.added, self.finalizing = db, db.marker, [], False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def execute(self, stmt, *a, **kw):
        if self.db.down:
            raise ConnectionError("baza nieosiagalna")
        sql = str(stmt)
        if sql.startswith("DELETE FROM settings"):
            self.marker = None
            self.finalizing = "WHERE" in sql
        elif sql.startswith("SELECT settings.value"):
            return _R(scalar=self.marker)
        elif sql.startswith("SELECT") and "FROM devices" in sql:
            return _R(rows=list(self.db.devices))
        elif sql.startswith("SELECT") and "FROM admin_peers" in sql:
            return _R(rows=list(self.db.admin_peers))
        return _R()

    def add(self, obj):
        if isinstance(obj, Setting) and obj.key == pb._PENDING_SETTING:
            self.marker = obj.value
        self.added.append(obj)

    def add_all(self, objs):
        self.added.extend(objs)

    async def flush(self):
        pass

    async def delete(self, obj):
        self.db.admin_peers = [p for p in self.db.admin_peers if p is not obj]

    async def commit(self):
        if self.db.down:
            raise ConnectionError("baza nieosiagalna")
        if self.db.fail_commit:
            raise RuntimeError("baza odrzucila zapis")
        if self.finalizing and self.db.fail_finalize:
            raise ConnectionError("zerwane polaczenie przy finalizacji")
        self.db.marker = self.marker
        self.db.inserted += self.added
        self.db.commits += 1
        if self.db.commit_then_fail:
            self.db.commit_then_fail = False
            raise ConnectionError("polaczenie zerwane przed potwierdzeniem commitu")

    async def rollback(self):
        pass

    async def close(self):
        pass


class _FakeAgent:
    """Agent WireGuard: interfejs (z kluczem albo bez), peery, licznik przestawien huba."""

    def __init__(self):
        self.available = True
        self.iface_pub = None
        self.peers: set = set()       # dzialaja w interfejsie
        self.saved: set = set()       # zapisane w pliku konfiguracyjnym
        self.setups = 0
        self.add_calls: list = []
        self.fail_peers: set = set()  # agent odrzuca
        self.unsaved: set = set()     # STARY agent: peer dziala, zapis na dysk sie nie udal
        self.on_add = None  # haczyk do wstrzykniecia rownoleglej operacji

    async def status(self):
        if not self.available:
            return None
        return {"up": self.iface_pub is not None, "public_key": self.iface_pub}

    async def ensure_wg_up(self, private_key=None):
        """Logika jak w wg_bringup (sprawdzana osobno w test_ensure_wg_up_*): brak odpowiedzi
        -> nic; przebudowa tylko, gdy hub nie dziala albo dziala z innym kluczem."""
        if not self.available:
            return None
        from app.routerwg.importer import derive_public
        if self.iface_pub is None or (private_key and derive_public(private_key) != self.iface_pub):
            self.setups += 1
            self.iface_pub = derive_public(private_key) if private_key else "nowy-losowy-klucz"
            self.peers.clear()  # w pamieci znikaja; plik agent zachowuje (setup_interface)
        return self.iface_pub

    async def get_peers(self):
        if not self.available:
            return None, "agent niedostepny"
        return [{"public_key": k, "persisted": k in self.saved} for k in self.peers], None

    async def add_peer(self, public_key, allowed_ip, psk=None):
        self.add_calls.append(public_key)
        if self.on_add:
            hook, self.on_add = self.on_add, None
            await hook()
        if not self.available or public_key in self.fail_peers:
            return False, "blad agenta"
        self.peers.add(public_key)
        if public_key in self.unsaved:
            return False, "zapis konfiguracji nieudany"
        self.saved.add(public_key)
        return True, None

    async def remove_peer(self, public_key):
        self.peers.discard(public_key)
        self.saved.discard(public_key)
        return True, None


def _archive(fernet_key: bytes, data_key: bytes | None = None, extra_db: dict | None = None) -> tuple[bytes, str]:
    """Kopia portalu: sekret SMTP zaszyfrowany `data_key` (domyslnie tym samym kluczem),
    klucz huba, plik kopii urzadzenia. Zwraca (archiwum, klucz publiczny huba)."""
    data_fernet = Fernet(data_key or fernet_key)
    priv, pub = security.generate_wg_keypair()
    db = {"settings": [{"key": "smtp_password_encrypted", "value": data_fernet.encrypt(b"haslo").decode()},
                       {"key": "wg_subnet", "value": "10.9.0.0/24"}]}
    db.update(extra_db or {})
    files = {
        "manifest.json": json.dumps({"format": "mtm-portal-1", "counts": {k: len(v) for k, v in db.items()}}).encode(),
        "db.json": json.dumps(db, default=pb._json_default).encode(),
        "secrets/fernet.key": fernet_key,
        "secrets/session.secret": b"sesja",
        "tls/ca.pem": b"-----CA-----",
        "wg-mt.key": priv.encode(),
        "store/kopia.enc": data_fernet.encrypt(b"binarna kopia"),
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue(), pub


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Katalogi w tmp, atrapa bazy, agent sterowany z testu. Fernet procesu przywracany po tescie."""
    dirs = {d: tmp_path / d for d in ("secrets", "tls", "store")}
    for d in dirs.values():
        d.mkdir()
    monkeypatch.setattr(pb, "SECRETS_DIR", str(dirs["secrets"]))
    monkeypatch.setattr(pb, "TLS_DIR", str(dirs["tls"]))
    monkeypatch.setattr(pb, "STORE_DIR", str(dirs["store"]))
    monkeypatch.setattr(security, "_fernet", security._fernet)

    db = _FakeDB()
    monkeypatch.setattr(pb, "async_session", db.session)

    async def noop():
        pass
    monkeypatch.setattr(pb, "load_wg_config", noop)

    monkeypatch.setattr(pb, "_MARKER_RETRY_SECONDS", 0)

    agent = _FakeAgent()
    monkeypatch.setattr(pb, "ensure_wg_up", agent.ensure_wg_up)
    import app.wg_agent_client as wac
    monkeypatch.setattr(wac, "add_peer", agent.add_peer)
    monkeypatch.setattr(wac, "get_peers", agent.get_peers)
    monkeypatch.setattr(wac, "get_interface_status", agent.status)
    from app import admin_peer_service
    monkeypatch.setattr(admin_peer_service, "remove_peer", agent.remove_peer)

    def leftovers():
        return sorted(f.name for d in dirs.values() for f in d.iterdir()
                      if f.name.endswith((".restore-tmp", ".part")) or "restore-pending" in f.name)

    return types.SimpleNamespace(db=db, dirs=dirs, agent=agent, leftovers=leftovers)


def test_foreign_fernet_key_rejected_before_any_change(env):
    """Klucz poprawny skladniowo, ale z innej instalacji: dawniej baza sie odtwarzala,
    a wyjatek lecial dopiero przy odszyfrowaniu PSK — po commicie."""
    archive, _ = _archive(Fernet.generate_key(), data_key=Fernet.generate_key())
    with pytest.raises(ValueError, match="nie pasuje"):
        asyncio.run(pb.restore_portal(archive))
    assert env.db.commits == 0
    assert not any(f for d in env.dirs.values() for f in d.iterdir())


def test_agent_down_leaves_resumable_restore(env):
    """Agent niedostepny: baza odtworzona, ale klucz huba NIE ginie — czeka na dysku,
    a ponowienie konczy odtwarzanie, gdy agent wroci."""
    key = Fernet.generate_key()
    archive, hub_pub = _archive(key)
    env.agent.available = False

    result = asyncio.run(pb.restore_portal(archive))
    assert result["complete"] is False and "tunel huba" in result["errors"][0]
    journal = pb.pending_restore()
    assert journal is not None and env.db.marker == journal["id"]
    assert os.path.exists(pb._hub_key_path())
    # pliki podmienione mimo braku tunelu, a proces uzywa klucza z kopii
    assert (env.dirs["secrets"] / "fernet.key").read_bytes() == key
    assert security._fernet.decrypt(Fernet(key).encrypt(b"x")) == b"x"

    env.agent.available = True  # agent wrocil
    again = asyncio.run(pb.resume_pending_restore())
    assert again["complete"] is True
    assert pb.pending_restore() is None and env.db.marker is None
    assert env.leftovers() == []


def test_file_swap_failure_after_commit_is_resumable(env, monkeypatch):
    """Blad os.replace PO commicie bazy: dawniej wyjatek bez mozliwosci dokonczenia."""
    archive, hub_pub = _archive(Fernet.generate_key())
    real_replace = os.replace
    failed = []

    def flaky_replace(src, dst):
        if str(src).endswith(pb._TMP_SUFFIX) and not failed:
            failed.append(src)
            raise OSError("dysk pelny")
        return real_replace(src, dst)
    monkeypatch.setattr(pb.os, "replace", flaky_replace)

    result = asyncio.run(pb.restore_portal(archive))
    assert result["complete"] is False and "dysk pelny" in result["errors"][0]
    assert env.db.marker is not None and pb.pending_restore()["attempts"] == 1

    again = asyncio.run(pb.resume_pending_restore())
    assert again["complete"] is True
    assert (env.dirs["tls"] / "ca.pem").read_bytes() == b"-----CA-----"
    assert (env.dirs["store"] / "kopia.enc").exists()
    assert env.leftovers() == []


def test_commit_failure_leaves_nothing_behind(env):
    env.db.fail_commit = True
    archive, _ = _archive(Fernet.generate_key())
    with pytest.raises(RuntimeError):
        asyncio.run(pb.restore_portal(archive))
    assert env.leftovers() == []
    assert not (env.dirs["secrets"] / "fernet.key").exists()


def test_journal_without_committed_marker_is_discarded(env):
    """Awaria miedzy zapisem dziennika a commitem: baza w stanie sprzed proby, wiec
    ponowienie NIE moze niczego podmieniac — tylko sprzata."""
    tmp = env.dirs["secrets"] / ("fernet.key" + pb._TMP_SUFFIX)
    tmp.write_bytes(b"obcy klucz")
    pb._write_file(pb._journal_path(), json.dumps({"id": "abc", "staged": [[str(tmp), str(tmp)[:-12]]]}).encode(), 0o600)
    assert asyncio.run(pb.resume_pending_restore()) is None
    assert env.leftovers() == [] and not (env.dirs["secrets"] / "fernet.key").exists()


def test_running_update_from_archive_is_closed(env):
    """Kopia z historia zrobiona w trakcie aktualizacji: przebieg nie moze wrocic jako
    wiecznie „running" i blokowac nowych aktualizacji."""
    run_id = uuid.uuid4()
    run = {"id": str(run_id), "scope": "device", "status": "running",
           "started_at": datetime.datetime(2026, 10, 1, 12, 0).isoformat()}
    step = {"id": str(uuid.uuid4()), "run_id": str(run_id), "step_type": "software", "status": "running"}
    archive, hub_pub = _archive(Fernet.generate_key(), extra_db={"update_runs": [run], "update_run_steps": [step]})
    result = asyncio.run(pb.restore_portal(archive))
    assert result["complete"] is True and result["runs_closed"] == 1
    restored = [o for o in env.db.inserted if isinstance(o, (UpdateRun, UpdateRunStep))]
    assert restored and all(o.status == "failed" for o in restored)


def test_pending_marker_from_archive_is_not_restored(env):
    archive, hub_pub = _archive(Fernet.generate_key(), extra_db={
        "settings": [{"key": pb._PENDING_SETTING, "value": "stary"}]})
    asyncio.run(pb.restore_portal(archive))
    assert not any(isinstance(o, Setting) and o.value == "stary" for o in env.db.inserted)


# ---- trzecia recenzja ----

def test_commit_confirmed_lost_but_saved_continues(env):
    """COMMIT doszedl, potwierdzenie nie: dawniej sprzatanie kasowalo dziennik i klucz huba,
    a zatwierdzony znacznik zostawal bez niczego do wznowienia."""
    env.db.commit_then_fail = True
    archive, _ = _archive(Fernet.generate_key())
    result = asyncio.run(pb.restore_portal(archive))
    assert result["complete"] is True
    assert env.db.marker is None and env.leftovers() == []


def test_commit_outcome_unknown_keeps_files_for_resume(env, monkeypatch):
    """COMMIT doszedl, a baza zaraz potem nieosiagalna — nie wiadomo, czy zapisala.
    Niczego nie sprzatamy; wznowienie rozstrzyga, gdy baza wroci."""
    env.db.commit_then_fail = True
    real_marker_check = pb._marker_committed

    async def db_gone_then_check(restore_id):
        env.db.down = True
        try:
            return await real_marker_check(restore_id)
        finally:
            env.db.down = False
    monkeypatch.setattr(pb, "_marker_committed", db_gone_then_check)
    archive, _ = _archive(Fernet.generate_key())
    with pytest.raises(pb.RestoreUncertain):
        asyncio.run(pb.restore_portal(archive))
    journal = pb.pending_restore()
    assert journal is not None and os.path.exists(pb._hub_key_path())
    assert any(f.endswith(pb._TMP_SUFFIX) for f in env.leftovers())

    monkeypatch.setattr(pb, "_marker_committed", real_marker_check)
    again = asyncio.run(pb.resume_pending_restore())
    assert again["complete"] is True and env.leftovers() == []
    assert (env.dirs["secrets"] / "fernet.key").exists()


def test_commit_definitely_failed_still_cleans_up(env):
    env.db.fail_commit = True
    archive, _ = _archive(Fernet.generate_key())
    with pytest.raises(RuntimeError):
        asyncio.run(pb.restore_portal(archive))
    assert env.leftovers() == []


def test_wizard_retry_does_not_discard_possibly_committed_journal(env, monkeypatch):
    """Nowa proba w kreatorze nie moze skasowac dziennika, ktory baza mogla zatwierdzic."""
    pb._write_file(pb._journal_path(), json.dumps({"id": "poprzednia", "staged": []}).encode(), 0o600)
    env.db.marker = "poprzednia"
    archive, _ = _archive(Fernet.generate_key())
    with pytest.raises(pb.RestoreUncertain):
        asyncio.run(pb.restore_portal(archive))
    assert pb.pending_restore()["id"] == "poprzednia" and env.db.commits == 0


def _admin_peer(name):
    priv, pub = security.generate_wg_keypair()
    return AdminPeer(id=uuid.uuid4(), name=name, wg_public_key=pub, wg_private_key_encrypted="x",
                     wg_preshared_key_encrypted=None, wg_ip="10.9.0.250")


def test_peer_removed_during_restore_stays_removed(env):
    """Admin odbiera dostep w trakcie dokladania peerow: dawniej odtwarzanie dokladalo go
    z powrotem ze swojej listy — brak w bazie, obecny na hubie, „zakonczone"."""
    from app.admin_peer_service import delete_admin_peer
    keep, revoked = _admin_peer("zostaje"), _admin_peer("odebrany")
    env.db.admin_peers = [keep, revoked]
    deletion = {}

    async def admin_deletes_now():
        deletion["task"] = asyncio.create_task(delete_admin_peer(env.db.session(), revoked))
        for _ in range(5):
            await asyncio.sleep(0)  # bez blokady usuniecie zdazyloby sie w calosci tutaj
    env.agent.on_add = admin_deletes_now

    async def scenario():
        result = await pb.restore_portal(_archive(Fernet.generate_key())[0])
        ok, _ = await deletion["task"]
        return result, ok
    result, deleted = asyncio.run(scenario())
    assert result["complete"] is True and deleted
    assert revoked.wg_public_key not in env.agent.peers
    assert revoked not in env.db.admin_peers and keep.wg_public_key in env.agent.peers


def test_retry_adds_missing_peers_without_resetting_hub(env):
    """Jeden uparty peer nie moze co minute zrywac polaczen calej floty."""
    good, bad = _admin_peer("dziala"), _admin_peer("uparty")
    env.db.admin_peers = [good, bad]
    env.agent.fail_peers = {bad.wg_public_key}
    result = asyncio.run(pb.restore_portal(_archive(Fernet.generate_key())[0]))
    assert result["complete"] is False and "peery: 1 z 2" in result["errors"][0]
    assert env.agent.setups == 1

    asyncio.run(pb.resume_pending_restore())          # dalej uparty
    env.agent.fail_peers = set()
    again = asyncio.run(pb.resume_pending_restore())  # wszedl
    assert again["complete"] is True
    assert env.agent.setups == 1, "hub przestawiony ponownie — zerwalby dzialajace polaczenia"
    assert env.agent.add_calls.count(good.wg_public_key) == 1
    assert env.agent.peers == {good.wg_public_key, bad.wg_public_key}


def test_finalize_failure_is_reported_not_raised(env):
    env.db.fail_finalize = True
    result = asyncio.run(pb.restore_portal(_archive(Fernet.generate_key())[0]))
    assert result["complete"] is False and result["errors"][0].startswith("finalizacja")
    assert pb.pending_restore()["last_errors"] == result["errors"]

    env.db.fail_finalize = False
    again = asyncio.run(pb.resume_pending_restore())
    assert again["complete"] is True and env.leftovers() == [] and env.db.marker is None


def test_resume_with_database_down_does_not_raise(env):
    """Wolane przy starcie backendu — wyjatek przerwalby uruchomienie aplikacji."""
    env.agent.available = False
    asyncio.run(pb.restore_portal(_archive(Fernet.generate_key())[0]))
    env.db.down = True
    result = asyncio.run(pb.resume_pending_restore())
    assert result["complete"] is False and "baza" in result["errors"][0]
    assert pb.pending_restore() is not None and os.path.exists(pb._hub_key_path())


# ---- czwarta recenzja ----

def test_running_but_unsaved_peer_is_not_success(env):
    """Peer dziala w pamieci huba, ale jego zapis na dysk zawiodl: dawniej ponowienie
    widzialo go na hubie, pomijalo i oglaszalo sukces — po restarcie kontenera peer znikal."""
    p = _admin_peer("bez-zapisu")
    env.db.admin_peers = [p]
    env.agent.unsaved = {p.wg_public_key}
    first = asyncio.run(pb.restore_portal(_archive(Fernet.generate_key())[0]))
    assert first["complete"] is False and "zapisanych" in first["errors"][0]
    assert p.wg_public_key in env.agent.peers  # dziala...

    again = asyncio.run(pb.resume_pending_restore())
    assert again["complete"] is False, "sukces mimo peera, ktory zniknie po restarcie"
    assert pb.pending_restore() is not None

    env.agent.unsaved = set()  # dysk naprawiony
    done = asyncio.run(pb.resume_pending_restore())
    assert done["complete"] is True and p.wg_public_key in env.agent.saved


def test_agent_without_persisted_field_never_confirms(env):
    """Starszy agent nie mowi, czy zapisal — brak potwierdzenia to nie sukces."""
    p = _admin_peer("stary-agent")
    env.db.admin_peers = [p]

    async def old_agent_peers():
        return [{"public_key": k} for k in env.agent.peers], None
    import app.wg_agent_client as wac
    wac_get = wac.get_peers
    wac.get_peers = old_agent_peers
    try:
        result = asyncio.run(pb.restore_portal(_archive(Fernet.generate_key())[0]))
    finally:
        wac.get_peers = wac_get
    assert result["complete"] is False


def _bringup(monkeypatch, status):
    """Prawdziwe ensure_wg_up z atrapa agenta. Zwraca liste wywolan setup_interface."""
    from app import wg_bringup
    calls = []

    async def fake_status():
        return status

    async def fake_setup(subnet, server_ip, private_key=None):
        from app.routerwg.importer import derive_public
        calls.append(private_key)
        return (derive_public(private_key) if private_key else "nowy"), None
    monkeypatch.setattr(wg_bringup, "get_interface_status", fake_status)
    monkeypatch.setattr(wg_bringup, "setup_interface", fake_setup)
    monkeypatch.setattr(wg_bringup, "_add_route", lambda: None)
    monkeypatch.setattr(wg_bringup.wg, "subnet", "10.9.0.0/24")
    monkeypatch.setattr(wg_bringup.wg, "server_ip", "10.9.0.1")
    monkeypatch.setattr(wg_bringup.wg, "hub_endpoint", "hub.example")
    monkeypatch.setattr(wg_bringup.wg, "server_public_key", "")

    async def no_db(*a, **kw):
        pass
    monkeypatch.setattr(wg_bringup, "set_setting", no_db)
    monkeypatch.setattr(wg_bringup, "async_session", lambda: _FakeSession(_FakeDB()))
    return wg_bringup, calls


_PRIV, _PUB = security.generate_wg_keypair()


@pytest.mark.parametrize("status,key,rebuild", [
    (None, _PRIV, False),                               # agent milczy: NIE przebudowujemy
    (None, None, False),
    ({"up": True, "public_key": _PUB}, _PRIV, False),   # hub juz z kluczem z kopii
    ({"up": True, "public_key": "inny"}, _PRIV, True),  # hub z innym kluczem
    ({"up": False, "public_key": None}, _PRIV, True),   # interfejsu nie ma
    ({"up": False, "public_key": None}, None, True),    # swieza instalacja (kreator)
    ({"up": True, "public_key": "biezacy"}, None, False),
], ids=["milczy-z-kluczem", "milczy", "hub-z-kluczem-z-kopii", "hub-z-innym-kluczem", "brak-interfejsu",
        "swieza-instalacja", "dziala-bez-klucza"])
def test_ensure_wg_up_rebuilds_only_on_agent_answer(monkeypatch, status, key, rebuild):
    wg_bringup, calls = _bringup(monkeypatch, status)
    asyncio.run(wg_bringup.ensure_wg_up(key))
    assert bool(calls) is rebuild


def test_restore_done_page_reports_incomplete():
    from app.templating import templates
    html = templates.env.get_template("setup_restore_done.html").render(
        request=None, result={"complete": False, "errors": ["tunel huba: agent niedostępny"],
                              "public_key": None, "peers_injected": 0, "runs_closed": 0, "counts": {}})
    assert "niedokończone" in html and "agent niedostępny" in html


# =====================================================================
# Szablony: zadnych danych w kontekscie JavaScript
# =====================================================================

def test_no_template_values_in_inline_handlers():
    """Przegladarka dekoduje encje HTML w atrybucie PRZED wykonaniem handlera, wiec
    escapowanie Jinja nie chroni onsubmit="confirm('{{ nazwa }}')" — nazwa O'Brien psula
    skrypt, a spreparowana wykonywala wlasny JS. Teksty potwierdzen ida przez data-confirm."""
    offenders = []
    for root, _dirs, files in os.walk("app/templates"):
        for f in files:
            text = open(os.path.join(root, f), encoding="utf-8").read()
            for m in re.finditer(r'\son[a-z]+\s*=\s*"[^"]*\{[{%]', text):
                offenders.append(f"{f}: {m.group(0)[:60]}")
    assert offenders == []


def test_data_confirm_is_wired_in_layout():
    assert "/static/confirm.js" in open("app/templates/base.html", encoding="utf-8").read()
    assert "data-confirm" in open("app/static/confirm.js", encoding="utf-8").read()


def test_hostile_name_stays_data():
    """Nazwa z apostrofem i proba wstrzykniecia trafia do atrybutu jako tekst."""
    from app.templating import templates
    html = templates.env.from_string('<form data-confirm="Usunąć {{ name }}?"></form>').render(
        name="x'); alert(1); ('\" onmouseover=\"alert(2)")
    assert 'onmouseover="' not in html and "&#39;" in html


# =====================================================================
# Przydzial adresow: wspolna blokada
# =====================================================================

class _AllocSession:
    def __init__(self):
        self.statements = []

    async def execute(self, stmt, *a, **kw):
        self.statements.append(str(stmt))
        return _R()


@pytest.mark.parametrize("allocator", ["allocate_ip", "allocate_admin_ip"])
def test_ip_allocators_take_pool_lock_first(monkeypatch, allocator):
    """Blokada PRZED odczytem zajetych adresow — inaczej dwa rownolegle przydzialy
    widza ten sam stan i biora ten sam ostatni wolny adres."""
    monkeypatch.setattr(security.wg, "subnet", "10.0.0.0/29")
    monkeypatch.setattr(security.wg, "server_ip", "10.0.0.1")
    s = _AllocSession()
    asyncio.run(getattr(security, allocator)(s))
    assert "pg_advisory_xact_lock" in s.statements[0]


# =====================================================================
# Syslog: mapa adres -> urzadzenie
# =====================================================================

def _receiver(monkeypatch, current_map):
    from app.syslog_receiver import SyslogReceiver
    r = SyslogReceiver(0)
    r.refreshes = 0

    async def fake_refresh():
        r.refreshes += 1
        r._ip_map = dict(current_map)
        r._ip_map_at = asyncio.get_running_loop().time()
        r._ip_map_stale = False
    monkeypatch.setattr(r, "_refresh_ip_map", fake_refresh)
    return r


def test_syslog_map_follows_reused_address(monkeypatch):
    """Urzadzenie A usuniete, jego adres dostaje B: dawniej adres byl „znany" i wpisy
    szly dalej na A (blad klucza obcego, utrata paczki)."""
    a, b = uuid.uuid4(), uuid.uuid4()
    db_map = {"10.0.0.5": a}
    r = _receiver(monkeypatch, db_map)

    async def scenario():
        await r._refresh_ip_map()
        assert await r._resolve("10.0.0.5") == a
        db_map["10.0.0.5"] = b
        assert await r._resolve("10.0.0.5") == a   # adres „znany" — bez sygnalu jeszcze A
        r.invalidate()                             # po usunieciu / dodaniu urzadzenia
        assert await r._resolve("10.0.0.5") == b
        # bez sygnalu tez: po _IP_MAP_TTL mapa i tak sie odswieza
        db_map["10.0.0.5"] = a
        r._ip_map_at -= 31
        assert await r._resolve("10.0.0.5") == a
    asyncio.run(scenario())


def test_syslog_batch_survives_deleted_device(monkeypatch):
    """Klucz obcy na jednym wpisie nie zabiera paczki calej floty."""
    gone, alive = uuid.uuid4(), uuid.uuid4()
    r = _receiver(monkeypatch, {"10.0.0.9": alive})
    inserted, notified = [], []

    async def fake_insert(batch):
        if any(e.device_id == gone for e in batch):
            raise IntegrityError("INSERT", {}, Exception("violates foreign key constraint"))
        inserted.extend(batch)

    async def fake_after(batch):
        notified.extend(batch)
    monkeypatch.setattr(r, "_insert", fake_insert)
    monkeypatch.setattr(r, "_after_insert", fake_after)

    batch = [DeviceLogEntry(device_id=gone, level="error", topics="t", message="a"),
             DeviceLogEntry(device_id=alive, level="error", topics="t", message="b"),
             DeviceLogEntry(device_id=alive, level="info", topics="t", message="c")]
    asyncio.run(r._store(batch))
    assert [e.message for e in inserted] == ["b", "c"]
    assert [e.message for e in notified] == ["b", "c"]


# =====================================================================
# Cel pingu musi nalezec do urzadzenia z adresu
# =====================================================================

def test_ping_target_of_other_device_is_404(monkeypatch):
    from app.routers import devices as dv
    mine = Device(id=uuid.uuid4(), name="moje", location_id=uuid.uuid4())
    foreign = PingTarget(id=uuid.uuid4(), device_id=uuid.uuid4(), ip="192.168.50.10", label="kamera obca")

    class S:
        async def get(self, model, key):
            return mine if model is Device else foreign

        async def close(self):
            pass

    async def must_not_ping(*a, **kw):
        raise AssertionError("ping obcego celu")
    monkeypatch.setattr(dv, "ping_from_device", must_not_ping)
    request = types.SimpleNamespace(state=types.SimpleNamespace(user=types.SimpleNamespace(role="admin")))
    with pytest.raises(HTTPException) as e:
        asyncio.run(dv.test_ping_target(request, str(mine.id), str(foreign.id), S()))
    assert e.value.status_code == 404
