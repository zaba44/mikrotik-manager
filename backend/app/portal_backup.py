"""Kopia i przywracanie CAŁEGO portalu (disaster recovery).

Format `mtm-portal-1` (tar.gz):
  manifest.json      — metadane (format, data, co zawiera, podsumowanie WG)
  db.json            — zrzut tabel (sekrety w wierszach dalej zaszyfrowane Fernetem)
  secrets/fernet.key — KRYTYCZNY: bez niego zaszyfrowane dane w bazie są nie do odczytu
  secrets/session.secret, secrets/backup_sftp.pw
  tls/               — certyfikat panelu i WŁASNE CA (bez CA trzeba by od nowa
                       instalować zaufanie na maszynach administracyjnych)
  wg-mt.key          — klucz PRYWATNY huba (odtwarza tożsamość serwera → flota wraca sama)
  store/<id>.enc     — pliki kopii binarnych urządzeń (tylko gdy include_device_backups)

Podział uzgodniony z użytkownikiem: KONFIGURACJA zawsze, HISTORIA opcjonalnie.
  * zawsze: lokalizacje, użytkownicy, urządzenia, peery admina, blokady PoE, cele pingów,
    wyciszenia powiadomień, ustawienia,
  * opcjonalnie: kopie urządzeń, zdarzenia syslog, historia (przebiegi aktualizacji
    i dziennik wysłanych powiadomień).
Cele pingów i wyciszenia powiadomień brakowało (wytknięte w recenzji zewnętrznej) —
tabele powstały po kopii portalu i nikt ich do niej nie dopisał. To konfiguracja, więc
po odtworzeniu ich brak zmieniał zachowanie portalu.

Format numeru NIE zmieniamy: restore iteruje po tym, co faktycznie jest w archiwum, więc
starsze kopie (bez nowych tabel) wczytują się bez zmian.
"""
import asyncio
import datetime
import io
import json
import logging
import os
import tarfile
import uuid

from sqlalchemy import delete, select, text
from sqlalchemy.dialects.postgresql import INET, UUID as PG_UUID
from sqlalchemy.types import Boolean, DateTime, Integer

from app import security
from app.config import settings
from app.database import async_session
from app.models import (AdminPeer, Backup, Device, DeviceLogEntry, Location, Notification,
                        NotificationOverride, PingTarget, PoeLockedPort, Setting, UpdateRun,
                        UpdateRunStep, User)
from app.wg_agent_client import get_private_key
from app.wg_bringup import ensure_wg_up
from app.wg_config import load_wg_config, wg

logger = logging.getLogger("portal_backup")

SECRETS_DIR = "/data/secrets"
STORE_DIR = "/data/backups/store"
TLS_DIR = "/data/tls"
# Klucz CA MUSI byc w kopii: bez niego po odtworzeniu portalu trzeba by od nowa
# instalowac zaufanie na wszystkich maszynach administracyjnych.
_TLS_FILES = ("ca.pem", "ca.key", "fullchain.pem", "cert.key")
_SECRET_FILES = ("fernet.key", "session.secret", "backup_sftp.pw")

# Kolejność FK-bezpieczna: wstawiamy w tej kolejności, kasujemy w odwrotnej.
# Trzeci element: grupa opcjonalna (None = konfiguracja, zawsze w kopii).
_ORDER = [
    ("locations", Location, None),
    ("users", User, None),
    ("devices", Device, None),
    ("admin_peers", AdminPeer, None),
    ("poe_locked_ports", PoeLockedPort, None),
    ("device_ping_targets", PingTarget, None),
    ("notification_overrides", NotificationOverride, None),
    ("settings", Setting, None),
    ("backups", Backup, "device_backups"),
    ("device_log_entries", DeviceLogEntry, "logs"),
    ("update_runs", UpdateRun, "history"),
    ("update_run_steps", UpdateRunStep, "history"),
    ("notifications", Notification, "history"),
]
# Tabele z kolumna IDENTITY: po wstawieniu jawnych identyfikatorow sekwencja zostaje na
# starcie, a nowe wiersze kolidowalyby z odtworzonymi (wytkniete w recenzji zewnetrznej).
_IDENTITY_TABLES = ("device_log_entries", "notifications")


class BackupError(Exception):
    """Kopia nie powstala — z powodem, ktory trzeba pokazac uzytkownikowi."""


class RestoreUncertain(Exception):
    """Nie wiadomo, czy baza zatwierdzila odtwarzanie — pliki zostaja, rozstrzygnie wznowienie."""


def _json_default(value):
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    return str(value)


def _dump_rows(objs) -> list[dict]:
    out = []
    for obj in objs:
        cols = obj.__table__.columns.keys()
        out.append({c: getattr(obj, c) for c in cols})
    return out


def _secret_bytes(fname: str) -> bytes | None:
    """Plik z wolumenu, a gdy go nie ma — wartosc, ktorej proces faktycznie uzywa (starsze
    instalacje trzymaly sekrety w .env). Kopia ma zawierac klucz W UZYCIU, nie „jakis"."""
    path = os.path.join(SECRETS_DIR, fname)
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    fallback = {"fernet.key": settings.fernet_key, "session.secret": settings.session_secret,
                "backup_sftp.pw": settings.backup_sftp_password}.get(fname)
    return fallback.encode() if fallback else None


async def export_portal(include_device_backups: bool, include_logs: bool = False,
                        include_history: bool = False) -> bytes:
    """Kopie urządzeń, zdarzenia syslog i historia są OPCJONALNE — to one robią rozmiar
    archiwum, a przy odtwarzaniu portalu zwykle liczy się konfiguracja.

    Kopia BEZ klucza huba albo klucza Fernet jest bezwartosciowa (flota sie nie polaczy,
    dane w bazie nie do odczytania), wiec wtedy przerywamy z bledem zamiast wydac plik,
    ktory wyglada na kompletny (wytkniete w recenzji zewnetrznej)."""
    wanted = {None, *(g for g, on in (("device_backups", include_device_backups),
                                      ("logs", include_logs), ("history", include_history)) if on)}

    priv = await get_private_key()
    if not priv:
        raise BackupError("Kanał sterujący WireGuard nie oddał klucza prywatnego huba. Bez niego "
                          "odtworzona instalacja dostałaby nową tożsamość i flota by się nie połączyła — "
                          "kopia NIE została utworzona. Spróbuj ponownie za chwilę.")
    fernet = _secret_bytes("fernet.key")
    if not fernet:
        raise BackupError("Brak klucza szyfrującego (fernet.key) — bez niego dane w kopii byłyby "
                          "nie do odczytania. Kopia NIE została utworzona.")

    async with async_session() as s:
        tables = {}
        for name, model, group in _ORDER:
            if group in wanted:
                tables[name] = _dump_rows((await s.execute(select(model))).scalars().all())

    manifest = {
        "format": "mtm-portal-1",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "includes_device_backups": include_device_backups,
        "includes_logs": include_logs,
        "includes_history": include_history,
        "wg": {
            "subnet": wg.subnet,
            "server_ip": wg.server_ip,
            "hub_endpoint": wg.hub_endpoint,
            "server_public_key": wg.server_public_key,
        },
        "counts": {name: len(rows) for name, rows in tables.items()},
    }

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def add_bytes(path: str, data: bytes):
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mtime = int(datetime.datetime.now().timestamp())
            tar.addfile(info, io.BytesIO(data))

        add_bytes("manifest.json", json.dumps(manifest, ensure_ascii=False).encode())
        add_bytes("db.json", json.dumps(tables, ensure_ascii=False, default=_json_default).encode())

        for fname in _SECRET_FILES:
            data = _secret_bytes(fname)
            if data:
                add_bytes(f"secrets/{fname}", data)

        for fname in _TLS_FILES:
            path = os.path.join(TLS_DIR, fname)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    add_bytes(f"tls/{fname}", f.read())

        add_bytes("wg-mt.key", priv.encode())

        if include_device_backups and os.path.isdir(STORE_DIR):
            for fname in os.listdir(STORE_DIR):
                fpath = os.path.join(STORE_DIR, fname)
                if os.path.isfile(fpath):
                    with open(fpath, "rb") as f:
                        add_bytes(f"store/{fname}", f.read())

    return buf.getvalue()


def _coerce_row(model, row: dict) -> dict:
    """Zamienia str-y z JSON z powrotem na typy kolumn (UUID, datetime)."""
    out = {}
    for col in model.__table__.columns:
        if col.name not in row:
            continue
        val = row[col.name]
        if val is None:
            out[col.name] = None
        elif isinstance(col.type, PG_UUID):
            out[col.name] = uuid.UUID(val)
        elif isinstance(col.type, DateTime):
            out[col.name] = datetime.datetime.fromisoformat(val)
        elif isinstance(col.type, (Boolean, Integer, INET)):
            out[col.name] = val
        else:
            out[col.name] = val
    return out




# ---- Odtwarzanie ----
#
# Odtwarzanie ma dwie czesci o roznej naturze: BAZA (jedna transakcja — albo cala, albo nic)
# i ZEWNETRZNY SWIAT po commicie (podmiana plikow sekretow, tunel huba u agenta, peery).
# Tej drugiej nie da sie zamknac w transakcji, wiec musi byc WZNAWIALNA (wytkniete w drugiej
# recenzji: po commicie blad os.replace, niedostepny agent albo nieudane peery zostawialy
# baze odtworzona, a klucz huba z archiwum ginal razem z zadaniem HTTP — kolejny start
# mogl wygenerowac nowy klucz i flota nie wracala).
#
# Mechanizm: przed commitem WSZYSTKO, czego potrzebuje druga czesc, laduje na dysku (pliki
# tymczasowe, klucz huba, dziennik). W tej samej transakcji co dane trafia do bazy znacznik
# z identyfikatorem odtwarzania. Dziennik na dysku + znacznik w bazie = commit sie udal,
# druga czesc do dokonczenia. Dziennik bez znacznika = commit sie nie udal, smieci do
# sprzatniecia. Dokonczenie jest idempotentne i ponawiane: przy starcie backendu, co minute
# z harmonogramu i przyciskiem w Ustawieniach — az tunel i wszystkie peery potwierdza.

_PENDING_SETTING = "portal_restore_pending"
_TMP_SUFFIX = ".restore-tmp"
# Jedna blokada na cale odtwarzanie i jego dokonczanie: harmonogram nie moze uznac
# dziennika trwajacego wlasnie odtwarzania (jeszcze bez commitu) za porzucony.
_restore_lock = asyncio.Lock()


def _journal_path() -> str:
    return os.path.join(SECRETS_DIR, "restore-pending.json")


def _hub_key_path() -> str:
    return os.path.join(SECRETS_DIR, "wg-mt.key.restore-pending")


def _write_file(path: str, data: bytes, mode: int) -> None:
    """Zapis atomowy: plik tymczasowy obok i os.replace — po awarii albo stary, albo nowy."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".part"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _write_staged(directory: str, files: dict[str, bytes], mode_for, staged: list[list[str]]) -> None:
    """Zapis do plikow tymczasowych OBOK docelowych (ten sam system plikow), bez podmiany.
    Dopisuje pary [tymczasowy, docelowy] do `staged` NA BIEZACO — blad w polowie zostawia
    liste tego, co faktycznie powstalo i trzeba posprzatac."""
    for fname, data in files.items():
        final = os.path.join(directory, fname)
        tmp = final + _TMP_SUFFIX
        staged.append([tmp, final])
        _write_file(tmp, data, mode_for(fname))


def _undecryptable(fernet, prepared, store_files: dict[str, bytes]) -> str | None:
    """Czy klucz z kopii odszyfruje to, co kopia zawiera. Klucz moze byc poprawny skladniowo,
    a z INNEJ instalacji (pomylone pliki) — wtedy wszystko by sie odtworzylo, a potem kazde
    haslo API, PSK i kopia urzadzenia bylyby nie do odczytu. Sprawdzamy PRZED zapisem."""
    from cryptography.fernet import InvalidToken
    for name, model, rows in prepared:
        cols = [c for c in model.__table__.columns.keys() if c.endswith("_encrypted")]
        for obj in rows:
            values = [getattr(obj, c) for c in cols]
            if model is Setting and obj.key.endswith("_encrypted"):
                values.append(obj.value)
            for value in values:
                if not value:
                    continue
                try:
                    fernet.decrypt(value.encode())
                except InvalidToken:
                    return name
    for fname, data in store_files.items():
        try:
            fernet.decrypt(data)
        except InvalidToken:
            return f"store/{fname}"
    return None


def _close_running_history(prepared) -> int:
    """Kopia z historia zrobiona w trakcie aktualizacji zawiera przebieg „running", ale
    zadanie, ktore go prowadzilo, nie wraca razem z kopia. Bez tego przebieg wisialby
    w nieskonczonosc i blokowal nowe aktualizacje urzadzenia/lokalizacji (sprzatanie przy
    starcie backendu juz sie odbylo)."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)  # kolumny bez strefy, jak _utcnow
    closed = 0
    for _name, model, rows in prepared:
        if model is UpdateRun:
            for run in rows:
                if run.status == "running":
                    run.status = "failed"
                    run.finished_at = run.finished_at or now
                    run.error_message = "Przerwane — kopia portalu powstała w trakcie aktualizacji"
                    closed += 1
        elif model is UpdateRunStep:
            for step in rows:
                if step.status == "running":
                    step.status = "failed"
                    step.finished_at = step.finished_at or now
    return closed


def _discard(staged: list[list[str]]) -> None:
    """Sprzatniecie po odtwarzaniu, ktorego baza nie zatwierdzila (albo po dokonczonym)."""
    for path in [tmp for tmp, _final in staged] + [_hub_key_path(), _journal_path()]:
        try:
            os.remove(path)
        except OSError:
            pass


async def _marker_committed(restore_id: str) -> bool | None:
    """Czy w bazie jest zatwierdzony znacznik TEGO odtwarzania. None = nie da sie sprawdzic
    (baza nieosiagalna) — wtedy nie wolno ani sprzatac, ani dokanczac."""
    for attempt in range(3):
        try:
            async with async_session() as s:
                marker = (await s.execute(select(Setting.value).where(Setting.key == _PENDING_SETTING))).scalar()
            return marker == restore_id
        except Exception as e:
            logger.warning("Nie mogę odczytać znacznika odtwarzania (%s), próba %d", e, attempt + 1)
            await asyncio.sleep(_MARKER_RETRY_SECONDS)
    return None


_MARKER_RETRY_SECONDS = 1.0


def pending_restore() -> dict | None:
    """Dziennik niedokonczonego odtwarzania (do pokazania w Ustawieniach) albo None."""
    try:
        with open(_journal_path()) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


async def restore_portal(archive_bytes: bytes) -> dict:
    """Przywraca portal z paczki (na ŚWIEŻEJ instalacji).

      1. walidacja CALEGO archiwum, przygotowanie wierszy, proba odszyfrowania wszystkich
         sekretow kluczem z kopii — nic jeszcze nie ruszone,
      2. pliki tymczasowe (sekrety, TLS, kopie urzadzen), klucz huba i dziennik na dysk,
      3. baza w JEDNEJ transakcji razem ze znacznikiem odtwarzania; blad -> rollback
         i sprzatniecie, portal jak przed proba,
      4. dokonczenie (_finish): podmiana plikow, tunel, peery — wznawialne az do skutku.
    Bledy z punktow 1–3 sa wyjatkami (nic nie zmieniono); od punktu 4 wynik z complete=False.
    """
    # ---- 1. walidacja ----
    try:
        tar = tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz")
    except (tarfile.TarError, OSError) as e:
        raise ValueError(f"To nie jest archiwum kopii portalu ({e}).")
    with tar:
        members = {m.name: m for m in tar.getmembers() if m.isfile()}

        def read(path):
            return tar.extractfile(members[path]).read() if path in members else None

        manifest = json.loads(read("manifest.json") or b"{}")
        if manifest.get("format") != "mtm-portal-1":
            raise ValueError("Nieznany format kopii (oczekiwano mtm-portal-1).")
        db = json.loads(read("db.json") or b"{}")
        secrets_files = {f: read(f"secrets/{f}") for f in _SECRET_FILES}
        if not secrets_files.get("fernet.key"):
            raise ValueError("W kopii brakuje klucza szyfrującego (fernet.key) — dane z bazy byłyby nie do odczytu.")
        wg_priv = read("wg-mt.key")
        if not wg_priv:
            raise ValueError("W kopii brakuje klucza prywatnego huba (wg-mt.key) — odtworzony hub dostałby "
                             "nową tożsamość i flota by się nie połączyła. Ta kopia powstała w wadliwej "
                             "wersji portalu; potrzebna jest kopia z klucza.")
        tls_files = {f: read(f"tls/{f}") for f in _TLS_FILES}
        store_files = {os.path.basename(n): tar.extractfile(m).read()
                       for n, m in members.items() if n.startswith("store/")}

    from cryptography.fernet import Fernet
    from app.routerwg.importer import derive_public
    try:
        new_fernet = Fernet(secrets_files["fernet.key"].decode().strip().encode())
    except Exception as e:
        raise ValueError(f"Klucz szyfrujący w kopii jest uszkodzony ({e}).")
    hub_priv = wg_priv.decode().strip()
    hub_pub = derive_public(hub_priv)
    if not hub_pub:
        raise ValueError("Klucz prywatny huba w kopii jest uszkodzony.")

    prepared = []  # (nazwa, model, [wiersze])
    for name, model, _group in _ORDER:
        rows = db.get(name, [])
        if model is Setting:  # znacznik z kopii zrobionej w trakcie innego odtwarzania
            rows = [r for r in rows if r.get("key") != _PENDING_SETTING]
        try:
            prepared.append((name, model, [model(**_coerce_row(model, r)) for r in rows]))
        except Exception as e:
            raise ValueError(f"Uszkodzone dane tabeli {name} w kopii ({type(e).__name__}: {e}).")

    bad = _undecryptable(new_fernet, prepared, store_files)
    if bad:
        raise ValueError(f"Klucz szyfrujący w kopii nie pasuje do jej danych (tabela {bad}) — to klucz "
                         "z innej instalacji albo pliki kopii zostały pomieszane. Nic nie zostało zmienione.")
    runs_closed = _close_running_history(prepared)

    async with _restore_lock:
        # Pozostalosc po wczesniejszej probie, ktorej baza nie zatwierdzila (inaczej nie
        # bylibysmy w kreatorze — po commicie istnieja uzytkownicy).
        old = pending_restore()
        if old:
            # Na slepo wolno skasowac tylko dziennik, ktorego baza na pewno NIE zatwierdzila —
            # po niejednoznacznym commicie poprzedniej proby to wlasnie trzeba rozstrzygnac.
            committed = await _marker_committed(old.get("id"))
            if committed is not False:
                raise RestoreUncertain(
                    "Poprzednia próba odtwarzania mogła zostać zapisana w bazie (albo baza jest "
                    "niedostępna). Portal rozstrzygnie to sam w ciągu minuty — odśwież stronę.")
            _discard(old.get("staged", []))

        staged: list[list[str]] = []
        try:
            # ---- 2. wszystko, czego potrzebuje dokonczenie, na dysk ----
            _write_staged(SECRETS_DIR, {k: v for k, v in secrets_files.items() if v}, lambda f: 0o600, staged)
            _write_staged(TLS_DIR, {k: v for k, v in tls_files.items() if v},
                          lambda f: 0o644 if f.endswith(".pem") else 0o600, staged)
            _write_staged(STORE_DIR, store_files, lambda f: 0o600, staged)
            _write_file(_hub_key_path(), hub_priv.encode(), 0o600)
            journal = {"id": uuid.uuid4().hex, "staged": staged, "hub_public_key": hub_pub,
                       "counts": manifest.get("counts", {}), "runs_closed": runs_closed,
                       "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       "attempts": 0, "last_errors": []}
            _write_file(_journal_path(), json.dumps(journal).encode(), 0o600)

            # ---- 3. baza: jedna transakcja ze znacznikiem ----
            commit_error = None
            s = async_session()
            try:
                try:
                    for _name, model, _group in reversed(_ORDER):
                        await s.execute(delete(model))
                    for _name, model, rows in prepared:
                        s.add_all(rows)
                        await s.flush()
                    s.add(Setting(key=_PENDING_SETTING, value=journal["id"]))
                    for table in _IDENTITY_TABLES:
                        await s.execute(text(
                            f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                            f"COALESCE((SELECT MAX(id) FROM {table}), 0) + 1, false)"))
                except Exception:
                    await s.rollback()  # COMMIT nie poszedl — wynik jednoznaczny
                    raise
                try:
                    await s.commit()
                except Exception as e:
                    commit_error = e
            finally:
                try:
                    await s.close()
                except Exception:
                    pass

            if commit_error is not None:
                # Blad PRZY commicie jest niejednoznaczny: baza mogla zatwierdzic, a polaczenie
                # zerwac sie przed potwierdzeniem (wytkniete w trzeciej recenzji — sprzatanie
                # usuwalo wtedy dziennik i klucz huba, a zatwierdzony znacznik zostawal bez
                # niczego do wznowienia). Rozstrzyga znacznik odczytany NOWYM polaczeniem.
                committed = await _marker_committed(journal["id"])
                if committed is None:
                    raise RestoreUncertain(
                        "Nie wiadomo, czy baza zapisała odtworzone dane — połączenie zerwało się przy "
                        f"zatwierdzaniu ({type(commit_error).__name__}). Pliki odtwarzania zostały zachowane: "
                        "portal sprawdzi to sam przy starcie i co minutę — jeśli zapis doszedł, dokończy "
                        "odtwarzanie, jeśli nie, posprząta i będzie można spróbować ponownie.")
                if not committed:
                    raise commit_error
                logger.warning("Commit odtwarzania zgłosił %s, ale znacznik jest w bazie — kontynuuję",
                               type(commit_error).__name__)
        except RestoreUncertain:
            raise  # bez sprzatania — moze byc co dokonczyc
        except Exception:
            _discard(staged)
            raise

        # Od tej chwili baza jest zaszyfrowana kluczem z kopii — proces musi go uzywac od razu,
        # niezaleznie od tego, jak pojdzie reszta.
        security._fernet = new_fernet

        # ---- 4. dokonczenie ----
        return await _finish(journal)


async def _durable_on_hub(get_peers) -> set[str]:
    """Klucze peerow, ktore na hubie dzialaja I sa zapisane w konfiguracji agenta (przetrwaja
    restart kontenera). Agent bez pola `persisted` (starszy obraz) nie potwierdza niczego —
    wtedy odtwarzanie dokladamy od nowa i nie oglaszamy sukcesu na slowo."""
    on_hub, _err = await get_peers()
    return {p["public_key"] for p in on_hub or [] if p.get("persisted") is True}


async def _finish(journal: dict) -> dict:
    """Druga czesc odtwarzania — idempotentna, wolana az do skutku. Nie rzuca: bledy
    laduja w wyniku i w dzienniku, a odtwarzanie zostaje oznaczone jako niedokonczone."""
    from cryptography.fernet import Fernet
    from app.wg_agent_client import add_peer, get_peers, hub_peers_lock

    errors: list[str] = []
    pubkey = None
    injected = 0
    try:
        # Podmiana plikow. Pliku tymczasowego, ktorego juz nie ma, podmieniono
        # w poprzedniej probie.
        for tmp, final in journal["staged"]:
            if os.path.exists(tmp):
                os.replace(tmp, final)
        with open(os.path.join(SECRETS_DIR, "fernet.key"), "rb") as f:
            security._fernet = Fernet(f.read().strip())

        # Świadomie przez ensure_wg_up(), NIE przez samo setup_interface(): oprócz
        # postawienia interfejsu po stronie agenta dodaje ono TRASĘ do podsieci WG
        # w netns backendu. Bez tego handshake działa, ale backend nie ma jak dojść do
        # routerów — REST na całej flocie leży.
        with open(_hub_key_path()) as f:
            hub_priv = f.read().strip()
        await load_wg_config()
        # Hub juz stojacy z kluczem z kopii (poprzednia proba) NIE jest przebudowywany, a brak
        # odpowiedzi agenta konczy sie stanem „niedokonczone", nie przebudowa — oba warunki
        # pilnuje ensure_wg_up() na JEDNYM odczycie statusu (trzecia i czwarta recenzja:
        # podwojny odczyt pozwalal, by timeout drugiego zerwal tunel calej floty).
        pubkey = await ensure_wg_up(hub_priv)
        if pubkey != journal["hub_public_key"]:
            errors.append("tunel huba: agent WireGuard nie postawił interfejsu z kluczem z kopii "
                          "(niedostępny albo błąd) — flota nie może się jeszcze połączyć")
        else:
            def _psk(obj):
                return security.decrypt(obj.wg_preshared_key_encrypted) if obj.wg_preshared_key_encrypted else None

            # Odczyt bazy i dokladanie pod wspolna blokada z usuwaniem peerow — inaczej peer
            # usuniety w trakcie (odebrany dostep) wracalby na hub z naszej nieaktualnej listy.
            async with hub_peers_lock:
                async with async_session() as s:
                    peers = list((await s.execute(select(Device))).scalars().all())
                    peers += list((await s.execute(select(AdminPeer))).scalars().all())
                # Pomijamy tylko peery, ktore dzialaja I sa zapisane w konfiguracji agenta.
                # Sam „dziala" nie wystarcza: peer bez zapisu znika przy restarcie kontenera,
                # a dawniej ponowienie widzialo go na hubie i oglaszalo sukces (czwarta recenzja).
                already = await _durable_on_hub(get_peers)
                for obj in peers:
                    if obj.wg_public_key not in already:
                        await add_peer(obj.wg_public_key, str(obj.wg_ip), _psk(obj))
                # Sukces dopiero po potwierdzeniu z huba, nie po kodach odpowiedzi add_peer.
                durable = await _durable_on_hub(get_peers)
                injected = sum(1 for obj in peers if obj.wg_public_key in durable)
            if injected < len(peers):
                errors.append(f"peery: {len(peers) - injected} z {len(peers)} nie jest na hubie "
                              "albo nie jest zapisanych w jego konfiguracji (zniknęłyby po restarcie)")
    except Exception as e:
        errors.append(f"{type(e).__name__}: {e}")

    complete = not errors
    if complete:
        # Finalizacja tez moze zawiesc (baza) — wtedy to stan „niedokonczone" z bledem
        # w dzienniku, nie wyjatek: formularz pokazalby porazke odtworzonego portalu, a przy
        # starcie backendu wyjatek przerwalby uruchomienie (trzecia recenzja). Gdy usuniecie
        # znacznika doszlo mimo bledu, nastepne wznowienie zobaczy dziennik bez znacznika
        # i tylko posprzata — wszystko inne jest juz na miejscu.
        try:
            async with async_session() as s:
                await s.execute(delete(Setting).where(Setting.key == _PENDING_SETTING))
                await s.commit()
            _discard([])  # klucz huba i dziennik — tunel juz go ma
        except Exception as e:
            complete = False
            errors.append(f"finalizacja: {type(e).__name__}: {e}")
    if not complete:
        journal["attempts"] = journal.get("attempts", 0) + 1
        journal["last_errors"] = errors
        journal["last_attempt_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            _write_file(_journal_path(), json.dumps(journal).encode(), 0o600)
        except OSError:
            pass

    return {
        "complete": complete,
        "errors": errors,
        "public_key": pubkey,
        "peers_injected": injected,
        "store_files": sum(1 for _tmp, final in journal["staged"] if final.startswith(STORE_DIR)),
        "runs_closed": journal.get("runs_closed", 0),
        "counts": journal.get("counts", {}),
    }


async def resume_pending_restore() -> dict | None:
    """Dokonczenie przerwanego odtwarzania: przy starcie backendu, z harmonogramu i na
    zadanie. None = nie bylo czego dokanczac."""
    if not os.path.exists(_journal_path()):
        return None
    async with _restore_lock:
        journal = pending_restore()
        if journal is None:
            if os.path.exists(_journal_path()):
                logger.error("Uszkodzony dziennik odtwarzania %s — zostawiam do ręcznej analizy", _journal_path())
            return None
        committed = await _marker_committed(journal.get("id"))
        if committed is None:
            # Baza nieosiagalna — nic nie przesadzamy. Wolane przy starcie backendu, wiec bez
            # wyjatku (nastepna proba z harmonogramu za minute).
            err = "baza niedostępna — nie można sprawdzić znacznika odtwarzania"
            logger.warning("Odtwarzanie portalu: %s", err)
            return {"complete": False, "errors": [err]}
        if not committed:
            # Znacznika nie ma: albo baza nie zatwierdzila odtwarzania (awaria przed commitem —
            # pliki tymczasowe to smieci), albo finalizacja usunela go mimo zgloszonego bledu
            # (wszystko podmienione, zostal dziennik). W obu przypadkach tylko sprzatamy.
            logger.warning("Dziennik odtwarzania %s bez znacznika w bazie — sprzątam", journal.get("id"))
            _discard(journal.get("staged", []))
            return None
        result = await _finish(journal)
        if result["complete"]:
            logger.info("Odtwarzanie portalu dokończone (próba %d)", journal.get("attempts", 0) + 1)
        else:
            logger.warning("Odtwarzanie portalu nadal niedokończone: %s", "; ".join(result["errors"]))
        return result
