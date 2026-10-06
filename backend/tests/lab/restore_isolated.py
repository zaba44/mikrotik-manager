"""Odtwarzanie kopii portalu w ODIZOLOWANYM srodowisku (osobna baza, osobny kontener) —
NIGDY na zywym portalu: odtwarzanie kasuje baze. Jak uruchomic: tests/lab/README.md.

Prawdziwa baza PostgreSQL, prawdziwe pliki; agent WireGuard i peery podmienione (nic nie
dociera do huba ani routerow). Kazdy scenariusz konczy sie asercja — skrypt wychodzi
z kodem bledu przy pierwszej niezgodnosci, zamiast drukowac wyniki do recznego czytania."""
import asyncio
import io
import json
import os
import tarfile
import uuid

from sqlalchemy import func, select

from app import portal_backup as pb
from app.database import async_session
from app.models import Notification, Setting, UpdateRun, User
from app.routerwg.importer import derive_public

WORK = "/tmp/rt-data"
for d in ("secrets", "tls", "store"):
    os.makedirs(f"{WORK}/{d}", exist_ok=True)
pb.SECRETS_DIR, pb.TLS_DIR, pb.STORE_DIR = f"{WORK}/secrets", f"{WORK}/tls", f"{WORK}/store"

AGENT = {"up": True}


async def fake_wg_up(priv=None):
    """Agent „dziala" = stawia interfejs z podanym kluczem i oddaje jego klucz publiczny."""
    return derive_public(priv) if AGENT["up"] and priv else None


HUB_PEERS: set = set()  # atrapa huba: peery dodane = dzialaja i sa zapisane w pliku


async def fake_add_peer(public_key, *a, **kw):
    HUB_PEERS.add(public_key)
    return True, None


async def fake_get_peers():
    return [{"public_key": k, "persisted": True} for k in HUB_PEERS], None


async def noop():
    pass

pb.ensure_wg_up = fake_wg_up
pb.load_wg_config = noop
import app.wg_agent_client as agent  # noqa: E402
agent.add_peer = fake_add_peer
agent.get_peers = fake_get_peers

ARCHIVE = open("/work/archive.tgz", "rb").read()
MANIFEST = json.loads(tarfile.open(fileobj=io.BytesIO(ARCHIVE), mode="r:gz").extractfile("manifest.json").read())


def rebuild(archive: bytes, mutate):
    """Kopia archiwum z modyfikacja (do testow awarii). mutate(nazwa, dane) -> dane albo None (usun)."""
    src = tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as dst:
        for m in src.getmembers():
            data = mutate(m.name, src.extractfile(m).read() if m.isfile() else None)
            if data is None:
                continue
            info = tarfile.TarInfo(m.name)
            info.size = len(data)
            dst.addfile(info, io.BytesIO(data))
    return out.getvalue()


def edit_db(fn):
    def mutate(name, data):
        if name == "db.json":
            db = json.loads(data)
            fn(db)
            return json.dumps(db).encode()
        return data
    return mutate


async def counts():
    async with async_session() as s:
        return {name: (await s.execute(select(func.count()).select_from(model))).scalar()
                for name, model, _ in pb._ORDER}


async def marker():
    async with async_session() as s:
        return (await s.execute(select(Setting.value).where(Setting.key == pb._PENDING_SETTING))).scalar()


def leftovers():
    return sorted(f for d in (pb.SECRETS_DIR, pb.TLS_DIR, pb.STORE_DIR) for f in os.listdir(d)
                  if f.endswith((".restore-tmp", ".part")) or "restore-pending" in f)


def check(cond, msg):
    if not cond:
        raise SystemExit(f"  NIEZGODNOSC: {msg}")
    print(f"  ok: {msg}")


async def expect_rejected(archive, exc, why):
    before, mtime = await counts(), os.path.getmtime(f"{pb.SECRETS_DIR}/fernet.key")
    try:
        await pb.restore_portal(archive)
    except exc as e:
        print(f"  odrzucone ({type(e).__name__}): {str(e)[:80]}")
    else:
        raise SystemExit(f"  NIEZGODNOSC: przyjeto kopie, ktora powinna byc odrzucona ({why})")
    check(await counts() == before, "baza bez zmian")
    check(os.path.getmtime(f"{pb.SECRETS_DIR}/fernet.key") == mtime, "sekrety nietkniete")
    check(leftovers() == [], "zadnych plikow tymczasowych ani dziennika")


async def main():
    print("== 1. odtworzenie na czystej bazie ==")
    res = await pb.restore_portal(ARCHIVE)
    check(res["complete"], "odtwarzanie dokonczone")
    after = await counts()
    check(all(after.get(k) == v for k, v in MANIFEST["counts"].items()), "liczba wierszy zgodna z manifestem")
    check(leftovers() == [] and await marker() is None, "bez plikow tymczasowych, dziennika i znacznika")
    check("fernet.key" in os.listdir(pb.SECRETS_DIR), "klucz szyfrujacy na miejscu")

    print("\n== 2. sekwencje IDENTITY po odtworzeniu ==")
    async with async_session() as s:
        mx = (await s.execute(select(func.max(Notification.id)))).scalar() or 0
        s.add(Notification(event_key="test", dedup_key="test", subject="test", status="sent"))
        await s.commit()
        new_id = (await s.execute(select(func.max(Notification.id)))).scalar()
    check(new_id > mx, f"nowy wiersz dostal id {new_id} > {mx} (bez kolizji)")

    print("\n== 3. blad W POLOWIE zapisu do bazy ==")
    await expect_rejected(rebuild(ARCHIVE, edit_db(lambda db: db["devices"].append(db["devices"][0]))),
                          Exception, "zdublowany klucz glowny")

    print("\n== 4. kopia bez klucza huba ==")
    await expect_rejected(rebuild(ARCHIVE, lambda n, d: None if n == "wg-mt.key" else d), ValueError, "brak wg-mt.key")

    print("\n== 5. klucz Fernet z innej instalacji (poprawny skladniowo) ==")
    from cryptography.fernet import Fernet
    foreign = Fernet.generate_key()
    await expect_rejected(rebuild(ARCHIVE, lambda n, d: foreign if n == "secrets/fernet.key" else d),
                          ValueError, "klucz nie pasuje do danych")

    print("\n== 6. agent WireGuard niedostepny -> odtwarzanie wznawialne ==")
    AGENT["up"] = False
    res = await pb.restore_portal(ARCHIVE)
    journal = pb.pending_restore()
    check(not res["complete"], f"zgloszone jako niedokonczone: {res['errors']}")
    check(journal is not None and await marker() == journal["id"], "dziennik na dysku = znacznik w bazie")
    check(os.path.exists(pb._hub_key_path()), "klucz huba z kopii czeka na dysku")
    async with async_session() as s:
        check((await s.execute(select(func.count()).select_from(User))).scalar() > 0, "baza odtworzona (sa uzytkownicy)")
    res = await pb.resume_pending_restore()
    check(res is not None and not res["complete"], "ponowienie przy dalej lezacym agencie: nadal niedokonczone")
    check(pb.pending_restore()["attempts"] == 2, "licznik prob rosnie")
    AGENT["up"] = True
    res = await pb.resume_pending_restore()
    check(res["complete"], "po powrocie agenta ponowienie konczy odtwarzanie")
    check(leftovers() == [] and await marker() is None, "dziennik, klucz huba i znacznik sprzatniete")

    print("\n== 7. blad podmiany plikow PO commicie bazy ==")
    real_replace, failed = os.replace, []

    def flaky(src, dst):
        if str(src).endswith(pb._TMP_SUFFIX) and not failed:
            failed.append(src)
            raise OSError("symulowany blad dysku")
        return real_replace(src, dst)
    pb.os.replace = flaky
    try:
        res = await pb.restore_portal(ARCHIVE)
    finally:
        pb.os.replace = real_replace
    check(not res["complete"] and "symulowany" in res["errors"][0], "blad zgloszony, bez wyjatku po commicie")
    check(await marker() is not None, "znacznik w bazie — wiadomo, ze jest co dokonczyc")
    res = await pb.resume_pending_restore()
    check(res["complete"] and leftovers() == [], "ponowienie podmienia pliki i konczy")

    print("\n== 8. kopia zrobiona w trakcie aktualizacji ==")
    run_id = str(uuid.uuid4())

    def add_running(db):
        db.setdefault("update_runs", []).append({"id": run_id, "scope": "device", "device_id": db["devices"][0]["id"],
                                                 "status": "running", "started_at": "2026-10-01T12:00:00"})
    res = await pb.restore_portal(rebuild(ARCHIVE, edit_db(add_running)))
    async with async_session() as s:
        run = await s.get(UpdateRun, uuid.UUID(run_id))
        running = (await s.execute(select(func.count()).where(UpdateRun.status == "running"))).scalar()
    check(res["complete"] and res["runs_closed"] >= 1, f"przebiegow zamknietych: {res['runs_closed']}")
    check(run.status == "failed" and running == 0, "zaden przebieg nie wraca jako „running”")

    print("\n== 9. dziennik bez zatwierdzonego znacznika (awaria przed commitem) ==")
    tmp = f"{pb.SECRETS_DIR}/fernet.key{pb._TMP_SUFFIX}"
    open(tmp, "wb").write(foreign)
    pb._write_file(pb._journal_path(), json.dumps({"id": "nie-zatwierdzony",
                                                    "staged": [[tmp, f"{pb.SECRETS_DIR}/fernet.key"]]}).encode(), 0o600)
    key_before = open(f"{pb.SECRETS_DIR}/fernet.key", "rb").read()
    check(await pb.resume_pending_restore() is None, "ponowienie niczego nie dokancza")
    check(leftovers() == [] and open(f"{pb.SECRETS_DIR}/fernet.key", "rb").read() == key_before,
          "smieci sprzatniete, klucz nie podmieniony")

    print("\n== 10. COMMIT zapisany, potwierdzenie zgubione (zerwane polaczenie) ==")
    from sqlalchemy.ext.asyncio import AsyncSession
    real_commit, lost = AsyncSession.commit, []

    async def commit_then_lose(self):
        await real_commit(self)
        if not lost:  # pierwszy commit to transakcja odtwarzania
            lost.append(1)
            raise ConnectionResetError("symulowana utrata potwierdzenia")
    AsyncSession.commit = commit_then_lose
    try:
        res = await pb.restore_portal(ARCHIVE)
    finally:
        AsyncSession.commit = real_commit
    check(lost == [1], "commit zgloszony jako nieudany")
    check(res["complete"] and leftovers() == [] and await marker() is None,
          "znacznik odczytany nowym polaczeniem — odtwarzanie dokonczone zamiast porzucone")

    print("\nWSZYSTKIE SCENARIUSZE ZGODNE")


asyncio.run(main())
