"""Sekwencje IDENTITY po odtworzeniu — na syntetycznych wpisach syslog o id 1..5.
Bez setval nowy wpis dostalby id 1 i zderzylby sie z odtworzonym. Tylko w odizolowanym
srodowisku (odtwarzanie kasuje baze) — tests/lab/README.md."""
import asyncio, io, json, os, tarfile

from sqlalchemy import func, select

from app import portal_backup as pb
from app.database import async_session
from app.models import DeviceLogEntry
from app.routerwg.importer import derive_public

WORK = "/tmp/rt-data"
for d in ("secrets", "tls", "store"):
    os.makedirs(f"{WORK}/{d}", exist_ok=True)
pb.SECRETS_DIR, pb.TLS_DIR, pb.STORE_DIR = f"{WORK}/secrets", f"{WORK}/tls", f"{WORK}/store"


async def fake_wg_up(priv=None):
    return derive_public(priv) if priv else None


async def noop():
    pass


HUB_PEERS: set = set()  # atrapa huba: peery dodane = dzialaja i sa zapisane w pliku


async def fake_add_peer(public_key, *a, **kw):
    HUB_PEERS.add(public_key)
    return True, None


async def fake_get_peers():
    return [{"public_key": k, "persisted": True} for k in HUB_PEERS], None

pb.ensure_wg_up = fake_wg_up
pb.load_wg_config = noop
import app.wg_agent_client as agent
agent.add_peer = fake_add_peer
agent.get_peers = fake_get_peers

src = tarfile.open(fileobj=io.BytesIO(open("/work/archive.tgz", "rb").read()), mode="r:gz")
out = io.BytesIO()
with tarfile.open(fileobj=out, mode="w:gz") as dst:
    for m in src.getmembers():
        data = src.extractfile(m).read()
        if m.name == "db.json":
            db = json.loads(data)
            dev = db["devices"][0]["id"]
            db["device_log_entries"] = [
                {"id": i, "device_id": dev, "received_at": "2026-10-01T12:00:00", "level": "warning",
                 "topics": "system,warning", "message": f"syntetyczny wpis {i}"} for i in range(1, 6)]
            data = json.dumps(db).encode()
        info = tarfile.TarInfo(m.name)
        info.size = len(data)
        dst.addfile(info, io.BytesIO(data))


async def main():
    res = await pb.restore_portal(out.getvalue())
    if not res["complete"]:
        raise SystemExit(f"  NIEZGODNOSC: odtwarzanie niedokonczone: {res['errors']}")
    async with async_session() as s:
        dev = (await s.execute(select(DeviceLogEntry.device_id).limit(1))).scalar()
        s.add(DeviceLogEntry(device_id=dev, level="error", topics="test,error", message="nowy po odtworzeniu"))
        await s.commit()
        ids = [r[0] for r in (await s.execute(select(DeviceLogEntry.id).order_by(DeviceLogEntry.id))).all()]
    print("  identyfikatory po odtworzeniu i nowym wpisie:", ids)
    if ids != [1, 2, 3, 4, 5, 6]:
        raise SystemExit("  NIEZGODNOSC: nowy wpis zderzyl sie z odtworzonymi identyfikatorami")
    print("  ok: nowy wpis bez kolizji")


asyncio.run(main())
