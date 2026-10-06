"""Poprawki po pierwszej recenzji — scenariusze wymagajace bazy, na TYMCZASOWYCH obiektach.
Wszystko, co powstanie (operator, urzadzenie, lokalizacja, peer admina), sprzatamy w finally.
Kazdy scenariusz konczy sie asercja (wyjscie z kodem bledu przy pierwszej niezgodnosci).

    docker exec -i -w /app -e MTM_LAB_USER=... -e MTM_LAB_PASSWORD=... mtm-backend python - < tests/lab/fixes_review.py
"""
import asyncio, datetime, io, json, os, re, tarfile, uuid
import httpx
from sqlalchemy import delete, func, select
from app.backup_service import enforce_retention
from app.database import async_session
from app.models import (AdminPeer, Backup, Device, Location, NotificationOverride, PingTarget, UpdateRun,
                        UpdateRunStep, User)
from app.wg_agent_client import get_peers

BASE = "https://caddy:8443"
TAG = "zz-test-" + uuid.uuid4().hex[:6]


def check(cond, msg):
    if not cond:
        raise SystemExit(f"  NIEZGODNOSC: {msg}")
    print(f"  ok: {msg}")


def err(html):
    m = re.search(r'<p class="error">(.*?)</p>', html, re.S)
    return " ".join(re.sub(r"<[^>]+>", " ", m.group(1)).split()) if m else None


async def client(user, pw):
    c = httpx.AsyncClient(base_url=BASE, verify=False, timeout=120.0, follow_redirects=True)
    await c.post("/login", data={"username": user, "password": pw})
    return c


async def hub_has(pubkey):
    peers, _ = await get_peers()
    return any(p["public_key"] == pubkey for p in peers or [])


async def main():
    admin = await client(os.environ["MTM_LAB_USER"], os.environ["MTM_LAB_PASSWORD"])
    made = {"users": [], "devices": [], "locations": [], "admin_peers": []}
    try:
        print("== lokalizacja i operator ==")
        r = await admin.post("/locations", data={"name": TAG + "-lok"})
        async with async_session() as s:
            loc = (await s.execute(select(Location).where(Location.name == TAG + "-lok"))).scalars().one()
        made["locations"].append(loc.id)
        await admin.post("/settings/users", data={"username": TAG + "-op", "password": "Test-haslo-1",
                                                   "role": "operator", "location_id": str(loc.id)})
        async with async_session() as s:
            op = (await s.execute(select(User).where(User.username == TAG + "-op"))).scalars().one()
        made["users"].append(op.id)

        print("\n== 12. sesja wygasa po resecie hasla przez admina ==")
        opc = await client(TAG + "-op", "Test-haslo-1")
        check("/login" not in str((await opc.get("/")).url), "operator zalogowany")
        await admin.post(f"/settings/users/{op.id}/password", data={"new_password": "Test-haslo-2"})
        check("/login" in str((await opc.get("/")).url), "po resecie hasla stara sesja wyrzucona na logowanie")
        await opc.aclose()
        opc = await client(TAG + "-op", "Test-haslo-2")

        print("\n== urzadzenie testowe (rejestracja przez portal) ==")
        r = await admin.post("/devices", data={"name": TAG + "-dev", "location_id": str(loc.id)})
        async with async_session() as s:
            dev = (await s.execute(select(Device).where(Device.name == TAG + "-dev"))).scalars().one()
        made["devices"].append(dev.id)
        check(await hub_has(dev.wg_public_key), "peer na hubie po rejestracji")

        print("\n== drobne: uprawnienia operatora ==")
        r = await opc.post(f"/devices/{dev.id}/addresses/unpin")
        check(r.status_code == 200, f"operator: odpiecie adresu -> {r.status_code} (wczesniej 403 z middleware)")
        r = await opc.get("/devices/new", follow_redirects=False)
        check(r.status_code == 403, f"operator: /devices/new -> {r.status_code} (wczesniej 200 z lista lokalizacji)")

        print("\n== 1. retencja: 3 udane + 5 nieudanych, limit 3 ==")
        async with async_session() as s:
            now = datetime.datetime.utcnow()
            for i in range(3):
                s.add(Backup(device_id=dev.id, backup_type="export", status="success", content_text_encrypted="x",
                             created_at=now - datetime.timedelta(days=10 + i)))
            for i in range(5):
                s.add(Backup(device_id=dev.id, backup_type="export", status="failed", error_message="offline",
                             created_at=now - datetime.timedelta(days=i)))
            await s.commit()
            from app.settings_store import get_int_setting, set_setting
            old_ret = await get_int_setting(s, "backup_retention_count")
            await set_setting(s, "backup_retention_count", "3")
            await s.commit()
        await enforce_retention(dev.id)
        async with async_session() as s:
            ok_n = (await s.execute(select(func.count()).where(Backup.device_id == dev.id, Backup.status == "success"))).scalar()
            bad_n = (await s.execute(select(func.count()).where(Backup.device_id == dev.id, Backup.status == "failed"))).scalar()
            from app.settings_store import set_setting
            await set_setting(s, "backup_retention_count", str(old_ret))
            await s.commit()
        check(ok_n == 3 and bad_n <= 3, f"po retencji: udanych {ok_n} (wczesniej zostalyby 0), nieudanych {bad_n}")

        print("\n== 2. usuniecie urzadzenia z kopiami, celem pingu, krokiem aktualizacji i wyciszeniem ==")
        async with async_session() as s:
            s.add(PingTarget(device_id=dev.id, ip="192.0.2.1", label="test"))
            run = UpdateRun(scope="location", location_id=loc.id, status="succeeded")
            s.add(run)
            await s.flush()
            s.add(UpdateRunStep(run_id=run.id, device_id=dev.id, step_type="software", status="succeeded"))
            s.add(NotificationOverride(scope_type="device", scope_id=dev.id, mode="muted"))
            s.add(NotificationOverride(scope_type="location", scope_id=loc.id, mode="muted"))
            await s.commit()
            run_id = run.id
        r = await admin.post(f"/devices/{dev.id}/delete")
        async with async_session() as s:
            gone = await s.get(Device, dev.id) is None
            left = {
                "kopie": (await s.execute(select(func.count()).where(Backup.device_id == dev.id))).scalar(),
                "pingi": (await s.execute(select(func.count()).where(PingTarget.device_id == dev.id))).scalar(),
                "kroki": (await s.execute(select(func.count()).where(UpdateRunStep.device_id == dev.id))).scalar(),
                "wyciszenia": (await s.execute(select(func.count()).where(NotificationOverride.scope_id == dev.id))).scalar(),
            }
        check(gone and not any(left.values()), f"urzadzenie usuniete razem z zaleznosciami {left}")
        check(not await hub_has(dev.wg_public_key), "peer zniknal z huba")
        if gone:
            made["devices"].remove(dev.id)

        print("\n== lokalizacja: odmowa przy przypisanym operatorze, potem usuniecie ==")
        r = await admin.post(f"/locations/{loc.id}/delete")
        check("operatorzy" in (err(r.text) or ""), f"lokalizacja z operatorem: odmowa — {err(r.text)}")
        async with async_session() as s:
            u = await s.get(User, op.id); await s.delete(u); await s.commit()
        made["users"].remove(op.id)
        r = await admin.post(f"/locations/{loc.id}/delete")
        async with async_session() as s:
            loc_gone = await s.get(Location, loc.id) is None
            run_after = await s.get(UpdateRun, run_id)
            ov = (await s.execute(select(func.count()).where(NotificationOverride.scope_id == loc.id))).scalar()
        check(loc_gone, "lokalizacja bez operatora usunieta")
        check(run_after is not None and run_after.location_id is None, "historia aktualizacji zostala, lokalizacja odpieta")
        check(ov == 0, "wyciszenia lokalizacji sprzatniete")
        if loc_gone:
            made["locations"].remove(loc.id)
        async with async_session() as s:
            await s.execute(delete(UpdateRun).where(UpdateRun.id == run_id)); await s.commit()

        print("\n== 11. peer administracyjny: usuwany tylko po potwierdzeniu z huba ==")
        await admin.post("/settings/admin-peers", data={"name": TAG + "-peer"})
        async with async_session() as s:
            ap = (await s.execute(select(AdminPeer).where(AdminPeer.name == TAG + "-peer"))).scalars().one()
        made["admin_peers"].append(ap.id)
        check(await hub_has(ap.wg_public_key), "peer admina na hubie po dodaniu")
        await admin.post(f"/settings/admin-peers/{ap.id}/delete")
        async with async_session() as s:
            ap_gone = await s.get(AdminPeer, ap.id) is None
        check(ap_gone and not await hub_has(ap.wg_public_key), "peer admina usuniety z bazy i z huba")
        if ap_gone:
            made["admin_peers"].remove(ap.id)

        print("\n== 3/4. eksport kopii portalu ==")
        r = await admin.post("/settings/portal-backup", data={"include_history": "1"})
        tar = tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz")
        names = tar.getnames()
        man = json.loads(tar.extractfile("manifest.json").read())
        check(r.status_code == 200 and "wg-mt.key" in names and "secrets/fernet.key" in names,
              "eksport z kluczem huba i kluczem szyfrujacym")
        check({"device_ping_targets", "notification_overrides", "update_runs"} <= set(man["counts"]),
              f"tabele konfiguracji i historii w kopii: {sorted(man['counts'])}")
        # Archiwum zawiera klucze calej instalacji — nigdzie go nie zapisujemy.
    finally:
        print("\n== SPRZATANIE ==")
        async with async_session() as s:
            for did in made["devices"]:
                d = await s.get(Device, did)
                if d:
                    from app.wg_agent_client import remove_peer
                    await remove_peer(d.wg_public_key)
                    for m in (Backup, PingTarget, UpdateRunStep):
                        await s.execute(delete(m).where(m.device_id == did))
                    await s.delete(d)
            for uid in made["users"]:
                u = await s.get(User, uid)
                if u: await s.delete(u)
            for lid in made["locations"]:
                l = await s.get(Location, lid)
                if l: await s.delete(l)
            for pid in made["admin_peers"]:
                p = await s.get(AdminPeer, pid)
                if p:
                    from app.wg_agent_client import remove_peer
                    await remove_peer(p.wg_public_key)
                    await s.delete(p)
            await s.commit()
        print("  pozostalo do sprzatniecia:", {k: len(v) for k, v in made.items()})
        if any(made.values()):
            raise SystemExit("  NIEZGODNOSC: zostaly obiekty testowe")
        await admin.aclose()


asyncio.run(main())
