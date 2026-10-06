"""Poprawki po DRUGIEJ recenzji — scenariusze na zywym portalu, na TYMCZASOWYCH obiektach
(sprzatane w finally). Zadnego zapisu na routerach: ping idzie na adres dokumentacyjny
192.0.2.1, restart — na adres w tunelu, pod ktorym nie ma zadnego urzadzenia.

    docker exec -i -w /app -e MTM_LAB_USER=... -e MTM_LAB_PASSWORD=... mtm-backend python - < tests/lab/fixes_review2.py
"""
import asyncio
import ipaddress
import os
import re
import uuid

import httpx
from sqlalchemy import delete, select

from app.database import async_session
from app.models import AdminPeer, Device, PingTarget
from app.routeros_client import reboot
from app.security import allocate_ip, encrypt, generate_wg_keypair
from app.wg_config import load_wg_config, wg

BASE = "https://caddy:8443"


def check(cond, msg):
    if not cond:
        raise SystemExit(f"  NIEZGODNOSC: {msg}")
    print(f"  ok: {msg}")


async def main():
    await load_wg_config()
    made_devices, made_targets, made_admin = [], [], []
    c = httpx.AsyncClient(base_url=BASE, verify=False, timeout=60.0, follow_redirects=True)
    await c.post("/login", data={"username": os.environ["MTM_LAB_USER"], "password": os.environ["MTM_LAB_PASSWORD"]})
    try:
        print("== 5. przydzial IP: druga rejestracja czeka na zapis pierwszej ==")
        holding, release = asyncio.Event(), asyncio.Event()
        got = {}

        async def first():
            async with async_session() as s:
                ip = await allocate_ip(s)
                priv, pub = generate_wg_keypair()
                dev = Device(name="zz-test-ip-" + uuid.uuid4().hex[:6], wg_public_key=pub,
                             wg_private_key_encrypted=encrypt(priv), wg_ip=ip, api_username="mtm-api")
                s.add(dev)
                await s.flush()
                made_devices.append(dev.id)
                got["first"] = ip
                holding.set()
                await release.wait()
                await s.commit()

        async def second():
            await holding.wait()
            async with async_session() as s:
                got["second"] = await allocate_ip(s)
                await s.rollback()

        t1, t2 = asyncio.create_task(first()), asyncio.create_task(second())
        await holding.wait()
        await asyncio.sleep(1.5)
        check(not t2.done(), "druga rejestracja czeka, dopoki pierwsza trzyma pule (bez blokady wzielaby ten sam adres)")
        release.set()
        await asyncio.gather(t1, t2)
        check(got["first"] != got["second"], f"rozne adresy: {got['first']} i {got['second']}")

        print("\n== 7. cel pingu innego urzadzenia ==")
        async with async_session() as s:
            devs = (await s.execute(select(Device).where(Device.id.notin_(made_devices)).limit(2))).scalars().all()
            target = PingTarget(device_id=devs[0].id, ip="192.0.2.1", label="zz-test")
            s.add(target)
            await s.commit()
            made_targets.append(target.id)
        r = await c.post(f"/devices/{devs[1].id}/ping-targets/{target.id}/test")
        check(r.status_code == 404 and "192.0.2.1" not in r.text, f"przez cudze urzadzenie: HTTP {r.status_code}, bez adresu celu")
        r = await c.post(f"/devices/{devs[0].id}/ping-targets/{target.id}/test")
        check(r.status_code == 200 and "192.0.2.1" in r.text, f"przez wlasciciela: HTTP {r.status_code}")

        print("\n== 8. restart urzadzenia, z ktorym nie ma polaczenia ==")
        async with async_session() as s:
            used = {ipaddress.ip_address(str(x)) for x in (await s.execute(select(Device.wg_ip))).scalars()}
            used |= {ipaddress.ip_address(str(x)) for x in (await s.execute(select(AdminPeer.wg_ip))).scalars()}
        free = next(h for h in reversed(list(ipaddress.ip_network(wg.subnet).hosts()))
                    if h not in used and str(h) != wg.server_ip)
        ghost = Device(name="duch", api_username="x", api_password_encrypted=encrypt("x"), wg_ip=str(free))
        result = await reboot(ghost)
        check(result["ok"] is False, f"{free} (nikogo tam nie ma): ok=False — {result.get('error', '')[:70]}")

        print("\n== R4. peer na hubie = peer zapisany w konfiguracji agenta ==")
        from app.wg_agent_client import get_peers
        await c.post("/settings/admin-peers", data={"name": "zz-test-trwalosc"})
        async with async_session() as s:
            ap = (await s.execute(select(AdminPeer).where(AdminPeer.name == "zz-test-trwalosc"))).scalars().one()
            made_admin.append(ap.id)
        on_hub = {p["public_key"]: p for p in (await get_peers())[0]}
        check(on_hub.get(ap.wg_public_key, {}).get("persisted") is True, "nowy peer dziala i jest zapisany w pliku")
        check(all(p.get("persisted") is True for p in on_hub.values()), f"wszystkie {len(on_hub)} peery huba zapisane")
        await c.post(f"/settings/admin-peers/{ap.id}/delete")
        check(ap.wg_public_key not in {p["public_key"] for p in (await get_peers())[0]}, "po usunieciu znika z huba")
        async with async_session() as s:
            if await s.get(AdminPeer, ap.id) is None:
                made_admin.remove(ap.id)

        print("\n== 3. potwierdzenia jako dane, nie kod ==")
        home = (await c.get("/")).text
        dev_id = re.search(r'href="/devices/([0-9a-f-]{36})"', home).group(1)
        pages = [f"/devices/{dev_id}", f"/devices/{dev_id}/fragment/updates", f"/devices/{dev_id}/bth",
                 "/settings/users", "/settings/admin-peers", "/settings/syslog"]
        bad = []
        for p in pages:
            html = (await c.get(p)).text
            bad += [p for m in re.finditer(r'\son[a-z]+="[^"]*confirm\(', html)]
        check(bad == [], "zadnego confirm() w handlerach inline")
        check("data-confirm=" in (await c.get(f"/devices/{dev_id}")).text, "strona urzadzenia uzywa data-confirm")
        check((await c.get("/static/confirm.js")).status_code == 200, "confirm.js serwowany")
    finally:
        async with async_session() as s:
            await s.execute(delete(PingTarget).where(PingTarget.id.in_(made_targets)))
            await s.execute(delete(Device).where(Device.id.in_(made_devices)))
            for pid in made_admin:  # nieudany test: peer moze byc na hubie
                p = await s.get(AdminPeer, pid)
                if p:
                    from app.wg_agent_client import remove_peer
                    await remove_peer(p.wg_public_key)
                    await s.delete(p)
            await s.commit()
            left = (await s.execute(select(Device).where(Device.name.like("zz-test-%")))).scalars().all()
        print(f"\n== SPRZATANIE: pozostalo obiektow testowych: {len(left)} ==")
        await c.aclose()
    print("\nWSZYSTKIE SCENARIUSZE ZGODNE")


asyncio.run(main())
