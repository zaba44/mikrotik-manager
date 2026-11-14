# Sonda zgodnosci — uruchamiana WEWNATRZ kontenera backendu (lab albo produkcja), TYLKO ODCZYT:
#   docker exec -i -w /app mtm-backend python - < tests/lab/compat_probe.py
"""Czy kazdy router floty ma menu i parametry, ktorych portal uzywa.

MikroTik zmienia nazwy miedzy wersjami (uzytkownicy Back To Home: `back-to-home-users` do 7.16,
`back-to-home-user` od 7.18; `/ip service`: `address` -> `available-from` w 7.24), a nieznana
nazwa w REST zwraca HTTP 500, nie 404 — takie roznice wychodzily dotad dopiero u klientow.
Sonda pyta `/console/inspect` o to, co portal zaklada, i wypisuje TYLKO odstepstwa, pogrupowane
po wersji RouterOS. Uruchom po dodaniu do floty nowej wersji RouterOS i przed wydaniem zmiany,
ktora dotyka nowego menu. Niczego nie zmienia i nie wypisuje danych z routerow."""
import asyncio
import collections

import httpx
from sqlalchemy import select

from app.database import async_session
from app.models import Device
from app.routeros_client import _auth, _base_url

# menu (sciezka inspect) -> parametry, ktore portal wysyla. Krotka = wystarczy jeden z wariantow.
EXPECT = {
    "ip,service,set": [("available-from", "address"), "certificate", "port"],
    "ip,firewall,filter,add": ["place-before", "src-address-list", "in-interface"],
    "interface,wireguard,peers,add": ["name", "preshared-key", "allowed-address"],
    "system,logging,add": ["topics", "action", "regex"],
    "certificate,add": ["common-name", "days-valid"],
    "system,package,update,check-for-updates": [],
    "interface,ethernet,monitor": ["numbers", "once"],
}
# Wystarczy jedno z tych menu (zalezne od wersji / sterownika).
ANY_OF = {
    "Back To Home — uzytkownicy": ["ip,cloud,back-to-home-user", "ip,cloud,back-to-home-users"],
}
BTH_ARCH = ("arm", "arm64", "tile")


async def children(client, base, path):
    r = await client.post(f"{base}/rest/console/inspect", json={"request": "child", "path": path})
    if r.status_code != 200:
        return None
    return {x.get("name") for x in r.json() if isinstance(x, dict) and x.get("type") == "child"}


async def probe(device):
    problems = []
    async with httpx.AsyncClient(verify=False, timeout=20, auth=_auth(device)) as c:
        base = _base_url(device)
        res = (await c.get(f"{base}/rest/system/resource")).json()
        version, arch = str(res.get("version", "?")).split(" ")[0], res.get("architecture-name", "?")
        for path, params in EXPECT.items():
            have = await children(c, base, path)
            if have is None or (not have and params):
                problems.append(f"brak menu /{path.replace(',', '/')}")
                continue
            for p in params:
                options = p if isinstance(p, tuple) else (p,)
                if not any(o in have for o in options):
                    problems.append(f"/{path.replace(',', '/')}: brak parametru {' ani '.join(options)}")
        if arch in BTH_ARCH:
            for label, paths in ANY_OF.items():
                if not any([await children(c, base, p) for p in paths]):
                    problems.append(f"{label}: zadne z menu {paths}")
    return version, arch, problems


async def main():
    async with async_session() as s:
        devices = (await s.execute(select(Device).where(Device.api_reachable.is_(True)).order_by(Device.name))).scalars().all()
    by_version = collections.defaultdict(list)
    for d in devices:
        try:
            version, arch, problems = await probe(d)
        except Exception as e:
            version, arch, problems = "?", "?", [f"blad sondy: {type(e).__name__}"]
        by_version[version].append((d.name, arch, problems))
    clean = 0
    for version in sorted(by_version):
        rows = by_version[version]
        bad = [(n, a, p) for n, a, p in rows if p]
        clean += len(rows) - len(bad)
        print(f"RouterOS {version}: {len(rows)} urzadzen, odstepstw: {len(bad)}")
        for name, arch, problems in bad:
            for p in problems:
                print(f"    {name} ({arch}): {p}")
    print(f"razem: {len(devices)} urzadzen, bez odstepstw: {clean}")


asyncio.run(main())
