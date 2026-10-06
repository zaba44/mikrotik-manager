# Scenariusz labowy — uruchamiany WEWNATRZ kontenera backendu, na zywym portalu:
#   docker exec -i -w /app -e MTM_LAB_USER=... -e MTM_LAB_PASSWORD=... mtm-backend python - < tests/lab/bth_router.py
# Zob. tests/lab/README.md (co robi, co zmienia na routerach, jak sprzata).
import os
"""Etap 2 przez PRAWDZIWE endpointy portalu na Router. Sprzata po sobie w finally."""
import asyncio, json, re, datetime
import httpx
from sqlalchemy import select, delete
from app.database import async_session
from app.models import Backup, Device
from app.routeros_client import _auth, _base_url
from app.security import decrypt

BASE = "https://caddy:8443"
KEY = re.compile(r"[A-Za-z0-9+/]{42,43}=")
USER = "mtm-test-portal"


def mask(t):
    t = re.sub(r"(?im)(PrivateKey\s*=\s*)\S+", r"\1<MASKA>", t)
    return KEY.sub("<klucz>", t)


def notice(html):
    m = re.search(r'<p class="(notice|error)">(.*?)</p>', html, re.S)
    return f"{m.group(1)}: {' '.join(m.group(2).split())}" if m else None


async def main():
    started = datetime.datetime.utcnow()
    async with async_session() as s:
        dev = (await s.execute(select(Device).where(Device.name == os.environ["MTM_LAB_BTH_DEVICE"]))).scalars().one()
        dz = (await s.execute(select(Device).where(Device.name == os.environ["MTM_LAB_NO_BTH_DEVICE"]))).scalars().one()
    rid = str(dev.id)
    async with httpx.AsyncClient(verify=False, timeout=40.0, auth=_auth(dev)) as ros:
        before = (await ros.get(f"{_base_url(dev)}/rest/ip/cloud")).json()
    try:
        async with httpx.AsyncClient(base_url=BASE, verify=False, timeout=120.0, follow_redirects=True) as c:
            await c.post("/login", data={"username": os.environ["MTM_LAB_USER"], "password": os.environ["MTM_LAB_PASSWORD"]})

            print("== 1. strona przy wylaczonym BTH ==")
            p = (await c.get(f"/devices/{rid}/bth")).text
            print("  przycisk wlaczenia:", "Włącz Back To Home" in p, "| DDNS zostaje:", "zostaje bez zmian" in p)

            print("\n== 2. wlaczenie przez portal ==")
            r = await c.post(f"/devices/{rid}/bth/enable")
            print("  ", notice(r.text))
            p = r.text
            print("  status:", re.findall(r'<span class="pill pill-[a-z]+"><span class="dot"></span>([^<]+)<', p)[:1],
                  "| adres VPN:", re.findall(r'<dt>Adres VPN</dt><dd><code>([^<]+)<', p))

            print("\n== 3. dodanie uzytkownika (allow-lan, wygasa po 1d) ==")
            r = await c.post(f"/devices/{rid}/bth/users/add", data={"name": USER, "allow_lan": "1", "expires": "1d"})
            print("  ", notice(r.text))
            row = re.search(rf"<b>{USER}</b>.*?</tr>", r.text, re.S)
            cells = re.findall(r"<td[^>]*>(.*?)</td>", row.group(0), re.S) if row else []
            flat = [" ".join(re.sub(r"<[^>]+>", " ", x).split()) for x in cells]
            print("   wiersz:", flat[1:6] if flat else "BRAK")
            uid = re.search(r'name="uid" value="([^"]+)"', r.text).group(1)

            print("\n== 4. duplikat nazwy ==")
            r = await c.post(f"/devices/{rid}/bth/users/add", data={"name": USER, "allow_lan": "1"})
            print("  ", notice(r.text))

            print("\n== 5. komentarz ==")
            r = await c.post(f"/devices/{rid}/bth/users/comment", data={"uid": uid, "comment": "telefon testowy"})
            print("  ", notice(r.text), "| widoczny:", 'value="telefon testowy"' in r.text)

            print("\n== 6. config pelny ==")
            r = await c.get(f"/devices/{rid}/bth/config", params={"uid": uid})
            body = re.search(r"<textarea[^>]*>(.*?)</textarea>", r.text, re.S).group(1)
            print("   no-store:", "no-store" in r.headers.get("cache-control", ""), "| QR:", "<svg" in r.text)
            print("\n".join("     " + ln for ln in mask(body).strip().splitlines()))

            print("\n== 7. config tylko LAN (pierwsze przelaczenie = wszystkie podsieci) ==")
            r = await c.get(f"/devices/{rid}/bth/config", params={"uid": uid, "mode": "lan"})
            body = re.search(r"<textarea[^>]*>(.*?)</textarea>", r.text, re.S).group(1)
            print("   zaznaczone:", re.findall(r'value="([0-9./]+)" checked', r.text))
            print("\n".join("     " + ln for ln in mask(body).strip().splitlines()))
            print("   ostrzezenia:", [" ".join(w.split()) for w in re.findall(r'<p class="notice"[^>]*>(.*?)</p>', r.text, re.S)])

            print("\n== 8. LAN bez zaznaczonych podsieci ==")
            r = await c.get(f"/devices/{rid}/bth/config", params={"uid": uid, "mode": "lan", "picked": "1"})
            print("   ostrzezenie:", [" ".join(w.split())[:70] for w in re.findall(r'<p class="notice"[^>]*>(.*?)</p>', r.text, re.S)])

            print("\n== 9. router bez wsparcia (MTM_LAB_NO_BTH_DEVICE) ==")
            r = await c.get(f"/devices/{dz.id}/bth")
            print("  ", notice(r.text))

        print("\n== 10. zrzuty przed zapisami ==")
        async with async_session() as s:
            snaps = (await s.execute(select(Backup).where(Backup.device_id == dev.id, Backup.backup_type == "wg-snapshot",
                                                         Backup.created_at >= started).order_by(Backup.created_at))).scalars().all()
            for b in snaps:
                payload = json.loads(decrypt(b.content_text_encrypted))
                txt = json.dumps(payload)
                print(f"   {b.note!r:62s} uzytk.={len(payload['items'])} klucz_prywatny_w_srodku={'private-key' in txt} token={'file-access-token' in txt}")
            snap_ids = [b.id for b in snaps]
    finally:
        print("\n== SPRZATANIE ==")
        async with httpx.AsyncClient(verify=False, timeout=40.0, auth=_auth(dev)) as ros:
            b = _base_url(dev)
            for u in (await ros.get(f"{b}/rest/ip/cloud/back-to-home-user")).json() if (await ros.get(f"{b}/rest/ip/cloud")).json().get("back-to-home-vpn") == "enabled" else []:
                if u.get("name") == USER:
                    print("  usuniecie uzytkownika ->", (await ros.delete(f"{b}/rest/ip/cloud/back-to-home-user/{u['.id']}")).status_code)
            print("  przywrocenie BTH ->", (await ros.post(f"{b}/rest/ip/cloud/set", json={"back-to-home-vpn": before["back-to-home-vpn"]})).status_code)
            await asyncio.sleep(4)
            after = (await ros.get(f"{b}/rest/ip/cloud")).json()
            for k in ("ddns-enabled", "dns-name", "back-to-home-vpn"):
                print(f"  {k:18s} przed={before.get(k)!s:34s} po={after.get(k)!s}")
        async with async_session() as s:
            res = await s.execute(delete(Backup).where(Backup.device_id == dev.id, Backup.backup_type == "wg-snapshot",
                                                       Backup.created_at >= started))
            await s.commit()
            print("  usuniete testowe zrzuty:", res.rowcount)

asyncio.run(main())
