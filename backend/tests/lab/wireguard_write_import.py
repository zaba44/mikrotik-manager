# Scenariusz labowy — uruchamiany WEWNATRZ kontenera backendu, na zywym portalu:
#   docker exec -i -w /app -e MTM_LAB_USER=... -e MTM_LAB_PASSWORD=... mtm-backend python - < tests/lab/wireguard_write_import.py
# Zob. tests/lab/README.md (co robi, co zmienia na routerach, jak sprzata).
import os
"""Etapy 3 i 4 end-to-end przez PRAWDZIWE endpointy portalu na urzadzeniu z MTM_LAB_WRITE_DEVICE.
Wszystko, co zalozymy, usuwamy w finally. Klucze tylko jako porownania."""
import asyncio, base64, datetime, io, re, zipfile
import httpx
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import delete, select
from app.database import async_session
from app.models import Backup, Device
from app.routeros_client import _auth, _base_url
from app.security import decrypt

BASE = "https://caddy:8443"
IF, NET, PORT = "WG_TEST", "10.199.99", "51899"


def kp():
    k = X25519PrivateKey.generate()
    return (base64.b64encode(k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())).decode(),
            base64.b64encode(k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode())


def msgs(html, cls):
    return [" ".join(re.sub(r"<[^>]+>", " ", m).split()) for m in re.findall(rf'<p class="{cls}"[^>]*>(.*?)</p>', html, re.S)]


def hidden(html):
    return dict(re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', html))


async def main():
    started = datetime.datetime.utcnow()
    async with async_session() as s:
        dev = (await s.execute(select(Device).where(Device.name == os.environ["MTM_LAB_WRITE_DEVICE"]))).scalars().one()
    did = str(dev.id)
    ros = httpx.AsyncClient(verify=False, timeout=30.0, auth=_auth(dev))
    b = _base_url(dev)
    P = f"{b}/rest/interface/wireguard/peers"
    mt_comment = next(x for x in (await ros.get(P)).json() if x["interface"] == "wg-mt")
    mt_id, mt_orig = mt_comment[".id"], mt_comment.get("comment", "")
    try:
        async with httpx.AsyncClient(base_url=BASE, verify=False, timeout=180.0, follow_redirects=True) as c:
            await c.post("/login", data={"username": os.environ["MTM_LAB_USER"], "password": os.environ["MTM_LAB_PASSWORD"]})
            peer_form = {"count": "2", "prefix": "Client_", "endpoint": "test.example.pl", "dns": "1.1.1.1",
                         "client_allowed": "", "keepalive": "25", "psk": "1", "responder": "1"}

            print("== ETAP 3a: nowy tunel ==")
            r = await c.post(f"/devices/{did}/wireguard/new/preview",
                             data={"name": IF, "port": PORT, "network": f"{NET}.0/24", "firewall": "1", **peer_form})
            print("  bledy podgladu:", msgs(r.text, "error"))
            print("  podglad:", [" ".join(re.sub(r"<[^>]+>", " ", li).split()) for li in re.findall(r"<li>(.*?)</li>", r.text, re.S)][:6])
            h = hidden(r.text)
            r = await c.post(f"/devices/{did}/wireguard/new/apply", data=h)
            print("  raport:", [" ".join(li.split()) for li in re.findall(r"<li[^>]*>([^<]+)</li>", r.text)])
            print("  ", msgs(r.text, "notice") + msgs(r.text, "error"))
            zip_href = re.search(r'href="(/devices/[^"]+/wireguard/zip\?[^"]+)"', r.text)

            iface = next(x for x in (await ros.get(f"{b}/rest/interface/wireguard")).json() if x["name"] == IF)
            rules = [x.get("comment") for x in (await ros.get(f"{b}/rest/ip/firewall/filter")).json() if x.get("chain") == "input"]
            print("  na routerze: interfejs port", iface.get("listen-port"), "| reguly input:", rules)
            peers = [x for x in (await ros.get(P)).json() if x["interface"] == IF]
            print("  peery:", [(x.get("name"), x["allowed-address"], bool(x.get("private-key")), x.get("client-endpoint")) for x in peers])

            print("\n== ETAP 3b: ZIP ==")
            r = await c.get(zip_href.group(1).replace("&amp;", "&"))
            z = zipfile.ZipFile(io.BytesIO(r.content))
            names = sorted(z.namelist())
            conf0 = z.read([n for n in names if n.endswith(".conf")][0]).decode()
            print("  HTTP", r.status_code, "| pliki:", names, "| no-store:", "no-store" in r.headers.get("cache-control", ""))
            print("  config kompletny (bez wypelniaczy):", "UZUPELNIJ" not in conf0 and "BRAK_KLUCZA" not in conf0,
                  "| Endpoint:", re.search(r"Endpoint = (\S+)", conf0).group(1),
                  "| PNG:", all(z.read(n)[:4] == b"\x89PNG" for n in names if n.endswith(".png")))

            print("\n== ETAP 3c: dodanie 2 peerow do istniejacego ==")
            r = await c.post(f"/devices/{did}/wireguard/add/preview", data={"iface": IF, **peer_form})
            h = hidden(r.text)
            print("  zaplanowane:", h.get("planned"))
            r = await c.post(f"/devices/{did}/wireguard/add/apply", data=h)
            print("  ", msgs(r.text, "notice") + msgs(r.text, "error"))

            print("\n== ETAP 3d: ktos zmienil router miedzy podgladem a zatwierdzeniem ==")
            r = await c.post(f"/devices/{did}/wireguard/add/preview", data={"iface": IF, **peer_form, "count": "1"})
            h = hidden(r.text)
            _, intruder_pub = kp()
            await ros.put(P, json={"interface": IF, "allowed-address": f"{h['planned']}/32", "public-key": intruder_pub,
                                   "name": "z_winboxa"})
            r = await c.post(f"/devices/{did}/wireguard/add/apply", data=h)
            print("  zatwierdzenie:", msgs(r.text, "error"))

            print("\n== ETAP 3e: blokady ==")
            r = await c.post(f"/devices/{did}/wireguard/add/preview", data={"iface": "wg-mt", **peer_form})
            print("  dodawanie na tunelu portalu:", msgs(r.text, "error"))
            r = await c.post(f"/devices/{did}/wireguard/import/preview", data={"iface": "wg-mt", "mode": "fill"},
                             files=[("files", ("a.conf", b"[Interface]\nAddress = 1.1.1.1/32\n", "text/plain"))])
            print("  import na tunelu portalu:", msgs(r.text, "error"))

            print("\n== ETAP 3f: komentarze ==")
            pid = next(x[".id"] for x in (await ros.get(P)).json() if x["interface"] == IF and x.get("name") == "Client_2")
            r = await c.post(f"/devices/{did}/wireguard/comment", data={"iface": IF, "pid": pid, "comment": "Client_2__laptop"})
            print("  WG_TEST:", msgs(r.text, "notice"), "| HX-Trigger:", r.headers.get("hx-trigger"))
            r = await c.post(f"/devices/{did}/wireguard/comment", data={"iface": "wg-mt", "pid": mt_id, "comment": mt_orig + " (test)"})
            print("  tunel portalu (dozwolone):", msgs(r.text, "notice"))

            print("\n== ETAP 4: import .conf ==")
            # „stare reczne" peery: tylko klucz publiczny, zero pol client-*, brak klucza prywatnego
            olds = {}
            for octet in (20, 21, 22):
                priv, pub = kp()
                rr = await ros.put(P, json={"interface": IF, "allowed-address": f"{NET}.{octet}/32", "public-key": pub,
                                            "name": f"stary_{octet}"})
                olds[octet] = (priv, pub, rr.json()[".id"])
            srv_pub = iface["public-key"]

            def conf(name, ip, priv, pub, server=srv_pub, with_priv=True):
                lines = ["[Interface]", f"## {name}", f"Address = {ip}/24"]
                if with_priv:
                    lines.append(f"PrivateKey = {priv}")
                lines += [f"## PublicKey = {pub}", "DNS = 192.168.88.1", "[Peer]",
                          f"Endpoint = vpn.firma.pl:{PORT}", f"PublicKey = {server}",
                          "AllowedIPs = 192.168.88.0/24", "PersistentKeepalive = 25"]
                return "\n".join(lines) + "\n"

            _, foreign_srv = kp()
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("Client_20.conf", conf("Client_20_dominik", f"{NET}.20", *olds[20][:2]))
                zf.writestr("Client_21.conf", conf("Client_21", f"{NET}.99", *olds[21][:2]))       # zly adres
                zf.writestr("Client_22.conf", conf("Client_22", f"{NET}.22", *olds[22][:2], with_priv=False))
                zf.writestr("obcy.conf", conf("obcy", f"{NET}.20", *olds[20][:2], server=foreign_srv))
            r = await c.post(f"/devices/{did}/wireguard/import/preview", data={"iface": IF, "mode": "fill"},
                             files=[("files", ("klienci.zip", buf.getvalue(), "application/zip"))])
            print("  podglad: no-store:", "no-store" in r.headers.get("cache-control", ""),
                  "| klucz prywatny na stronie:", olds[20][0] in r.text)
            for row in re.findall(r"<tr>\s*<td><b>(.*?)</tr>", r.text, re.S):
                cells = [" ".join(re.sub(r"<[^>]+>", " ", x).split()) for x in re.findall(r"<td>(.*?)</td>", "<td><b>" + row, re.S)]
                print("   ", cells[0][:22].ljust(22), "|", cells[2].ljust(9), "|", cells[3][:95], "|", cells[4][:70])
            token = hidden(r.text).get("token")
            r = await c.post(f"/devices/{did}/wireguard/import/apply", data={"token": token})
            print("  wynik:", re.search(r'zapisano \d+ z \d+', r.text).group(0) if re.search(r'zapisano \d+ z \d+', r.text) else msgs(r.text, "error"))
            r = await c.post(f"/devices/{did}/wireguard/import/apply", data={"token": token})
            print("  ponowne uzycie tokenu:", msgs(r.text, "error"))

            rows = {x[".id"]: x for x in (await ros.get(P)).json()}
            p20, p22 = rows[olds[20][2]], rows[olds[22][2]]
            print("  .20: klucz prywatny = z pliku:", p20.get("private-key") == olds[20][0],
                  "| public bez zmian:", p20.get("public-key") == olds[20][1],
                  "| nazwa nietknieta:", p20.get("name"),
                  "| client-*:", p20.get("client-address"), p20.get("client-dns"), p20.get("client-endpoint"),
                  p20.get("client-keepalive"), p20.get("client-allowed-address"))
            print("  .22: bez klucza prywatnego:", not p22.get("private-key"), "| client-endpoint:", p22.get("client-endpoint"))
            print("  .21 (konflikt) nietkniety:", not rows[olds[21][2]].get("client-endpoint"))

            r = await c.get(f"/devices/{did}/wireguard/config", params={"iface": IF, "pid": olds[20][2]})
            body = re.search(r"<textarea[^>]*>(.*?)</textarea>", r.text, re.S).group(1)
            print("  config .20 po imporcie kompletny:", "UZUPELNIJ" not in body and "BRAK_KLUCZA" not in body)

        print("\n== zrzuty ==")
        async with async_session() as s:
            snaps = (await s.execute(select(Backup).where(Backup.device_id == dev.id, Backup.backup_type == "wg-snapshot",
                                                         Backup.created_at >= started).order_by(Backup.created_at))).scalars().all()
            secrets = [olds[o][0] for o in olds]
            for sn in snaps:
                txt = decrypt(sn.content_text_encrypted)
                print(f"   {sn.note!r:72s} klucz prywatny w srodku: {any(k in txt for k in secrets)}")
    finally:
        print("\n== SPRZATANIE ==")
        await ros.patch(f"{P}/{mt_id}", json={"comment": mt_orig})
        for x in (await ros.get(P)).json():
            if x["interface"] == IF:
                await ros.delete(f"{P}/{x['.id']}")
        for x in (await ros.get(f"{b}/rest/ip/firewall/filter")).json():
            if x.get("comment") == f"accept {IF}":
                await ros.delete(f"{b}/rest/ip/firewall/filter/{x['.id']}")
        for x in (await ros.get(f"{b}/rest/ip/address")).json():
            if x.get("interface") == IF:
                await ros.delete(f"{b}/rest/ip/address/{x['.id']}")
        for x in (await ros.get(f"{b}/rest/interface/wireguard")).json():
            if x["name"] == IF:
                await ros.delete(f"{b}/rest/interface/wireguard/{x['.id']}")
        mt_now = next(x for x in (await ros.get(P)).json() if x[".id"] == mt_id)
        print("  komentarz tunelu portalu przywrocony:", mt_now.get("comment", "") == mt_orig)
        print("  WG:", [x["name"] for x in (await ros.get(f"{b}/rest/interface/wireguard")).json()],
              "| reguly input:", len([x for x in (await ros.get(f"{b}/rest/ip/firewall/filter")).json() if x.get("chain") == "input"]),
              "| adresy:", [a["address"] for a in (await ros.get(f"{b}/rest/ip/address")).json()])
        async with async_session() as s:
            res = await s.execute(delete(Backup).where(Backup.device_id == dev.id, Backup.backup_type == "wg-snapshot",
                                                       Backup.created_at >= started))
            await s.commit()
            print("  usuniete testowe zrzuty:", res.rowcount)
        await ros.aclose()


asyncio.run(main())
