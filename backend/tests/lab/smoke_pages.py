# Scenariusz labowy — uruchamiany WEWNATRZ kontenera backendu, na zywym portalu:
#   docker exec -i -w /app -e MTM_LAB_USER=... -e MTM_LAB_PASSWORD=... mtm-backend python - < tests/lab/smoke_pages.py
# Zob. tests/lab/README.md (co robi, co zmienia na routerach, jak sprzata).
import os
"""Test dymny po aktualizacji Starlette 1.x: kazda strona i fragment musza dac 200.
Przez Caddy'ego (HTTPS) — ciasteczko sesji ma teraz flage Secure."""
import asyncio, re
import httpx

BASE = "https://caddy:8443"


async def main():
    async with httpx.AsyncClient(base_url=BASE, verify=False, timeout=120.0, follow_redirects=False) as c:
        r = await c.post("/login", data={"username": os.environ["MTM_LAB_USER"], "password": os.environ["MTM_LAB_PASSWORD"]})
        cookie = r.headers.get("set-cookie", "")
        print("logowanie:", r.status_code, "| Secure:", "secure" in cookie.lower(), "| HttpOnly:", "httponly" in cookie.lower(),
              "| SameSite=lax:", "samesite=lax" in cookie.lower())
        c.follow_redirects = True
        home = (await c.get("/")).text
        devs = dict(re.findall(r'href="/devices/([0-9a-f-]{36})"[^>]*>\s*([^<]+)', home))
        locs = list(dict.fromkeys(re.findall(r'href="/locations/([0-9a-f-]{36})"', home)))
        pages = ["/", "/locations", "/settings", "/settings/cert", "/settings/syslog", "/settings/smtp",
                 "/settings/notifications", "/settings/admin-peers", "/settings/users", "/settings/about", "/account"]
        pages += [f"/locations/{l}" for l in locs]
        frags = ["", "/fragment/health", "/fragment/interfaces", "/fragment/addresses", "/fragment/poe",
                 "/fragment/leases", "/fragment/syslog", "/fragment/backups", "/fragment/notifications",
                 "/fragment/winbox-rule", "/fragment/wireguard", "/wireguard", "/bth"]
        reachable = []
        for did, name in devs.items():
            st = (await c.get(f"/devices/{did}")).text
            if "nieosiągalne" not in st or "osiągalne</dd>" in st:
                reachable.append((did, name.strip()))
        for did, _ in reachable:
            pages += [f"/devices/{did}{f}" for f in frags]
        bad = []
        for p in pages:
            r = await c.get(p)
            if r.status_code != 200 or "Internal Server Error" in r.text or "Traceback" in r.text:
                bad.append((p, r.status_code))
        print(f"stron i fragmentow: {len(pages)} | urzadzen: {len(reachable)} | bledy: {len(bad)}")
        for p, code in bad[:15]:
            print("   BLAD", code, p)


asyncio.run(main())
