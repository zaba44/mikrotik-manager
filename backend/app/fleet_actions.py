"""Akcje wykonywane na routerach przez API — to, co dotad trzeba bylo wklejac recznie
w terminalu kazdego urzadzenia. Jedna akcja = jeden skrypt RouterOS w bloku `{ }`,
wykonany przez `/rest/execute` z `as-string` (synchronicznie, z wynikiem).

Skrypty sa IDEMPOTENTNE: mozna je puszczac wielokrotnie i na calej flocie naraz.
"""
import asyncio
from dataclasses import dataclass

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app import admin_block
from app.models import Device
from app.routeros_client import _auth, _base_url, _device_sem
from app.wg_config import wg

# Ile routerow naraz. Kazdy ma jeszcze wlasny limit rownoleglych zapytan (_device_sem).
PARALLEL = 6
LOG_RULE_COMMENT = "MTM: logowania ludzi"

# RouterOS co 10-30 min odnawia sesje REST konta mtm-api i zapisuje trzy linie
# `system,info,account` — ~110 wpisow na dobe, bufor 1000 linii zapycha sie w tydzien.
# Regula `info` przestaje zapisywac `account`, a osobna regula zostawia logowania LUDZI
# (Winbox/SSH/WebFig/telnet/FTP). Nieudane logowania maja temat error,critical — zostaja.
# `regex` jest od ~7.23; starszy RouterOS nie zna parametru, stad :parse i on-error.
# Ruszamy tylko regule o temacie dokladnie `info` — wlasnych ustawien admina nie nadpisujemy.
LOG_TIDY_LINES = [
    ':foreach r in=[/system logging find where topics~"info" and action=memory] do={'
    ':if ([:tostr [/system logging get $r topics]] = "info") do={/system logging set $r topics=info,!account}}',
    f':if ([:len [/system logging find comment="{LOG_RULE_COMMENT}"]] = 0) do={{'
    ':do {[[:parse "/system logging add topics=account regex=\\"via (winbox|ssh|web|telnet|ftp)\\" '
    f'action=memory comment=\\"{LOG_RULE_COMMENT}\\""]]}} on-error={{}}}}',
]


def log_tidy_script() -> str:
    return "\n".join(["{", *LOG_TIDY_LINES,
                      ':put "MTM: log uporzadkowany - logowania konta API nie sa juz zapisywane"', "}"]) + "\n"


def log_clear_script() -> str:
    # RouterOS nie ma „wyczysc log": bufor skraca sie do 1 linii i wraca do poprzedniego rozmiaru.
    return "\n".join([
        "{",
        ":local n [/system logging action get [find name=memory] memory-lines]",
        "/system logging action set [find name=memory] memory-lines=1",
        "/system logging action set [find name=memory] memory-lines=$n",
        ':put ("MTM: log wyczyszczony (bufor " . $n . " linii)")',
        "}",
    ]) + "\n"


def cert_renew_script(device_ip: str) -> str:
    """Nowy certyfikat www-ssl na 10 lat. Nowy powstaje OBOK starego i dopiero podpisany
    przejmuje usluge — polaczenie API nie zostaje ani chwili bez certyfikatu."""
    return "\n".join([
        "{",
        "/certificate remove [find name=mtm-cert-new]",
        f"/certificate add name=mtm-cert-new common-name={device_ip} days-valid=3650",
        "/certificate sign mtm-cert-new; :local w 0; :while (([/certificate get [find name=mtm-cert-new] "
        "private-key] != true) && ($w < 60)) do={:delay 1s; :set w ($w + 1)}",
        ':if ([/certificate get [find name=mtm-cert-new] private-key] != true) do={'
        ':error "MTM: nowy certyfikat nie zostal podpisany - nic nie zmieniono"}',
        "/ip service set www-ssl certificate=mtm-cert-new",
        "/certificate remove [find name=mtm-cert]",
        "/certificate set [find name=mtm-cert-new] name=mtm-cert",
        ':put "MTM: certyfikat odnowiony na 10 lat"',
        "}",
    ]) + "\n"


@dataclass(frozen=True)
class Action:
    key: str
    label: str
    description: str
    confirm: str


ACTIONS: dict[str, Action] = {a.key: a for a in (
    Action("winbox", "Winbox dla adminów",
           "Wpuszcza Winbox z bloku administracyjnego, tylko przez tunel. Regułę wstawia przed pierwszą "
           "regułą akceptującą port Winboxa albo na górę listy; istniejącej nie przesuwa.",
           "Dodać regułę Winbox dla bloku administracyjnego"),
    Action("log_tidy", "Uporządkuj log",
           "Przestaje zapisywać w logu routera logowania konta API portalu (ok. 110 wpisów na dobę). "
           "Logowania przez Winbox, SSH i WebFig oraz nieudane próby zostają.",
           "Wyłączyć zapisywanie logowań konta API w logu"),
    Action("log_clear", "Wyczyść log",
           "Czyści bufor logu w pamięci routera. Logi na dysku i wysyłane dalej (syslog) zostają.",
           "Wyczyścić log w pamięci"),
    Action("cert_renew", "Odnów certyfikat API",
           "Wystawia nowy certyfikat usługi www-ssl na 10 lat i podmienia stary bez przerwy w działaniu API.",
           "Odnowić certyfikat API"),
)}


async def script_for(session: AsyncSession, device: Device, key: str) -> str:
    if key == "winbox":
        return admin_block.winbox_script(str(await admin_block.get_block(session)))
    if key == "log_tidy":
        return log_tidy_script()
    if key == "log_clear":
        return log_clear_script()
    if key == "cert_renew":
        return cert_renew_script(str(device.wg_ip))
    raise KeyError(key)


async def run_script(device: Device, script: str, timeout: float = 90.0) -> dict:
    """{"ok", "output"}. Blad skryptu RouterOS wraca jako HTTP 4xx/5xx z opisem w `detail`."""
    if not device.api_username or not device.api_password_encrypted:
        return {"ok": False, "output": "brak danych API"}
    try:
        async with _device_sem(device), httpx.AsyncClient(verify=False, timeout=timeout, auth=_auth(device)) as c:
            resp = await c.post(f"{_base_url(device)}/rest/execute", json={"as-string": "", "script": script})
        try:
            data = resp.json()
        except ValueError:
            data = {}
        if resp.status_code >= 400:
            return {"ok": False, "output": str(data.get("detail") or data.get("message") or f"HTTP {resp.status_code}")}
        out = str(data.get("ret", "")).replace("\r\n", "\n").strip()
        return {"ok": True, "output": out}
    except httpx.TimeoutException:
        return {"ok": False, "output": "router nie odpowiedział w czasie"}
    except Exception as e:
        return {"ok": False, "output": f"{type(e).__name__}: {e}"}


async def run_many(session: AsyncSession, devices: list[Device], key: str) -> list[dict]:
    """Ta sama akcja na wielu routerach, po kilka naraz. Kolejnosc wynikow jak na wejsciu."""
    if not wg.configured:
        return [{"device": d, "ok": False, "output": "sieć WireGuard nie jest skonfigurowana"} for d in devices]
    scripts = {d.id: await script_for(session, d, key) for d in devices}
    gate = asyncio.Semaphore(PARALLEL)

    async def one(device: Device) -> dict:
        async with gate:
            return {"device": device, **await run_script(device, scripts[device.id])}
    return list(await asyncio.gather(*(one(d) for d in devices)))
