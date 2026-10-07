import asyncio
import ipaddress

import httpx

from app.models import Device
from app.security import decrypt

_TIMEOUT = 5.0
_INSTALL_TIMEOUT = 180.0  # pobieranie+instalacja pakietu RouterOS może potrwać kilka minut

# Limit równoczesnych zapytań REST NA JEDNO urządzenie. RouterOS potrafi zerwać część
# połączeń, gdy przeglądarka wysyła kilkadziesiąt naraz (np. „zbadaj wszystkie statyczne"
# przy kilkudziesięciu dzierżawach) — i wtedy sypie się też odczyt dzierżaw/kondycji.
# Semafor per-device serializuje ruch do kilku równoczesnych, więc pingi lecą w kolejce
# zamiast zalać router. Pojedyncze żądania i tak działały — problem był tylko w nawale.
# Empirycznie: przy 4 router kolejkuje u siebie i wolniejsze żądania (dzierżawy przy
# trwających pingach) potrafią przekroczyć timeout — 2 jest stabilne.
_DEVICE_CONCURRENCY = 2
_device_semaphores: dict[str, asyncio.Semaphore] = {}


def _device_sem(device: Device) -> asyncio.Semaphore:
    key = str(device.id)
    sem = _device_semaphores.get(key)
    if sem is None:
        sem = asyncio.Semaphore(_DEVICE_CONCURRENCY)
        _device_semaphores[key] = sem
    return sem


def _auth(device: Device) -> tuple[str, str]:
    return (device.api_username, decrypt(device.api_password_encrypted))


def _base_url(device: Device) -> str:
    return f"https://{device.wg_ip}"


async def get_status(device: Device) -> dict:
    if not device.api_username or not device.api_password_encrypted:
        return {"reachable": False, "error": "brak danych API (urządzenie zarejestrowane bez configu API)"}

    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, auth=_auth(device)) as client:
            resp = await client.get(f"{_base_url(device)}/rest/system/resource")
            resp.raise_for_status()
            data = resp.json()

            identity = None
            try:
                identity_resp = await client.get(f"{_base_url(device)}/rest/system/identity")
                identity_resp.raise_for_status()
                identity = identity_resp.json().get("name")
            except Exception:
                pass  # nazwa MikroTika to tylko dodatek do statusu, brak nie blokuje reszty

            winbox_port = None
            try:
                svc_resp = await client.get(f"{_base_url(device)}/rest/ip/service")
                svc_resp.raise_for_status()
                for svc in svc_resp.json():
                    if svc.get("name") == "winbox":
                        winbox_port = svc.get("port")
                        break
            except Exception:
                pass  # port Winbox to dodatek — przyda się, gdy dojdzie zdalny dostęp

            return {
                "reachable": True,
                "version": data.get("version"),
                "uptime": data.get("uptime"),
                "identity": identity,
                "winbox_port": winbox_port,
                "board_name": data.get("board-name"),
                "error": None,
            }
    except Exception as e:
        return {"reachable": False, "version": None, "uptime": None, "error": str(e)}


async def get_routerboard_info(device: Device) -> dict:
    """Zwraca current-firmware/upgrade-firmware/model albo {'ok': False, 'error': ...}."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, auth=_auth(device)) as client:
            resp = await client.get(f"{_base_url(device)}/rest/system/routerboard")
            resp.raise_for_status()
            data = resp.json()
            return {
                "ok": True,
                "current_firmware": data.get("current-firmware"),
                "upgrade_firmware": data.get("upgrade-firmware"),
                "model": data.get("model"),
                "serial": data.get("serial-number"),
            }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def check_for_updates(device: Device) -> dict:
    """Odpytuje serwery MikroTika o dostępną wersję. Zwraca installed/latest/status."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0, auth=_auth(device)) as client:
            resp = await client.post(f"{_base_url(device)}/rest/system/package/update/check-for-updates")
            resp.raise_for_status()
            data = resp.json()
            # Endpoint zwraca listę snapshotów (progres); interesuje nas ostatni.
            last = data[-1] if isinstance(data, list) and data else data
            return {
                "ok": True,
                "installed_version": last.get("installed-version"),
                "latest_version": last.get("latest-version"),
                "status": last.get("status"),
            }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def install_package_update(device: Device) -> dict:
    """Blokujące — pobiera i instaluje najnowszy pakiet, urządzenie samo się restartuje.
    Może potrwać kilka minut, stąd wydłużony timeout."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=_INSTALL_TIMEOUT, auth=_auth(device)) as client:
            resp = await client.post(f"{_base_url(device)}/rest/system/package/update/install")
            resp.raise_for_status()
            data = resp.json()
            last = data[-1] if isinstance(data, list) and data else data
            return {"ok": True, "detail": last.get("status") if isinstance(last, dict) else str(last)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def upgrade_firmware(device: Device) -> dict:
    """Przygotowuje nowy firmware (zgodny z aktualnie zainstalowanym RouterOS) —
    wymaga osobnego reboot(), żeby się faktycznie zaaplikował."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, auth=_auth(device)) as client:
            resp = await client.post(f"{_base_url(device)}/rest/system/routerboard/upgrade")
            resp.raise_for_status()
            return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def wait_for_router_file_stable(
    device: Device, filename: str, *, timeout_seconds: float = 20.0, poll_interval: float = 1.0
) -> dict:
    """Polluje /rest/file aż rozmiar pliku na routerze przestanie rosnąć.
    Konieczne, bo /rest/execute NIE czeka na zakończenie skryptu — potwierdzone
    empirycznie na żywym sprzęcie (AP DÓŁ): `/export ... file=` zwraca się natychmiast
    (zwraca referencję typu `*1B`, nie tekst), a wywołany zaraz potem `/tool fetch`
    potrafił złapać plik jeszcze w trakcie zapisu (0 bajtów przesłanych). Bez tego
    /system backup/save (REST menu-path, może się zachowywać inaczej) też nie jest
    z góry pewny — sprawdzamy dla obu typów kopii tym samym mechanizmem."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_seconds
    last_size = -1
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, auth=_auth(device)) as client:
            while loop.time() < deadline:
                resp = await client.get(f"{_base_url(device)}/rest/file", params={"name": filename})
                resp.raise_for_status()
                data = resp.json()
                if data:
                    size = int(data[0].get("size", 0))
                    if size > 0 and size == last_size:
                        return {"ok": True}
                    last_size = size
                await asyncio.sleep(poll_interval)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": False, "error": f"plik {filename} nie ustabilizował się na routerze w ciągu {timeout_seconds}s"}


async def export_config(device: Device, *, name: str) -> dict:
    """`/export terse show-sensitive file=<name>` — terse, żeby każda linijka (np.
    reguła firewalla) była samodzielna do skopiowania, show-sensitive żeby hasła były
    w jawnej postaci (kopia ma być faktycznie kompletna do odtworzenia). Zapis do
    pliku zamiast liczenia na tekst w odpowiedzi REST — /rest/execute zwraca tylko
    referencję do joba, nie przechwytuje wydruku konsoli (potwierdzone empirycznie,
    patrz wait_for_router_file_stable)."""
    script = f"/export terse show-sensitive file={name}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, auth=_auth(device)) as client:
            resp = await client.post(f"{_base_url(device)}/rest/execute", json={"script": script})
            resp.raise_for_status()
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    filename = f"{name}.rsc"
    stable = await wait_for_router_file_stable(device, filename)
    if not stable["ok"]:
        return {"ok": False, "error": stable["error"]}
    return {"ok": True, "filename": filename}


async def create_binary_backup(device: Device, *, name: str) -> dict:
    """Tworzy plik backupu na routerze (/system backup save), name bez rozszerzenia
    — RouterOS sam dopisuje .backup."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0, auth=_auth(device)) as client:
            resp = await client.post(
                f"{_base_url(device)}/rest/system/backup/save", json={"name": name}
            )
            resp.raise_for_status()
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    filename = f"{name}.backup"
    stable = await wait_for_router_file_stable(device, filename)
    if not stable["ok"]:
        return {"ok": False, "error": stable["error"]}
    return {"ok": True, "filename": filename}


async def push_backup_via_fetch(
    device: Device,
    *,
    local_filename: str,
    remote_filename: str,
    sftp_host: str,
    sftp_port: int,
    sftp_user: str,
    sftp_password: str,
) -> dict:
    """Router sam wysyła plik przez SFTP (push) — składnia potwierdzona ręcznie na
    żywym sprzęcie (Krok 0) przed napisaniem tej funkcji."""
    script = (
        f'/tool fetch upload=yes url="sftp://{sftp_host}:{sftp_port}/{remote_filename}" '
        f'user="{sftp_user}" password="{sftp_password}" src-path={local_filename}'
    )
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0, auth=_auth(device)) as client:
            resp = await client.post(f"{_base_url(device)}/rest/execute", json={"script": script})
            resp.raise_for_status()
            return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def cleanup_router_backup_file(device: Device, filename: str) -> dict:
    """Usuwa lokalny plik backupu na routerze po udanym wysłaniu — nie zaśmiecamy
    dysku routera kopiami, które i tak trzymamy u siebie."""
    script = f'/file remove [find name="{filename}"]'
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, auth=_auth(device)) as client:
            resp = await client.post(f"{_base_url(device)}/rest/execute", json={"script": script})
            resp.raise_for_status()
            return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _to_float(value, default=None):
    """RouterOS oddaje liczby jako lancuchy; brak pomiaru ma zostac None, NIE zerem —
    zero znaczyloby „zmierzono 0 W", a to zupelnie co innego niz „ten model nie mierzy"."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# Czujniki z /system/health. Nazwy pól różnią się między modelami (empiria 2026-08-03
# na 9 urządzeniach): wAP ax daje voltage/cpu-temperature/board-temperature1, RB5009
# dokłada jack-voltage/poe-*, CRS328 wentylatory i pobór PoE, hAP ax2 samą temperaturę
# CPU. Nieznane nazwy pokazujemy surowo — RouterOS dokłada czujniki w nowych modelach.
_HEALTH_LABELS = {
    "cpu-temperature": "Temperatura CPU",
    "temperature": "Temperatura",
    "board-temperature1": "Temperatura płyty",
    "board-temperature2": "Temperatura płyty 2",
    "switch-temperature": "Temperatura switcha",
    "voltage": "Napięcie",
    "jack-voltage": "Napięcie (gniazdo)",
    "2pin-voltage": "Napięcie (2-pin)",
    "poe-in-voltage": "Napięcie PoE-in",
    "poe-out-consumption": "Pobór PoE",
    "power-consumption": "Pobór mocy",
    "current": "Prąd",
    "fan-state": "Wentylatory",
    "fan1-speed": "Wentylator 1",
    "fan2-speed": "Wentylator 2",
    "fan3-speed": "Wentylator 3",
    "fan4-speed": "Wentylator 4",
    "psu1-state": "Zasilacz 1",
    "psu2-state": "Zasilacz 2",
    "psu1-voltage": "Napięcie zasilacza 1",
    "psu2-voltage": "Napięcie zasilacza 2",
    "psu1-current": "Prąd zasilacza 1",
    "psu2-current": "Prąd zasilacza 2",
}
# kolejność wyświetlania: najpierw temperatury, potem zasilanie, na końcu wentylatory
_HEALTH_ORDER = ("temperature", "voltage", "consumption", "current", "psu", "fan")
# Progi ostrzeżeń dla temperatur — MikroTiki normalnie chodzą w 50–65°C, więc dopiero
# wyraźnie wyższe wartości podświetlamy (żeby nie robić fałszywych alarmów na całej flocie).
_TEMP_WARN, _TEMP_BAD = 80.0, 90.0


async def _fetch_health(client: httpx.AsyncClient, device: Device) -> list:
    """Surowe /system/health. Część modeli (mAP lite, hAP ac2) NIE MA tej gałęzi i zwraca
    400 „no such command or directory (health)" — to nie awaria, tylko cecha sprzętu,
    więc traktujemy jak brak czujników, nie jak błąd odczytu kondycji."""
    try:
        resp = await client.get(f"{_base_url(device)}/rest/system/health")
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, list) else []
    except Exception:
        pass
    return []


def _parse_health(rows: list) -> list:
    sensors = []
    for row in rows:
        name = row.get("name") or ""
        value = row.get("value")
        if not name or value in (None, ""):
            continue
        unit = row.get("type") or ""  # "C", "V", "W", "RPM", "" (stany tekstowe)
        level = ""
        if unit == "C":
            try:
                temp = float(value)
                level = "bad" if temp >= _TEMP_BAD else ("warn" if temp >= _TEMP_WARN else "ok")
            except ValueError:
                pass
        rank = next((i for i, k in enumerate(_HEALTH_ORDER) if k in name), len(_HEALTH_ORDER))
        sensors.append({
            "name": name,
            "label": _HEALTH_LABELS.get(name, name),
            "value": value,
            "unit": unit,
            "level": level,
            "_rank": rank,
        })
    sensors.sort(key=lambda s: (s["_rank"], s["name"]))
    return sensors


async def get_device_health(device: Device, with_interfaces: bool = True) -> dict:
    """Kondycja: zasoby (CPU/RAM/dysk), opcjonalnie interfejsy, publiczny IP + NAT.
    Jeden klient, kilka wywołań — ładowane leniwie (HTMX), więc nie blokuje strony.
    Pod semaforem — czeka w kolejce, jeśli trwa akurat „zbadaj wszystkie".
    Odczyt jest idempotentny, a router bywa chwilowo zajęty — jedno ponowienie."""
    async with _device_sem(device):
        result = await _get_device_health_once(device, with_interfaces)
        if not result["ok"]:
            await asyncio.sleep(1.5)
            result = await _get_device_health_once(device, with_interfaces)
        return result


async def _get_device_health_once(device: Device, with_interfaces: bool = True) -> dict:
    try:
        async with httpx.AsyncClient(verify=False, timeout=15.0, auth=_auth(device)) as client:
            res = (await client.get(f"{_base_url(device)}/rest/system/resource")).json()

            # Prędkość linku ethernetów: monitor wszystkich portów jednym wywołaniem
            # (nazwy bywają różne: WAN, ether2, sfp-sfpplus1 — stąd najpierw lista).
            eth_rate: dict = {}
            interfaces: list = []
            if with_interfaces:
                # Od kiedy interfejsy sa osobna sekcja, kondycja nie musi ich pobierac —
                # a to trzy zapytania mniej na urzadzenie, w tym kosztowny monitor portow.
                try:
                    eths = (await client.get(f"{_base_url(device)}/rest/interface/ethernet")).json()
                    names = [e.get("name") for e in eths if e.get("name")]
                    if names:
                        mon = (await client.post(
                            f"{_base_url(device)}/rest/interface/ethernet/monitor",
                            json={"numbers": ",".join(names), "once": "true"},
                        )).json()
                        for m in mon:
                            eth_rate[m.get("name")] = m.get("rate")  # np. "1Gbps", "10Gbps", None gdy no-link
                except Exception:
                    pass


                try:
                    for i in (await client.get(f"{_base_url(device)}/rest/interface")).json():
                        name = i.get("name")
                        interfaces.append({
                            "name": name,
                            # Komentarz z RouterOS opisuje, CO wisi na porcie („KAM 07").
                            # Pole przychodzi tylko gdy niepuste — jak przy /ip/address.
                            "comment": i.get("comment"),
                            "type": i.get("type"),
                            "running": i.get("running") == "true",
                            "disabled": i.get("disabled") == "true",
                            "mtu": i.get("actual-mtu") or i.get("mtu"),
                            "rate": eth_rate.get(name),
                            "rx_byte": _to_int(i.get("rx-byte")),
                            "tx_byte": _to_int(i.get("tx-byte")),
                        })
                except Exception:
                    pass

            sensors = _parse_health(await _fetch_health(client, device))

            public_address, behind_nat, cloud_enabled = None, None, False
            try:
                cloud = (await client.get(f"{_base_url(device)}/rest/ip/cloud")).json()
                pub = cloud.get("public-address", "")
                if pub and pub != "0.0.0.0":
                    cloud_enabled = True
                    public_address = pub
                    addrs = (await client.get(f"{_base_url(device)}/rest/ip/address")).json()
                    local = [a.get("address", "").split("/")[0] for a in addrs if a.get("interface") != "wg-mt"]
                    behind_nat = pub not in local
            except Exception:
                pass

            return {
                "ok": True,
                "cpu_load": _to_int(res.get("cpu-load")),
                "cpu_count": res.get("cpu-count"),
                "free_memory": _to_int(res.get("free-memory")),
                "total_memory": _to_int(res.get("total-memory")),
                "free_hdd": _to_int(res.get("free-hdd-space")),
                "total_hdd": _to_int(res.get("total-hdd-space")),
                "board_name": res.get("board-name"),
                "version": res.get("version"),
                "uptime": res.get("uptime"),
                "interfaces": interfaces,
                "sensors": sensors,
                "public_address": public_address,
                "behind_nat": behind_nat,
                "cloud_enabled": cloud_enabled,
            }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


REPORT_LEVELS = ("warning", "error", "critical")


async def fetch_log(device: Device, levels: tuple = REPORT_LEVELS) -> dict:
    """Jednorazowy odczyt bufora logów routera — NIE wymaga włączonego syslogu.
    Uzupełnia push: syslog łapie zdarzenia od chwili podłączenia, a to sięga wstecz
    w to, co router już ma (zmierzone: bufor 1000 wpisów = 3–5 dni).

    Dwie rzeczy potwierdzone empirycznie i dlatego zrobione tak, a nie inaczej:
    1. Filtr `?topics=error` po stronie routera NIE DZIAŁA (zwraca 0 mimo istniejących
       wpisów) — odsiewamy u siebie.
    2. `.proplist` DZIAŁA, więc nie ciągniemy zbędnych pól przez tunel.
    Dekodowanie tolerancyjne: w logu bywają bajty spoza UTF-8 (0xea = 'ę' w cp1250)."""
    async with _device_sem(device):
        try:
            async with httpx.AsyncClient(verify=False, timeout=45.0, auth=_auth(device)) as client:
                resp = await client.get(
                    f"{_base_url(device)}/rest/log?.proplist=time,topics,message"
                )
                resp.raise_for_status()
                rows = _json(resp)
                entries, total = [], len(rows)
                for row in rows:
                    topics = row.get("topics") or ""
                    tokens = {t.strip() for t in topics.split(",")}
                    hit = next((lv for lv in levels if lv in tokens), None)
                    if hit:
                        entries.append({
                            "time": row.get("time") or "",
                            "level": hit,
                            "topics": topics,
                            "message": row.get("message") or "",
                        })
                return {"ok": True, "entries": entries, "total_in_buffer": total}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# Nazwa akcji logowania na routerze. BEZ MYŚLNIKA — RouterOS odrzuca `mtm-syslog`
# komunikatem „action name can contain only letters and numbers" (empiria 2026-08-03),
# mimo że mtm-api / mtm-cert / mtm-hub są w innych menu akceptowane.
SYSLOG_ACTION = "mtmsyslog"
SYSLOG_BASE_TOPICS = ("warning", "error", "critical")
SYSLOG_INFO_TOPIC = "info"


def _json(resp) -> list | dict:
    """RouterOS potrafi wstawić bajty spoza UTF-8 (0xea = 'ę' w cp1250 — złapane na
    MIECIU), przez co resp.json() wywala się na całym odczycie."""
    import json as _j

    return _j.loads(resp.content.decode("utf-8", errors="replace"))


async def _syslog_purge(client: httpx.AsyncClient, device: Device) -> int:
    """Usuwa nasze reguły (odwołują się do akcji), potem samą akcję. Kolejność istotna."""
    base, removed = _base_url(device), 0
    for rule in _json(await client.get(f"{base}/rest/system/logging")):
        if rule.get("action") == SYSLOG_ACTION:
            await client.delete(f"{base}/rest/system/logging/{rule['.id']}")
            removed += 1
    for act in _json(await client.get(f"{base}/rest/system/logging/action")):
        if act.get("name") == SYSLOG_ACTION:
            await client.delete(f"{base}/rest/system/logging/action/{act['.id']}")
            removed += 1
    return removed


async def configure_syslog(
    device: Device, *, hub_ip: str, port: int, include_info: bool = False
) -> dict:
    """Ustawia wysyłkę logów z routera na hub. Idempotentne: najpierw kasuje własne
    wpisy, potem tworzy je od nowa — dzięki temu zmiana portu czy flagi `info` nie
    zostawia duplikatów. `src-address` przypina adres źródłowy do adresu urządzenia
    w tunelu, bo po nim rozpoznajemy nadawcę po stronie portalu."""
    async with _device_sem(device):
        try:
            async with httpx.AsyncClient(verify=False, timeout=20.0, auth=_auth(device)) as client:
                base = _base_url(device)
                await _syslog_purge(client, device)

                resp = await client.put(f"{base}/rest/system/logging/action", json={
                    "name": SYSLOG_ACTION,
                    "target": "remote",
                    "remote": hub_ip,
                    "remote-port": str(port),
                    "src-address": str(device.wg_ip),
                })
                if resp.status_code >= 400:
                    return {"ok": False, "error": f"akcja logowania: {resp.text[:200]}"}

                topics = list(SYSLOG_BASE_TOPICS) + ([SYSLOG_INFO_TOPIC] if include_info else [])
                for topic in topics:
                    r = await client.put(f"{base}/rest/system/logging",
                                         json={"topics": topic, "action": SYSLOG_ACTION})
                    if r.status_code >= 400:
                        return {"ok": False, "error": f"reguła {topic}: {r.text[:200]}"}

                state = await _syslog_read(client, device)
                return {"ok": True, "topics": topics, **state}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def disable_syslog(device: Device) -> dict:
    """Zdejmuje z routera dokładnie to, co dodaliśmy — nic więcej."""
    async with _device_sem(device):
        try:
            async with httpx.AsyncClient(verify=False, timeout=20.0, auth=_auth(device)) as client:
                removed = await _syslog_purge(client, device)
                state = await _syslog_read(client, device)
                return {"ok": True, "removed": removed, **state}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def _syslog_read(client: httpx.AsyncClient, device: Device) -> dict:
    base = _base_url(device)
    acts = [a for a in _json(await client.get(f"{base}/rest/system/logging/action"))
            if a.get("name") == SYSLOG_ACTION]
    rules = [r for r in _json(await client.get(f"{base}/rest/system/logging"))
             if r.get("action") == SYSLOG_ACTION]
    return {
        "action_present": bool(acts),
        "rule_topics": sorted(r.get("topics", "") for r in rules),
        "remote": acts[0].get("remote") if acts else None,
        "remote_port": acts[0].get("remote-port") if acts else None,
    }


async def get_syslog_state(device: Device) -> dict:
    """Stan NA ROUTERZE (nie w bazie) — pozwala wykryć rozjazd, np. gdy ktoś zdjął
    konfigurację ręcznie albo router wrócił z kopii sprzed włączenia syslogu."""
    async with _device_sem(device):
        try:
            async with httpx.AsyncClient(verify=False, timeout=15.0, auth=_auth(device)) as client:
                return {"ok": True, **await _syslog_read(client, device)}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def get_dhcp_leases(device: Device) -> dict:
    """Dzierżawy DHCP. Statyczne (dynamic=false) ze status=waiting to często hosty z
    ręcznie wpisanym IP na karcie (nie leasują) — dlatego przydaje się ping.
    Pod semaforem — nie rywalizuje z pingami przy „zbadaj wszystkie".
    Odczyt jest idempotentny, a router bywa chwilowo zajęty — jedno ponowienie."""
    async with _device_sem(device):
        result = await _get_dhcp_leases_once(device)
        if not result["ok"]:
            await asyncio.sleep(1.5)
            result = await _get_dhcp_leases_once(device)
        return result


async def _get_dhcp_leases_once(device: Device) -> dict:
    try:
        async with httpx.AsyncClient(verify=False, timeout=15.0, auth=_auth(device)) as client:
            data = (await client.get(f"{_base_url(device)}/rest/ip/dhcp-server/lease")).json()
            leases = []
            for l in data:
                leases.append({
                    "address": l.get("address"),
                    "mac": l.get("mac-address"),
                    "host_name": l.get("host-name"),
                    "status": l.get("status"),
                    "dynamic": l.get("dynamic") == "true",
                    "comment": l.get("comment"),
                    "last_seen": l.get("last-seen"),
                })
            leases.sort(key=lambda x: [int(o) for o in (x["address"] or "0.0.0.0").split(".") if o.isdigit()] or [0])
            return {"ok": True, "leases": leases}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def ping_from_device(device: Device, address: str, count: int = 3) -> dict:
    """Ping z tego MikroTika (przez REST /ping) na wskazany adres. Synchronicznie
    zwraca listę wpisów; bierzemy ostatni (agregat sent/received/packet-loss/avg-rtt).
    Pod semaforem — przy „zbadaj wszystkie" pingi lecą w kolejce, nie zalewają routera."""
    async with _device_sem(device):
        try:
            async with httpx.AsyncClient(verify=False, timeout=20.0, auth=_auth(device)) as client:
                resp = await client.post(
                    f"{_base_url(device)}/rest/ping", json={"address": address, "count": str(count)}
                )
                resp.raise_for_status()
                data = resp.json()
                last = data[-1] if isinstance(data, list) and data else {}
                received = int(last.get("received", 0) or 0)
                return {
                    "ok": True,
                    "reachable": received > 0,
                    "sent": int(last.get("sent", count) or count),
                    "received": received,
                    "packet_loss": int(last.get("packet-loss", 100) or 100),
                    "avg_rtt": last.get("avg-rtt"),
                    "status": last.get("status"),  # np. "host unreachable" gdy brak odpowiedzi
                }
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# Bledy, przy ktorych polecenie NA PEWNO nie dotarlo do routera: nie bylo polaczenia albo
# zadanie nie wyszlo z klienta. Kazdy inny blad transportu (odczyt, zerwanie, timeout
# odpowiedzi) zdarza sie juz PO wyslaniu — wtedy restart mogl ruszyc albo nie.
_NOT_SENT = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout, httpx.UnsupportedProtocol,
             httpx.ProxyError, httpx.LocalProtocolError)


async def reboot(device: Device) -> dict:
    """Trzy rozne wyniki, bo przy restarcie polaczenie i tak zaraz pada:
      * router odpowiedzial — kod HTTP rozstrzyga (401/403/400 = restartu nie bylo;
        wczesniej 403 dawalo ok=True, wytkniete w pierwszej recenzji),
      * polecenie NIE wyszlo (brak polaczenia, timeout zestawiania, haslo nie do
        odszyfrowania) — porazka; wczesniej kazdy wyjatek byl „spodziewanym zerwaniem"
        i portal meldowal restart routera, z ktorym nawet sie nie polaczyl (druga recenzja),
      * polecenie wyszlo, odpowiedz nie przyszla — ok z flaga `unconfirmed`: to typowy
        przebieg restartu, ale dowodem jest dopiero spadek uptime'u (aktualizacje to
        sprawdzaja, przy recznym restarcie mowimy to uzytkownikowi)."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, auth=_auth(device)) as client:
            resp = await client.post(f"{_base_url(device)}/rest/system/reboot")
    except _NOT_SENT as e:
        return {"ok": False, "error": f"brak połączenia z routerem, polecenie nie zostało wysłane ({type(e).__name__}: {e})"}
    except httpx.TransportError as e:
        return {"ok": True, "unconfirmed": True,
                "note": f"polecenie wysłane, router nie odpowiedział ({type(e).__name__}) — typowe przy restarcie, "
                        "ale niepotwierdzone"}
    except Exception as e:
        return {"ok": False, "error": f"polecenie nie zostało wysłane ({type(e).__name__}: {e})"}
    if resp.status_code >= 400:
        return {"ok": False, "error": f"router odrzucił restart: HTTP {resp.status_code} {resp.text[:120]}"}
    return {"ok": True}


# Typy interfejsow, ktore NIGDY nie sa produkcyjnym LAN-em ani adresem zarzadzania.
# Filtrujemy po TYPIE, nie po nazwie: nazwy sa dowolne (WG_HOLANDIA, back-to-home-vpn,
# tun0), typ jest wlasnoscia RouterOS-a i nie zalezy od konwencji uzytkownika.
# UWAGA: WireGuard RouterOS raportuje jako "wg", NIE "wireguard" — sprawdzone na sprzecie.
TUNNEL_IFACE_TYPES = {
    "wg", "wireguard", "ovpn-out", "ovpn-in", "l2tp-out", "l2tp-in", "pptp-out", "pptp-in",
    "sstp-out", "sstp-in", "pppoe-out", "pppoe-in", "gre-tunnel", "ipip-tunnel",
    "eoip-tunnel", "zerotier", "6to4-tunnel",
}


async def get_ip_addresses(device: Device) -> dict:
    """Pelna lista adresow IP urzadzenia, wzbogacona o typ interfejsu i flagi.

    Portal niczego tu nie wybiera ani nie ukrywa — pokazuje wszystko, co urzadzenie
    zwraca, a wskazanie adresu glownego nalezy do czlowieka. Adnotacje sluza wylacznie
    czytelnosci tabeli: przy kilkunastu wierszach (tunele, VLAN-y, PPPoE) samo
    `address/interface` jest nieskanowalne wzrokiem.

    RouterOS zwraca wszystkie pola jako lancuchy "true"/"false" — stad porownania.
    """
    if not device.api_username or not device.api_password_encrypted:
        return {"ok": False, "error": "Brak danych API", "rows": []}

    from app.wg_config import wg

    try:
        hub_net = ipaddress.ip_network(wg.subnet, strict=False) if wg.subnet else None
    except ValueError:
        hub_net = None

    try:
        async with _device_sem(device):
            async with httpx.AsyncClient(verify=False, timeout=20.0, auth=_auth(device)) as client:
                raw = _json(await client.get(f"{_base_url(device)}/rest/ip/address"))
                types: dict[str, str] = {}
                try:
                    for i in _json(await client.get(f"{_base_url(device)}/rest/interface")):
                        if i.get("name"):
                            types[i["name"]] = i.get("type") or ""
                except Exception:
                    pass
                # Adres publiczny bierzemy z /ip/cloud, nie z listy adresow: router za
                # NAT-em operatora nie ma go na zadnym interfejsie, a i tak chcemy wiedziec,
                # pod czym widac go ze swiata.
                cloud_public = None
                try:
                    pub = (_json(await client.get(f"{_base_url(device)}/rest/ip/cloud"))
                           or {}).get("public-address", "")
                    if pub and pub != "0.0.0.0":
                        cloud_public = pub
                except Exception:
                    pass
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "rows": [], "public_address": None}

    rows = []
    for a in raw if isinstance(raw, list) else []:
        addr = a.get("address") or ""
        iface = a.get("interface") or ""
        itype = types.get(iface, "")
        bare = addr.split("/")[0]
        is_hub = False
        is_public = False
        try:
            ip = ipaddress.ip_address(bare)
            is_hub = bool(hub_net and ip in hub_net)
            is_public = not ip.is_private and not ip.is_loopback and not ip.is_link_local
        except ValueError:
            pass
        rows.append({
            "address": addr,
            "network": a.get("network"),
            "interface": iface,
            "actual_interface": a.get("actual-interface"),
            "type": itype,
            "dynamic": a.get("dynamic") == "true",
            "disabled": a.get("disabled") == "true",
            "invalid": a.get("invalid") == "true",
            "slave": a.get("slave") == "true",
            "vrf": a.get("vrf"),
            "comment": a.get("comment"),
            "is_hub_tunnel": is_hub,
            "is_public": is_public,
            "is_tunnel_iface": itype in TUNNEL_IFACE_TYPES,
        })
    rows.sort(key=lambda r: (r["is_hub_tunnel"], r["is_tunnel_iface"], r["interface"], r["address"]))
    if not cloud_public:
        cloud_public = next((r["address"].split("/")[0] for r in rows if r["is_public"]), None)
    return {"ok": True, "rows": rows, "error": None, "public_address": cloud_public}


# ---- PoE per port ----
#
# Empiria ze sprzetu (2026-09-25):
#  * `/interface/ethernet/poe` daje KONFIGURACJE (poe-out, poe-priority, poe-voltage,
#    power-cycle-*), a `/interface/ethernet/poe/monitor` ODCZYT NA ZYWO.
#  * Model bez PoE odpowiada **HTTP 400**, nie pusta lista — tak samo jak /system/health
#    na modelach bez czujnikow.
#  * Pomiar NIE jest uniwersalny: 24-portowy switch zwraca napiecie, prad i moc, ale
#    router z pojedynczym portem PoE-out oddaje z monitora sam `poe-out-status`.
#    Dlatego brak pomiaru to None, nigdy zero — zero znaczyloby „zmierzono 0 W".
#  * `poe-out-current` jest w miliamperach (61 mA * 52,1 V ~ 3,1 W = `poe-out-power`).

POE_OUT_VALUES = ("auto-on", "forced-on", "off")


async def get_poe(device: Device) -> dict:
    if not device.api_username or not device.api_password_encrypted:
        return {"ok": False, "supported": None, "error": "Brak danych API", "rows": []}
    try:
        async with _device_sem(device):
            async with httpx.AsyncClient(verify=False, timeout=20.0, auth=_auth(device)) as client:
                resp = await client.get(f"{_base_url(device)}/rest/interface/ethernet/poe")
                if resp.status_code == 400:
                    return {"ok": True, "supported": False, "rows": [], "error": None}
                cfg = _json(resp)
                if not isinstance(cfg, list) or not cfg:
                    return {"ok": True, "supported": False, "rows": [], "error": None}

                names = [c.get("name") for c in cfg if c.get("name")]
                # Komentarz interfejsu obok portu PoE to nie ozdoba: mowi, ktora kamere
                # restartujesz. Jedno zapytanie wiecej, ale tylko przy otwarciu sekcji.
                comments = {}
                try:
                    for i in _json(await client.get(f"{_base_url(device)}/rest/interface")):
                        if i.get("name") and i.get("comment"):
                            comments[i["name"]] = i["comment"]
                except Exception:
                    pass
                mon = {}
                try:
                    data = _json(await client.post(
                        f"{_base_url(device)}/rest/interface/ethernet/poe/monitor",
                        json={"numbers": ",".join(names), "once": "true"},
                    ))
                    mon = {m.get("name"): m for m in data if m.get("name")}
                except Exception:
                    pass
    except Exception as e:
        return {"ok": False, "supported": None, "error": f"{type(e).__name__}: {e}", "rows": []}

    rows = []
    for c in cfg:
        name = c.get("name")
        m = mon.get(name, {})
        rows.append({
            "id": c.get(".id"),
            "name": name,
            "comment": comments.get(name),
            "poe_out": c.get("poe-out"),
            "priority": c.get("poe-priority"),
            "voltage_mode": c.get("poe-voltage"),
            "cycle_interval": c.get("power-cycle-interval"),
            "status": m.get("poe-out-status"),
            "voltage": _to_float(m.get("poe-out-voltage")),
            "current_ma": _to_float(m.get("poe-out-current")),
            "power_w": _to_float(m.get("poe-out-power")),
            "power_pair": m.get("poe-out-power-pair"),
        })
    powered = [r for r in rows if r["status"] == "powered-on"]
    total = sum(r["power_w"] for r in rows if r["power_w"] is not None)
    return {
        "ok": True, "supported": True, "rows": rows, "error": None,
        "powered": len(powered),
        "total_power": round(total, 1) if total else None,
    }


async def set_poe_out(device: Device, port_id: str, value: str) -> dict:
    if value not in POE_OUT_VALUES:
        return {"ok": False, "error": f"Niedozwolona wartość: {value}"}
    try:
        async with _device_sem(device):
            async with httpx.AsyncClient(verify=False, timeout=20.0, auth=_auth(device)) as client:
                resp = await client.patch(
                    f"{_base_url(device)}/rest/interface/ethernet/poe/{port_id}",
                    json={"poe-out": value},
                )
                if resp.status_code >= 400:
                    return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
                return {"ok": True, "error": None}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def poe_power_cycle(device: Device, port_name: str, duration: str = "5s") -> dict:
    """Zdalny restart zasilanego urzadzenia. Odciecie PoE NIE zrywa lacza danych —
    sprawdzone: router pozostal osiagalny przez caly czas testu."""
    try:
        async with _device_sem(device):
            async with httpx.AsyncClient(verify=False, timeout=30.0, auth=_auth(device)) as client:
                resp = await client.post(
                    f"{_base_url(device)}/rest/interface/ethernet/poe/power-cycle",
                    json={"numbers": port_name, "duration": duration},
                )
                if resp.status_code >= 400:
                    return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
                return {"ok": True, "error": None}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ---- Modem LTE/5G (szczegoly formatu i ustalenia ze sprzetu: app/lte.py) ----

async def lte_present(device: Device) -> bool | None:
    """Czy urzadzenie ma modem. Bez modemu `/interface/lte` zwraca pusta liste.
    None = nie udalo sie sprawdzic (nie zgadujemy)."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT, auth=_auth(device)) as client:
            resp = await client.get(f"{_base_url(device)}/rest/interface/lte")
        if resp.status_code != 200:
            return None
        return len(resp.json()) > 0
    except Exception:
        return None


async def get_lte(device: Device) -> dict:
    """Modemy i jednorazowy odczyt monitora kazdego z nich. Identyfikatory (IMEI, IMSI,
    ICCID) odrzuca app.lte.parse_monitor — dalej nie ida."""
    from app import lte
    try:
        async with httpx.AsyncClient(verify=False, timeout=20.0, auth=_auth(device)) as client:
            resp = await client.get(f"{_base_url(device)}/rest/interface/lte")
            resp.raise_for_status()
            modems = []
            for m in resp.json():
                name = m.get("name")
                row = {"name": name, "running": m.get("running") == "true",
                       "disabled": m.get("disabled") == "true",
                       "network_mode": m.get("network-mode"), "allow_roaming": m.get("allow-roaming"),
                       "monitor": None, "error": None}
                if not row["disabled"]:
                    mon = await client.post(f"{_base_url(device)}/rest/interface/lte/monitor",
                                            json={"numbers": name, "once": ""})
                    if mon.status_code >= 400:
                        row["error"] = f"HTTP {mon.status_code}: {mon.text[:120]}"
                    else:
                        row["monitor"] = lte.parse_monitor(mon.json())
                modems.append(row)
        return {"ok": True, "modems": modems}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "modems": []}


async def lte_firmware_check(device: Device, name: str) -> dict:
    """`/interface/lte/firmware-upgrade` BEZ upgrade=yes — tylko sprawdza wersje (modem pyta
    serwery producenta, wiec to trwa kilka sekund).

    Parametry ustalone przez `/console/inspect` na RouterOS 7 (nie zgadywane): wskazanie
    modemu to `number` (LICZBA POJEDYNCZA — w `monitor` jest `numbers`; pierwsza wersja wyslala
    `numbers` i dostala „unknown parameter numbers"). Polecenie dziala jak monitor: z `once`
    zwraca PIERWSZA klatke, w ktorej `latest` jeszcze nie ma, a status to „checking..."
    (druga wersja tak wlasnie utknela na produkcji). Dlatego `duration`: REST zwraca wszystkie
    klatki z tego czasu, a my bierzemy ostatnia z rozstrzygnietym wynikiem."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=90.0, auth=_auth(device)) as client:
            resp = await client.post(f"{_base_url(device)}/rest/interface/lte/firmware-upgrade",
                                     json={"number": name, "duration": _LTE_FW_CHECK_SECONDS})
        if resp.status_code >= 400:
            return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:160]}"}
        return {"ok": True, **lte_firmware_result(resp.json())}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


_LTE_FW_CHECK_SECONDS = "15s"


def lte_firmware_result(data) -> dict:
    """Klatki odpowiedzi -> wynik. Ostatnia klatka, w ktorej sprawdzanie sie zakonczylo
    (jest `latest` albo status inny niz „checking"); gdy takiej nie ma — informacja, ze
    sprawdzanie jeszcze trwa."""
    frames = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    frames = [f for f in frames if isinstance(f, dict)]
    done = [f for f in frames if f.get("latest") or not str(f.get("status", "")).lower().startswith("checking")]
    row = (done or frames or [{}])[-1]
    return {"installed": row.get("installed"), "latest": row.get("latest"), "status": row.get("status"),
            "pending": not done and bool(frames)}
