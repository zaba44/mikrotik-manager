"""Adres lokalny urzadzenia — sledzenie tego, co WSKAZAL uzytkownik.

Portal nie zgaduje, ktory adres jest „ten wlasciwy". Przy switchu w trybie bridge nie ma
serwera DHCP, przy kilku VLAN-ach kandydatow jest kilka, a nazwy interfejsow (LAN_BRIDGE,
bridge1, vlan_biuro) sa dowolne. Kazda heurystyka dziala na jednej flocie i klamie na innej,
wiec wyboru dokonuje czlowiek, a portal jedynie pilnuje, zeby wskazanie sie nie zdezaktualizowalo.

Zasady sledzenia wynikaja z tego, czym adres jest na urzadzeniu:

* **dynamiczny** — jego tozsamoscia jest INTERFEJS, bo wartosc ma sie zmieniac (klient DHCP,
  PPPoE). Pokazujemy to, co aktualnie na nim siedzi; gdy interfejs chwilowo nie ma adresu,
  mowimy „czekam na adres" zamiast zdejmowac przypiecie.
* **statyczny** — tozsamoscia jest para interfejs + adres. Gdy pary nie ma, ale interfejs
  zostal i ma dokladnie jeden statyczny adres, przyjmujemy go jako RENUMERACJE (i mowimy
  o tym wprost). Przy niejednoznacznosci odpinamy — z widoczna informacja.

Wszystko to dzieje sie WYLACZNIE po udanym odczycie. Przy niedostepnym routerze nie wiemy,
czy adres zniknal — wiemy tylko, ze go nie widzimy, a odpiecie przy zwykłej awarii lacza
byloby cicha utrata konfiguracji uzytkownika.
"""
import datetime

from sqlalchemy import select

from app.database import async_session
from app.models import Device
from app.routeros_client import get_ip_addresses


def _statics(rows: list[dict], iface: str) -> list[dict]:
    return [r for r in rows if r["interface"] == iface and not r["dynamic"]]


def apply_rows(device: Device, rows: list[dict]) -> None:
    """Uaktualnia przypiety adres na podstawie SWIEZO odczytanej listy. Modyfikuje obiekt
    w miejscu — zapis do bazy nalezy do wolajacego."""
    iface = device.local_addr_interface
    if not iface:
        device.local_addr_note = None
        return

    if device.local_addr_dynamic:
        # Brak adresu na interfejsie i usuniecie interfejsu wygladaja z /ip/address
        # identycznie, a przy adresie dynamicznym „chwilowo pusto" jest stanem normalnym
        # (odnowienie dzierzawy, zerwana sesja PPPoE) — dlatego czekamy, nie odpinamy.
        current = [r for r in rows if r["interface"] == iface]
        device.local_addr_value = current[0]["address"] if current else None
        device.local_addr_note = None if current else "czekam na adres"
        return

    exact = next(
        (r for r in rows if r["interface"] == iface and r["address"] == device.local_addr_value),
        None,
    )
    if exact:
        device.local_addr_note = None
        return

    candidates = _statics(rows, iface)
    if len(candidates) == 1:
        old = device.local_addr_value
        device.local_addr_value = candidates[0]["address"]
        device.local_addr_note = f"adres zmienił się z {old} na {candidates[0]['address']}"
        return

    gone = device.local_addr_value
    device.local_addr_interface = None
    device.local_addr_value = None
    device.local_addr_dynamic = False
    device.local_addr_note = f"adres {gone} zniknął z urządzenia — przypięcie usunięte"


def _snapshot(device: Device) -> dict:
    return {
        "interface": device.local_addr_interface,
        "value": device.local_addr_value,
        "dynamic": device.local_addr_dynamic,
        "note": device.local_addr_note,
        "public_address": device.public_address,
        "behind_nat": device.public_behind_nat,
    }


async def refresh(device: Device) -> dict:
    """Odczyt z urzadzenia + zapis wyniku. Otwiera WLASNA sesje, bo wolajacy zamyka swoja
    przed dlugim REST-em (dziesiatki rownoczesnych fragmentow wyczerpywaly pule polaczen).

    Stan przypiecia wraca w `result["pinned"]` jako zwykly slownik — obiekt Device po
    zamknieciu sesji jest odlaczony i siegniecie po jego pola rzucaloby wyjatkiem.
    """
    result = await get_ip_addresses(device)
    if not result.get("ok"):
        result["pinned"] = _snapshot(device)
        return result

    async with async_session() as s:
        fresh = await s.get(Device, device.id)
        if fresh is None:
            result["pinned"] = _snapshot(device)
            return result
        apply_rows(fresh, result["rows"])
        fresh.public_address = result.get("public_address")
        # „Za NAT-em" = adres widziany ze swiata nie siedzi na zadnym interfejsie routera.
        # Liczymy to tutaj, bo mamy juz pelna liste — w tabeli Status nie ma sie skad wziac.
        pub = result.get("public_address")
        own = [r["address"].split("/")[0] for r in result["rows"] if not r["is_hub_tunnel"]]
        fresh.public_behind_nat = (pub not in own) if pub else None
        fresh.addr_checked_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        await s.commit()
        result["pinned"] = _snapshot(fresh)
    return result


async def refresh_all() -> int:
    """Cykliczne odswiezenie przypietych adresow. Tylko urzadzenia, ktore cos maja
    przypiete — reszta nie ma czego odswiezac, a przy 300 routerach to roznica miedzy
    kilkoma zapytaniami a kilkoma setkami."""
    async with async_session() as s:
        devices = (await s.execute(
            select(Device).where(Device.local_addr_interface.isnot(None))
        )).scalars().all()
        s.expunge_all()
    done = 0
    for d in devices:
        try:
            if (await refresh(d)).get("ok"):
                done += 1
        except Exception as e:
            print(f"[addr] {d.name}: {type(e).__name__}: {e}", flush=True)
    return done
