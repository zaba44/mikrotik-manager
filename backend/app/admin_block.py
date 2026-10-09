"""Blok administracyjny: koncowy fragment podsieci tunelu zarezerwowany dla peerow admina
i urzadzen administracyjnych (np. router w biurze). Na routerach klientow jeden wpis
listy `mtm-admin` (caly blok) wpuszcza Winbox ze wszystkich adresow administracyjnych —
nowy peer admina nie wymaga juz zmian na routerach.

Dlatego ZWYKLE urzadzenie nigdy nie moze dostac adresu z bloku (mialoby Winbox do calej
floty), a zmiana wielkosci bloku nie moze nikogo „przerzucic" na druga strone granicy."""
import ipaddress

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AdminPeer, Device
from app.settings_store import get_setting, set_setting
from app.wg_config import wg

SETTING_KEY = "wg_admin_prefix"
DEFAULT_PREFIX = 27
MAX_PREFIX = 30


def default_prefix(subnet: str) -> int:
    """/27 (31 adresow); w malej podsieci (/26 i mniejszej) — cwierc podsieci."""
    net = ipaddress.ip_network(subnet, strict=False)
    if net.prefixlen <= DEFAULT_PREFIX - 2:
        return DEFAULT_PREFIX
    return min(net.prefixlen + 2, MAX_PREFIX)


def block_for(subnet: str, prefix: int) -> ipaddress.IPv4Network:
    """Koncowy blok /prefix podsieci (z jej adresem rozgloszeniowym)."""
    net = ipaddress.ip_network(subnet, strict=False)
    size = 2 ** (32 - prefix)
    return ipaddress.ip_network(f"{ipaddress.ip_address(int(net.broadcast_address) + 1 - size)}/{prefix}")


def usable(subnet: str, prefix: int) -> int:
    """Adresy do rozdania w bloku: bez rozgloszeniowego podsieci (i huba, gdyby tam byl)."""
    block = block_for(subnet, prefix)
    hub = 1 if wg.server_ip and ipaddress.ip_address(wg.server_ip) in block else 0
    return block.num_addresses - 1 - hub


def choices(subnet: str) -> list[int]:
    """Dopuszczalne wielkosci: od /30 do polowy podsieci."""
    net = ipaddress.ip_network(subnet, strict=False)
    return list(range(MAX_PREFIX, net.prefixlen, -1))


async def get_prefix(session: AsyncSession) -> int:
    value = await get_setting(session, SETTING_KEY)
    if value.isdigit() and int(value) in choices(wg.subnet):
        return int(value)
    return default_prefix(wg.subnet)


async def get_block(session: AsyncSession) -> ipaddress.IPv4Network:
    return block_for(wg.subnet, await get_prefix(session))


async def members(session: AsyncSession, block: ipaddress.IPv4Network) -> tuple[list[AdminPeer], list[Device]]:
    """Peery admina i urzadzenia z adresem w bloku (te drugie = urzadzenia administracyjne)."""
    peers = (await session.execute(select(AdminPeer).order_by(AdminPeer.wg_ip))).scalars().all()
    devices = (await session.execute(select(Device).order_by(Device.wg_ip))).scalars().all()
    return ([p for p in peers if ipaddress.ip_address(p.wg_ip) in block],
            [d for d in devices if ipaddress.ip_address(d.wg_ip) in block])


async def change_problem(session: AsyncSession, new_prefix: int) -> str | None:
    """Powod odmowy zmiany wielkosci bloku albo None. Zmniejszenie: nikt administracyjny nie
    moze wypasc poza blok (stracilby Winbox). Zwiekszenie: nowy obszar musi byc pusty —
    zwykle urzadzenie w bloku dostaloby Winbox do calej floty."""
    if new_prefix not in choices(wg.subnet):
        return "Niedozwolona wielkość bloku."
    old, new = await get_block(session), block_for(wg.subnet, new_prefix)
    if wg.server_ip and ipaddress.ip_address(wg.server_ip) in new:
        return f"Blok {new} obejmowałby adres huba ({wg.server_ip})."
    peers, devices = await members(session, old)
    out = [p.name for p in peers if ipaddress.ip_address(p.wg_ip) not in new]
    out += [d.name for d in devices if ipaddress.ip_address(d.wg_ip) not in new]
    if out:
        return (f"Blok {new} jest za mały — poza nim zostałyby: {', '.join(out)}. "
                "Usuń je albo wybierz większy blok.")
    admin_ids = {d.id for d in devices}
    inside = [d.name for d in (await session.execute(select(Device))).scalars()
              if d.id not in admin_ids and ipaddress.ip_address(d.wg_ip) in new]
    if inside:
        return (f"W obszarze bloku {new} są już zwykłe urządzenia: {', '.join(inside)}. "
                "Dostałyby Winbox do wszystkich routerów — wybierz mniejszy blok.")
    return None


async def set_prefix(session: AsyncSession, prefix: int) -> None:
    await set_setting(session, SETTING_KEY, str(prefix))


def winbox_script(block: str, lst: str = "mtm-admin", comment: str = "MTM: Winbox dla adminow") -> str:
    """Uniwersalny skrypt dla KAZDEGO routera floty (RouterOS 7.15–7.24, sprawdzone na zywo).

    - port Winboxa czyta sam; od 7.23 `/ip service` ma tez dynamiczne wpisy aktywnych polaczen
      (connection=true), stad wybor w petli; `available-from` (7.24+) albo `address`;
    - do listy dodaje caly blok; wpis bloku o innym adresie (po zmianie wielkosci) i dawne
      wpisy pojedynczych peerow („MTM admin: ...") usuwa;
    - regule wstawia przed pierwsza regula input/accept z portem Winboxa (takze wylaczona,
      takze lista portow), a bez niej — na gore listy, pod ewentualna dynamiczna regula
      fasttracka. `find ... disabled=no` na 7.23 zwraca 0 regul, wiec warunki w petli przez get;
    - istniejacej reguly nie przesuwa, poprawia tylko port. Mozna uruchamiac wielokrotnie."""
    rule = (f"/ip firewall filter add chain=input protocol=tcp dst-port=$port src-address-list={lst} "
            f'in-interface=wg-mt action=accept comment="{comment}"')
    range_comment = "MTM: peery administracyjne (zakres)"
    return "\n".join([
        "{",
        f':local adm "{block}"',
        ':local svc ""; :foreach i in=[/ip service find name=winbox] do={:if (([:len $svc] = 0) && '
        '(([/ip service get $i]->"connection") != true)) do={:set svc $i}}',
        ":local it [/ip service get $svc]",
        ':local port ($it->"port")',
        ':local sa ($it->"available-from"); :if ([:len $sa] = 0) do={:set sa ($it->"address")}',
        f':foreach i in=[/ip firewall address-list find list={lst} comment="{range_comment}"] do={{'
        f':if ([/ip firewall address-list get $i address] != $adm) do={{/ip firewall address-list remove $i}}}}',
        f'/ip firewall address-list remove [find list={lst} comment~"^MTM admin: "]',
        f':if ([:len [/ip firewall address-list find list={lst} address=$adm]] = 0) do={{'
        f'/ip firewall address-list add list={lst} address=$adm comment="{range_comment}"}}',
        ':local anchor ""',
        ':foreach i in=[/ip firewall filter find chain=input action=accept] do={:if ([:len $anchor] = 0) do={'
        ':local dp ([/ip firewall filter get $i]->"dst-port"); '
        ':if (([:len $dp] > 0) && (("," . $dp . ",") ~ ("," . $port . ","))) do={:set anchor $i}}}',
        ':if ([:len $anchor] = 0) do={:foreach i in=[/ip firewall filter find] do={:if (([:len $anchor] = 0) && '
        '(([/ip firewall filter get $i]->"dynamic") != true)) do={:set anchor $i}}}',
        f':local r [/ip firewall filter find comment="{comment}"]',
        ":if ([:len $r] > 0) do={/ip firewall filter set $r dst-port=$port} else={"
        f":if ([:len $anchor] > 0) do={{{rule} place-before=$anchor}} else={{{rule}}}}}",
        ':if ($it->"disabled") do={:put "UWAGA: usluga winbox jest WYLACZONA (/ip service enable winbox)"}',
        ':if ([:len $sa] > 0) do={:put ("UWAGA: winbox przyjmuje tylko z: " . [:tostr $sa] . " - dopisz tam " . $adm)}',
        ':put ("MTM: Winbox dla adminow - port " . $port . ", dostep z " . $adm . " przez wg-mt")',
        "}",
    ]) + "\n"
