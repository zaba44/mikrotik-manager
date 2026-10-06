"""Doprowadzenie sieci WG do stanu gotowego na podstawie konfiguracji z bazy:
- trasa do podsieci WG w netns backendu (dawniej w entrypoint.sh — ale świeża
  instalacja nie zna podsieci przy starcie kontenera, więc robimy to tu, po
  wczytaniu konfiguracji, także po zapisie z kreatora),
- interfejs wg-mt postawiony przez agenta (jeśli nie stoi),
- synchronizacja klucza publicznego huba do bazy (zdejmuje ręczny krok z .env).
"""
import logging
import socket
import subprocess

from app.database import async_session
from app.settings_store import set_setting
from app.wg_agent_client import get_interface_status, setup_interface
from app.wg_config import wg

logger = logging.getLogger("wg_bringup")


def _add_route() -> None:
    try:
        wg_ip = socket.gethostbyname("wireguard")
        subprocess.run(["ip", "route", "replace", wg.subnet, "via", wg_ip], check=False)
        logger.info("Trasa %s via %s", wg.subnet, wg_ip)
    except Exception as e:
        logger.warning("Nie udało się dodać trasy do %s: %s", wg.subnet, e)


async def ensure_wg_up(private_key: str | None = None) -> str | None:
    """Wywoływane w lifespan oraz po zapisie konfiguracji w kreatorze. Zwraca klucz
    publiczny huba (albo None). private_key podawany tylko przy restore (odtworzenie
    tożsamości huba dla floty)."""
    if not wg.configured:
        return None

    _add_route()

    # Status czytany RAZ i tylko odpowiedz agenta decyduje o przebudowie. Brak odpowiedzi
    # (timeout, restart kontenera) to nie dowod, ze interfejsu nie ma — dawniej konczyl sie
    # setup_interface(), czyli zerwaniem dzialajacego tunelu calej floty (wytkniete w
    # czwartej recenzji; przy starcie backendu to samo grozilo przy kazdym wolnym agencie).
    status = await get_interface_status()
    if status is None:
        logger.warning("Agent WireGuard nie odpowiada — interfejsu wg-mt nie ruszam")
        return None
    pubkey = status.get("public_key")
    running = bool(status.get("up"))

    # Z kluczem (odtwarzanie kopii): przebudowa tylko, gdy hub nie dziala z TYM kluczem.
    # Ponowienie odtwarzania nie moze zrywac tunelu, ktory poprzednia proba juz postawila.
    from app.routerwg.importer import derive_public
    wrong_key = bool(private_key) and pubkey != derive_public(private_key)
    if not running or wrong_key:
        pubkey, err = await setup_interface(wg.subnet, wg.server_ip, private_key)
        if err:
            logger.error("setup wg-mt nieudany: %s", err)

    if pubkey and pubkey != wg.server_public_key:
        wg.server_public_key = pubkey
        async with async_session() as session:
            await set_setting(session, "wg_server_public_key", pubkey)
        logger.info("Zaktualizowano klucz publiczny huba w bazie")

    return pubkey
