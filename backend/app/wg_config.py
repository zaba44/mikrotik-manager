"""Konfiguracja sieci WireGuard portalu — źródłem prawdy jest baza (tabela settings),
nie .env. Dzięki temu kreator może ją ustawić przy pierwszym uruchomieniu, a panel
edytować później. Wartości trzymane w pamięci (cache), ładowane raz w lifespan;
call-site'y czytają synchronicznie `wg.subnet` itd.

Transformacja: przy pierwszym starcie po wdrożeniu, jeśli w bazie nie ma jeszcze
wartości, seedujemy je z .env (WG_SUBNET, ...) i utrwalamy — potem można je z .env
usunąć (poza tym, czego nadal potrzebuje infrastruktura: entrypoint route, kontener
wireguard — to domknie Faza 3).
"""
import os

from app.database import async_session
from app.settings_store import get_setting, set_setting

# klucz w settings -> (atrybut, zmienna env do seedowania)
_KEYS = {
    "wg_subnet": ("subnet", "WG_SUBNET"),
    "wg_server_ip": ("server_ip", "WG_SERVER_IP"),
    "wg_hub_endpoint": ("hub_endpoint", "HUB_ENDPOINT"),
    "wg_server_public_key": ("server_public_key", "WG_SERVER_PUBLIC_KEY"),
}


class WgConfig:
    subnet: str = ""
    server_ip: str = ""
    hub_endpoint: str = ""
    server_public_key: str = ""

    @property
    def mask(self) -> str:
        return self.subnet.split("/")[1] if "/" in self.subnet else ""

    @property
    def configured(self) -> bool:
        return bool(self.subnet and self.server_ip and self.hub_endpoint)


wg = WgConfig()


async def load_wg_config() -> None:
    async with async_session() as session:
        for db_key, (attr, env_key) in _KEYS.items():
            value = await get_setting(session, db_key)
            if not value:
                value = os.environ.get(env_key, "")
                if value:
                    await set_setting(session, db_key, value)  # seed do bazy jednorazowo
            setattr(wg, attr, value)


async def save_wg_config(session, *, subnet, server_ip, hub_endpoint, server_public_key=None) -> None:
    await set_setting(session, "wg_subnet", subnet)
    await set_setting(session, "wg_server_ip", server_ip)
    await set_setting(session, "wg_hub_endpoint", hub_endpoint)
    wg.subnet, wg.server_ip, wg.hub_endpoint = subnet, server_ip, hub_endpoint
    if server_public_key is not None:
        await set_setting(session, "wg_server_public_key", server_public_key)
        wg.server_public_key = server_public_key
