import base64
import ipaddress
import secrets
import string

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin_block import get_block
from app.config import settings
from app.models import AdminPeer, Device
from app.wg_config import wg

_fernet = Fernet(settings.fernet_key.encode())


def encrypt(value: str) -> str:
    return _fernet.encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()


def encrypt_bytes(value: bytes) -> bytes:
    return _fernet.encrypt(value)


def decrypt_bytes(token: bytes) -> bytes:
    return _fernet.decrypt(token)


def generate_wg_keypair() -> tuple[str, str]:
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(private_bytes).decode(), base64.b64encode(public_bytes).decode()


def generate_api_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_preshared_key() -> str:
    """PSK WireGuard = 32 losowe bajty base64 (jak `wg genpsk`). Dodatkowa warstwa:
    odporność post-quantum + drugi sekret na tunel (wyciek klucza prywatnego nie
    wystarcza do zestawienia sesji)."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


class AdminBlockFull(RuntimeError):
    pass


# Klucz blokady doradczej PostgreSQL dla puli adresow tunelu (dowolna stala, byle wlasna).
_IP_POOL_LOCK = 0x6D746D5F69707031  # "mtm_ipp1"


async def _lock_ip_pool(session: AsyncSession) -> None:
    """Przydzial adresu to „sprawdz, co wolne" + INSERT w dwoch roznych tabelach (urzadzenia
    i peery admina), wiec UNIQUE na kazdej z osobna nie zatrzyma dwoch rownoleglych
    rejestracji bioracych ten sam ostatni wolny adres (wytkniete w drugiej recenzji).
    Blokada transakcyjna: trzymana do commitu/rollbacku sesji, czyli obejmuje przydzial
    I zapis — wolajacy musi zapisac rekord w tej samej transakcji, co robia oba miejsca.
    Brana PRZED odczytem zajetych adresow: w READ COMMITTED kolejne zapytania widza juz
    to, co zatwierdzil poprzedni posiadacz blokady."""
    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _IP_POOL_LOCK})


async def _used_addresses(session: AsyncSession) -> set:
    # Wspolna ewidencja: urzadzenia ORAZ peery administracyjne (wytkniete w recenzji
    # zewnetrznej — kolizja wychodzila po cichu, dwa peery z tym samym adresem).
    used = {ipaddress.ip_address(wg.server_ip)}
    for row in (await session.execute(select(Device.wg_ip))).all():
        used.add(ipaddress.ip_address(row[0]))
    for row in (await session.execute(select(AdminPeer.wg_ip))).all():
        used.add(ipaddress.ip_address(row[0]))
    return used


async def allocate_ip(session: AsyncSession) -> str:
    """Adres zwyklego urzadzenia — od dolu puli, NIGDY z bloku administracyjnego: kazdy
    adres z bloku ma na routerach floty dostep do Winboxa."""
    await _lock_ip_pool(session)
    network = ipaddress.ip_network(wg.subnet)
    used = await _used_addresses(session)
    block = await get_block(session)

    for host in network.hosts():
        if host not in used and host not in block:
            return str(host)

    raise RuntimeError("Brak wolnych adresów IP w puli WG_SUBNET (poza blokiem administracyjnym)")


async def allocate_admin_ip(session: AsyncSession) -> str:
    """Adres administracyjny (peer admina albo urzadzenie administracyjne) — z bloku
    administracyjnego, od jego gory. Poza blok nie wychodzi: tam regula Winboxa na routerach
    by go nie wpuscila."""
    await _lock_ip_pool(session)
    network = ipaddress.ip_network(wg.subnet)
    used = await _used_addresses(session)
    block = await get_block(session)

    for ip_int in range(int(network.broadcast_address) - 1, int(block.network_address) - 1, -1):
        candidate = ipaddress.ip_address(ip_int)
        if candidate not in used:
            return str(candidate)

    raise AdminBlockFull(f"Blok administracyjny {block} jest pełny — powiększ go w Ustawieniach → Peery administracyjne.")
