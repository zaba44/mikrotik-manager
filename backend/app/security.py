import base64
import ipaddress
import secrets
import string

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

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


async def allocate_ip(session: AsyncSession) -> str:
    await _lock_ip_pool(session)
    network = ipaddress.ip_network(wg.subnet)
    server_ip = ipaddress.ip_address(wg.server_ip)

    # Wspolna ewidencja: urzadzenia ORAZ peery administracyjne. Te drugie ida od konca puli,
    # wiec kolizja wychodzila dopiero przy prawie pelnej podsieci — ale wtedy po cichu,
    # dwa peery z tym samym adresem (wytkniete w recenzji zewnetrznej; alokator adminow od
    # poczatku sprawdzal urzadzenia, ten nie sprawdzal adminow).
    result = await session.execute(select(Device.wg_ip))
    used = {ipaddress.ip_address(row[0]) for row in result.all()}
    for row in (await session.execute(select(AdminPeer.wg_ip))).all():
        used.add(ipaddress.ip_address(row[0]))
    used.add(server_ip)

    for host in network.hosts():
        if host not in used:
            return str(host)

    raise RuntimeError("Brak wolnych adresów IP w puli WG_SUBNET")


async def allocate_admin_ip(session: AsyncSession) -> str:
    """Adres dla peera administracyjnego — z KOŃCA puli (schodząc od góry), żeby nie
    kolidować z urządzeniami (te idą od dołu). Bez rezerwowania osobnego bloku:
    kolizja z alokacją urządzeń nastąpiłaby dopiero przy wypełnieniu całej podsieci."""
    await _lock_ip_pool(session)
    network = ipaddress.ip_network(wg.subnet)
    server_ip = ipaddress.ip_address(wg.server_ip)

    used = {server_ip}
    for row in (await session.execute(select(Device.wg_ip))).all():
        used.add(ipaddress.ip_address(row[0]))
    for row in (await session.execute(select(AdminPeer.wg_ip))).all():
        used.add(ipaddress.ip_address(row[0]))

    network_int = int(network.network_address)
    for ip_int in range(int(network.broadcast_address) - 1, network_int, -1):
        candidate = ipaddress.ip_address(ip_int)
        if candidate not in used:
            return str(candidate)

    raise RuntimeError("Brak wolnych adresów IP w puli WG_SUBNET")
