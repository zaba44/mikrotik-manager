from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import AdminPeer
from app.security import allocate_admin_ip, decrypt, encrypt, generate_preshared_key, generate_wg_keypair
from app.wg_agent_client import add_peer, hub_peers_lock, remove_peer
from app.wg_config import wg


def build_admin_peer_config(peer: AdminPeer) -> str:
    """Gotowy config klienta WireGuard do importu (np. na PC). AllowedIPs = cała
    podsieć WG, żeby maszyna admina widziała wszystkie urządzenia przez tunel."""
    psk_line = ""
    if peer.wg_preshared_key_encrypted:
        psk_line = f"PreSharedKey = {decrypt(peer.wg_preshared_key_encrypted)}\n"
    return f"""[Interface]
PrivateKey = {decrypt(peer.wg_private_key_encrypted)}
Address = {peer.wg_ip}/{wg.mask}

[Peer]
PublicKey = {wg.server_public_key}
Endpoint = {wg.hub_endpoint}:{settings.wg_port}
AllowedIPs = {wg.subnet}
{psk_line}PersistentKeepalive = 25
"""


async def create_admin_peer(session: AsyncSession, name: str) -> tuple[AdminPeer, str | None]:
    """Generuje klucze, przydziela adres z końca puli, dodaje peera do żywego wg-mt.
    Zwraca (peer, peer_warning) — błąd agenta nie blokuje zapisu (baza to źródło
    prawdy), tylko sygnalizowany ostrzeżeniem, tak jak przy urządzeniach."""
    private_key, public_key = generate_wg_keypair()
    preshared_key = generate_preshared_key()
    wg_ip = await allocate_admin_ip(session)

    peer = AdminPeer(
        name=name.strip(),
        wg_public_key=public_key,
        wg_private_key_encrypted=encrypt(private_key),
        wg_preshared_key_encrypted=encrypt(preshared_key),
        wg_ip=wg_ip,
    )
    session.add(peer)
    await session.commit()
    await session.refresh(peer)

    added, error = await add_peer(peer.wg_public_key, str(peer.wg_ip), preshared_key)
    warning = None
    if not added:
        warning = (
            f"Automatyczne dodanie peera na wg-mt nie powiodło się ({error}). "
            f"Dodaj ręcznie: docker compose exec wireguard wg set wg-mt peer "
            f"{peer.wg_public_key} allowed-ips {peer.wg_ip}/32"
        )
    return peer, warning


async def delete_admin_peer(session: AsyncSession, peer: AdminPeer) -> tuple[bool, str | None]:
    """Usuniecie peera administracyjnego to ODEBRANIE DOSTEPU, wiec rekord znika z bazy
    dopiero, gdy hub potwierdzi usuniecie. Wczesniej bylo „best-effort": przy niedzialajacym
    agencie rekord znikal z panelu, a peer zostawal na hubie — i to trwale, bo agent zapisuje
    peery do pliku konfiguracyjnego (wytkniete w recenzji zewnetrznej). Panel przestawal go
    pokazywac, a dostep dalej dzialal."""
    async with hub_peers_lock:  # odtwarzanie kopii nie moze go w tym czasie dolozyc z powrotem
        ok, error = await remove_peer(peer.wg_public_key)
        if not ok:
            return False, error
        await session.delete(peer)
        await session.commit()
    return True, None
