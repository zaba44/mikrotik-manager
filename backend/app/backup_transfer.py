import asyncio
import logging
import os

import asyncssh

from app.config import settings

logger = logging.getLogger("backup_transfer")

INCOMING_DIR = "/data/backups/incoming"
HOST_KEY_PATH = "/data/backups/ssh_host_key"
SFTP_USERNAME = "mtm-backup"

_POLL_INTERVAL_SECONDS = 2


class _AuthServer(asyncssh.SSHServer):
    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == SFTP_USERNAME and password == settings.backup_sftp_password


class _ChrootSFTPServer(asyncssh.SFTPServer):
    def __init__(self, chan):
        super().__init__(chan, chroot=INCOMING_DIR)


async def start_backup_sftp_server() -> asyncssh.SSHAcceptor:
    """Serwer SFTP wbudowany w backend — osiągalny wyłącznie przez tunel wg-mt
    (DNAT w kontenerze wireguard, żaden port nie jest publikowany na hosta).
    Wzorzec (server_factory/sftp_factory/validate_password) potwierdzony ręcznie
    w Kroku 0 na żywym sprzęcie przed wdrożeniem produkcyjnym."""
    os.makedirs(INCOMING_DIR, exist_ok=True)
    server = await asyncssh.listen(
        "0.0.0.0",
        settings.backup_sftp_port,
        server_host_keys=[HOST_KEY_PATH],
        server_factory=_AuthServer,
        sftp_factory=_ChrootSFTPServer,
    )
    logger.info("Backup SFTP server listening on :%d", settings.backup_sftp_port)
    return server


def incoming_path(token: str) -> str:
    return os.path.join(INCOMING_DIR, token)


async def wait_for_upload(token: str, timeout_seconds: float) -> str | None:
    """Polluje katalog przychodzący aż plik `token` przestanie rosnąć (koniec
    transferu SFTP), albo upłynie timeout. Polling zamiast hooków wewnętrznych
    asyncssh (open/close na SFTPServer) — nie chcieliśmy zgadywać niesprawdzonego
    zachowania biblioteki tak jak nie zgadywaliśmy składni RouterOS w Kroku 0."""
    path = incoming_path(token)
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_seconds
    last_size = -1

    while loop.time() < deadline:
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)
        if os.path.exists(path):
            size = os.path.getsize(path)
            if size > 0 and size == last_size:
                return path
            last_size = size

    return None


def cleanup_incoming(token: str) -> None:
    path = incoming_path(token)
    if os.path.exists(path):
        os.remove(path)
