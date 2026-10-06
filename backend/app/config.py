import os
from dataclasses import dataclass

# Sekrety aplikacyjne żyją na wolumenie (/data/secrets), nie w .env — dzięki temu
# świeża instalacja generuje je sama, a przywracanie kopii portalu może je odtworzyć
# (klucz Fernet MUSI przetrwać, inaczej zaszyfrowane dane w bazie są nie do odczytu).
# entrypoint.sh seeduje/generuje te pliki przed startem uvicorna; env to fallback
# na czas przejścia (istniejący lab jeszcze ma wartości w .env).
#
# Zmienne WG_* i HUB_ENDPOINT są OPCJONALNE: przy świeżej instalacji ustawia je kreator
# pierwszego uruchomienia i trafiają do bazy (patrz app/wg_config.py). Dlatego czytamy
# je przez .get() — brak klucza w .env nie może wywalać backendu przy starcie, bo to
# domyślny stan dystrybuowanego obrazu.
_SECRETS_DIR = "/data/secrets"


def _secret(filename: str, env_key: str) -> str:
    path = os.path.join(_SECRETS_DIR, filename)
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    return os.environ[env_key]


@dataclass(frozen=True)
class Settings:
    fernet_key: str
    wg_subnet: str
    wg_server_ip: str
    wg_port: str
    wg_server_public_key: str
    hub_endpoint: str
    wg_agent_token: str
    poll_interval_seconds: int
    update_wait_timeout_seconds: int
    update_post_online_buffer_seconds: int
    backup_sftp_password: str
    backup_sftp_port: int
    backup_upload_timeout_seconds: int
    session_secret: str
    syslog_port: int


def load_settings() -> Settings:
    # UWAGA na wzorzec `os.environ.get(KEY) or "domyslna"` zamiast `get(KEY, "domyslna")`:
    # docker compose przekazuje do kontenera KAZDA zmienna wymieniona w `environment:`,
    # a gdy nie ma jej w .env — wstawia PUSTY CIAG. Wtedy klucz istnieje, wiec drugi
    # argument get() nigdy nie zadziala i int("") wywala aplikacje. Wyszlo dopiero przy
    # pierwszej instalacji z krotkiego .env (dystrybucja) — patrz docs/oracle.md.
    return Settings(
        fernet_key=_secret("fernet.key", "FERNET_KEY"),
        session_secret=_secret("session.secret", "SESSION_SECRET"),
        backup_sftp_password=_secret("backup_sftp.pw", "BACKUP_SFTP_PASSWORD"),
        wg_subnet=os.environ.get("WG_SUBNET", ""),
        wg_server_ip=os.environ.get("WG_SERVER_IP", ""),
        wg_port=os.environ.get("WG_PORT") or "51820",
        wg_server_public_key=os.environ.get("WG_SERVER_PUBLIC_KEY", ""),
        hub_endpoint=os.environ.get("HUB_ENDPOINT", ""),
        wg_agent_token=os.environ.get("WG_AGENT_TOKEN", ""),
        poll_interval_seconds=int(os.environ.get("POLL_INTERVAL_SECONDS") or "60"),
        update_wait_timeout_seconds=int(os.environ.get("UPDATE_WAIT_TIMEOUT_SECONDS") or "600"),
        update_post_online_buffer_seconds=int(os.environ.get("UPDATE_POST_ONLINE_BUFFER_SECONDS") or "90"),
        backup_sftp_port=int(os.environ.get("BACKUP_SFTP_PORT") or "2222"),
        backup_upload_timeout_seconds=int(os.environ.get("BACKUP_UPLOAD_TIMEOUT_SECONDS") or "120"),
        # Niestandardowy port syslog — osiągalny tylko przez tunel (DNAT), nigdzie nie
        # publikowany na hosta. Routery dostają go od nas przez API, więc 514 nie jest
        # do niczego potrzebne (i lepiej nie zajmować portu systemowego na VPS-ie).
        syslog_port=int(os.environ.get("SYSLOG_PORT") or "5514"),
    )


settings = load_settings()
