from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Setting

# Klucze konfigurowalne w panelu /settings. Wartość domyślna użyta, gdy w tabeli
# settings jeszcze nie ma wiersza (pierwsze uruchomienie).
_DEFAULTS = {
    "backup_schedule_hours": "24",
    "backup_retention_count": "10",
    # 0 = trzymaj bez ograniczen; domyslnie kwartal historii zdarzen
    "syslog_retention_days": "90",
    # Globalny przełącznik — świeża instalacja startuje z syslogiem WYŁĄCZONYM.
    "syslog_enabled": "0",
    # Twardy sufit na urządzenie: retencja czasowa nie chroni przed nagłym zalewem.
    "syslog_max_entries_per_device": "5000",
    # Poczta — sama konfiguracja; warstwa zdarzeń/subskrypcji dochodzi osobno.
    "smtp_enabled": "0",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_security": "starttls",
    "smtp_username": "",
    "smtp_from": "",
    "smtp_to": "",
    "smtp_password_encrypted": "",
    # Powiadomienia — WSZYSTKO domyslnie wylaczone; wlacza sie swiadomie.
    "notify_enabled": "0",
    "notify_syslog_error": "0",
    "notify_syslog_warning": "0",
    "notify_device_offline": "0",
    "notify_device_online": "0",
    "notify_portal_login": "0",
    "notify_portal_login_failed": "0",
    "notify_backup_failed": "0",
    "notify_update_failed": "0",
    # Trzy bezpieczniki antyspamowe (0 = wylaczony dany bezpiecznik).
    "notify_dedup_minutes": "30",
    "notify_max_per_device_hour": "6",
    "notify_max_total_hour": "30",
    # Cotygodniowy raport — pomija bezpieczniki (nie jest zdarzeniem), ale wymaga
    # glownego przelacznika powiadomien.
    "notify_weekly_report": "0",
    "notify_weekly_report_last": "",
    "notify_retention_days": "60",
}


async def get_setting(session: AsyncSession, key: str) -> str:
    row = await session.get(Setting, key)
    if row is not None:
        return row.value
    return _DEFAULTS.get(key, "")


async def get_int_setting(session: AsyncSession, key: str) -> int:
    return int(await get_setting(session, key))


async def set_setting(session: AsyncSession, key: str, value: str) -> None:
    row = await session.get(Setting, key)
    if row is None:
        session.add(Setting(key=key, value=value))
    else:
        row.value = value
    await session.commit()


_BACKUP_KEYS = ("backup_schedule_hours", "backup_retention_count")
_SYSLOG_KEYS = ("syslog_enabled", "syslog_retention_days", "syslog_max_entries_per_device")


async def get_backup_settings(session: AsyncSession) -> dict[str, str]:
    return {key: await get_setting(session, key) for key in _BACKUP_KEYS}


async def get_syslog_settings(session: AsyncSession) -> dict[str, str]:
    return {key: await get_setting(session, key) for key in _SYSLOG_KEYS}
