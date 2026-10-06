"""Wysyłka e-mail (SMTP) — na razie sama konfiguracja i test; warstwa zdarzeń
(subskrypcje, limity antyspamowe) dochodzi osobno.

Świadomie stdlib `smtplib` w wątku zamiast nowej zależności typu aiosmtplib: poczta
leci rzadko i pojedynczo, więc `asyncio.to_thread` w zupełności wystarcza, a każda
kolejna biblioteka to kolejna rzecz do utrzymania w obrazie.

Hasło SMTP trzymamy zaszyfrowane Fernetem w tabeli `settings` — tak samo jak hasła API
urządzeń i klucze WG. Konsekwencja: jedzie w kopii portalu razem z kluczem Fernet,
czyli odtworzenie portalu odtwarza też działającą pocztę.
"""
import asyncio
import datetime
import smtplib
import ssl
from email.message import EmailMessage

from sqlalchemy.ext.asyncio import AsyncSession

from app.security import decrypt, encrypt
from app.settings_store import get_setting, set_setting

SMTP_KEYS = (
    "smtp_enabled",
    "smtp_host",
    "smtp_port",
    "smtp_security",   # none | starttls | ssl
    "smtp_username",
    "smtp_from",
    "smtp_to",         # domyślni odbiorcy, po przecinku
)
_PASSWORD_KEY = "smtp_password_encrypted"


async def get_smtp_settings(session: AsyncSession) -> dict:
    cfg = {key: await get_setting(session, key) for key in SMTP_KEYS}
    # Hasła NIE zwracamy — do formularza idzie tylko informacja, czy jest ustawione.
    cfg["has_password"] = bool(await get_setting(session, _PASSWORD_KEY))
    return cfg


async def save_smtp_settings(session: AsyncSession, values: dict, password: str | None) -> None:
    for key in SMTP_KEYS:
        if key in values:
            await set_setting(session, key, values[key])
    # Puste pole hasła = zostaw dotychczasowe (żeby edycja portu nie kasowała hasła).
    if password:
        await set_setting(session, _PASSWORD_KEY, encrypt(password))


async def clear_smtp_password(session: AsyncSession) -> None:
    await set_setting(session, _PASSWORD_KEY, "")


def _build_message(cfg: dict, to: list[str], subject: str, body: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = cfg.get("smtp_from") or cfg.get("smtp_username") or "mikrotik-manager"
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def _send_blocking(cfg: dict, password: str, msg: EmailMessage) -> None:
    host = cfg["smtp_host"]
    port = int(cfg.get("smtp_port") or 587)
    security = (cfg.get("smtp_security") or "starttls").lower()
    timeout = 20

    if security == "ssl":
        context = ssl.create_default_context()
        server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    try:
        server.ehlo()
        if security == "starttls":
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        if cfg.get("smtp_username"):
            server.login(cfg["smtp_username"], password)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


async def send_mail(session: AsyncSession, *, subject: str, body: str,
                    to: list[str] | None = None, force: bool = False) -> dict:
    """`force=True` pomija globalny przełącznik — używane przez „wyślij testowo",
    żeby dało się sprawdzić konfigurację przed jej włączeniem."""
    cfg = await get_smtp_settings(session)
    if not force and cfg.get("smtp_enabled") != "1":
        return {"ok": False, "error": "Wysyłka e-mail jest wyłączona w ustawieniach."}
    if not cfg.get("smtp_host"):
        return {"ok": False, "error": "Nie podano serwera SMTP."}

    recipients = to or [a.strip() for a in (cfg.get("smtp_to") or "").split(",") if a.strip()]
    if not recipients:
        return {"ok": False, "error": "Brak odbiorcy — podaj adres w ustawieniach albo w teście."}

    raw = await get_setting(session, _PASSWORD_KEY)
    password = decrypt(raw) if raw else ""
    msg = _build_message(cfg, recipients, subject, body)
    try:
        await asyncio.to_thread(_send_blocking, cfg, password, msg)
        return {"ok": True, "recipients": recipients}
    except Exception as e:
        # Komunikaty SMTP bywają jedyną wskazówką, co jest źle skonfigurowane —
        # pokazujemy typ i treść wprost, zamiast generycznego „nie udało się".
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def send_test_mail(session: AsyncSession, to: list[str] | None = None) -> dict:
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return await send_mail(
        session,
        subject="MikroTik Manager — wiadomość testowa",
        body=(
            "To jest wiadomość testowa z portalu MikroTik Manager.\n\n"
            f"Wysłana: {stamp}\n\n"
            "Jeśli ją widzisz, konfiguracja SMTP działa i portal będzie mógł wysyłać\n"
            "powiadomienia o zdarzeniach, gdy je włączysz.\n"
        ),
        to=to,
        force=True,
    )
