"""Token instalacyjny — zamyka okno przejecia portalu przed przeklikaniem kreatora.

Od `docker compose up` do zalozenia pierwszego administratora kreator jest otwarty dla
kazdego, kto dotrze do portu panelu. Przy CADDY_BIND=0.0.0.0 na VPS-ie bez chmurowej zapory
to cala sieć — a Docker omija lancuch INPUT, wiec lokalny iptables nie pomaga (zob.
README, sekcja Bezpieczenstwo). Kto pierwszy zalozy konto, ten ma portal.

Token powstaje przy starcie, gdy w bazie nie ma uzytkownikow, i trafia WYLACZNIE do logow
kontenera — czyli do kogos, kto i tak ma dostep do serwera. Kreator i odtwarzanie kopii
wymagaja go; po udanym zalozeniu portalu plik znika.
"""
from __future__ import annotations

import hmac
import logging
import os
import secrets

from app.config import _SECRETS_DIR

logger = logging.getLogger("setup")

_PATH = os.path.join(_SECRETS_DIR, "setup.token")
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # bez 0/O i 1/I/L — przepisywany z logow recznie


def _generate() -> str:
    raw = "".join(secrets.choice(_ALPHABET) for _ in range(12))
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


def ensure() -> str:
    """Wolane przy starcie, gdy portal nie jest jeszcze zalozony. Restart przed ukonczeniem
    kreatora NIE zmienia tokenu — inaczej ktos z logami sprzed restartu wpisywalby stary."""
    os.makedirs(_SECRETS_DIR, exist_ok=True)
    token = ""
    if os.path.exists(_PATH):
        with open(_PATH) as f:
            token = f.read().strip()
    if not token:
        token = _generate()
        with open(_PATH, "w") as f:
            f.write(token)
        os.chmod(_PATH, 0o600)
    bar = "=" * 64
    logger.warning("\n%s\n  TOKEN INSTALACYJNY: %s\n  Wpisz go w kreatorze pierwszego uruchomienia.\n%s",
                   bar, token, bar)
    print(f"\n{bar}\n  TOKEN INSTALACYJNY: {token}\n  Wpisz go w kreatorze pierwszego uruchomienia.\n{bar}\n",
          flush=True)
    return token


def check(value: str) -> bool:
    if not os.path.exists(_PATH):
        return False
    with open(_PATH) as f:
        expected = f.read().strip()
    given = (value or "").strip().upper().replace(" ", "")
    if given and "-" not in given and len(given) == 12:
        given = f"{given[0:4]}-{given[4:8]}-{given[8:12]}"
    return bool(expected) and hmac.compare_digest(given.encode(), expected.encode())


def consume() -> None:
    try:
        os.remove(_PATH)
    except FileNotFoundError:
        pass
