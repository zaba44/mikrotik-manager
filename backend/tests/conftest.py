"""Testy czystej logiki — bez bazy, routerow i Dockera.

Uruchomienie (z katalogu backend):  python -m pytest tests

Moduly aplikacji czytaja konfiguracje przy imporcie, wiec zmienne srodowiskowe ustawiamy
TUTAJ, przed pierwszym importem `app`. Silnik bazy powstaje leniwie (create_async_engine
nie laczy sie przy imporcie), wiec falszywy DATABASE_URL wystarcza, dopoki test nie
dotyka bazy. Testy wymagajace bazy albo sprzetu sa w scenariuszach na labie, nie tu.
"""
import os
import sys

from cryptography.fernet import Fernet

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@127.0.0.1:1/test")
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())
os.environ.setdefault("SESSION_SECRET", "test-session-secret")
os.environ.setdefault("BACKUP_SFTP_PASSWORD", "test-sftp")

# Szablony laduja sie ze sciezki wzglednej `app/templates` — jak w kontenerze (WORKDIR /app).
os.chdir(BACKEND)
sys.path.insert(0, BACKEND)
