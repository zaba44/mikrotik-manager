import base64
import hashlib
import hmac
import os
import uuid

from fastapi import HTTPException, Request

from app.models import User

# pbkdf2 ze stdlib — bez nowej zależności/native-wheel (bcrypt/passlib). Format:
# pbkdf2_sha256$<iteracje>$<salt_b64>$<hash_b64>.
_ITERATIONS = 600_000


def session_fingerprint(password_hash: str) -> str:
    """Odcisk hasla zapisywany w sesji. Zmiana hasla (wlasna albo reset przez admina)
    zmienia odcisk, wiec wszystkie inne zalogowane sesje tego uzytkownika przestaja byc
    wazne — przejete ciasteczko nie przetrwa resetu hasla. Sam hash hasla do ciasteczka
    nie trafia: ciasteczko jest podpisane, ale nie szyfrowane."""
    return hashlib.sha256(("mtm-session:" + password_hash).encode()).hexdigest()[:20]


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def current_user(request: Request) -> User:
    """User zalogowany w tym żądaniu (ustawiony przez auth middleware). Na trasach
    chronionych zawsze jest — middleware wcześniej przekierowałby na /login."""
    return request.state.user


def is_admin(user: User) -> bool:
    return user.role == "admin"


def require_admin(request: Request) -> User:
    user = current_user(request)
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Tylko administrator")
    return user


def can_see_location(user: User, location_id: uuid.UUID | None) -> bool:
    return is_admin(user) or (location_id is not None and location_id == user.location_id)


def require_location(request: Request, location_id: uuid.UUID | None) -> None:
    if not can_see_location(current_user(request), location_id):
        raise HTTPException(status_code=403, detail="Brak dostępu do tej lokalizacji")


def can_operate(user: User) -> bool:
    """Może wykonywać akcje operacyjne (aktualizacja/restart/sprawdzanie): admin zawsze,
    operator tylko gdy NIE jest 'tylko statusy'. Nie mówi jeszcze o której lokalizacji —
    to sprawdza require_operate_location."""
    return is_admin(user) or (user.role == "operator" and not user.status_only)


def require_operate_location(request: Request, location_id: uuid.UUID | None) -> None:
    user = current_user(request)
    if is_admin(user):
        return
    if can_operate(user) and location_id is not None and location_id == user.location_id:
        return
    raise HTTPException(status_code=403, detail="Brak uprawnień do operacji na tym urządzeniu")
