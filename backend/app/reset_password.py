"""Reset zapomnianego hasla z poziomu serwera — bez logowania do panelu.

Uzycie (na serwerze, w katalogu stacka):

    docker compose exec backend python -m app.reset_password            # wypisze konta i zapyta
    docker compose exec backend python -m app.reset_password admin      # od razu dla konta „admin"

Haslo wpisuje sie przy ukrytym wprowadzaniu (dwa razy), wiec nie trafia ani na ekran, ani
do historii polecen. Bez terminala (skrypt) login i haslo czytane sa ze stdin, jak w
`app.create_admin`:  printf 'login\\nhaslo\\n' | docker compose exec -T backend python -m app.reset_password

Zmienia WYLACZNIE haslo — rola i lokalizacja konta zostaja. Wszystkie zalogowane sesje tego
konta wygasaja (odcisk hasla w sesji). Kto ma dostep do serwera, ma i tak pelna wladze nad
portalem, wiec to nie jest nowa furtka, tylko wygodniejsza droga niz reczny SQL.
Gdy nie zostalo zadne konto administratora, zob. `app.create_admin`.
"""
import asyncio
import getpass
import sys

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import hash_password
from app.database import async_session
from app.models import User


async def reset(session: AsyncSession, username: str, password: str) -> bool:
    """Ustawia nowe haslo kontu. False, gdy konta nie ma."""
    user = (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if user is None:
        return False
    user.password_hash = hash_password(password)
    await session.commit()
    return True


def _ask(usernames: list[str], preset: str | None) -> tuple[str, str]:
    """Login i haslo: z terminala (ukryte haslo, dwa razy) albo ze stdin."""
    if not sys.stdin.isatty():
        lines = sys.stdin.read().splitlines()
        if preset:
            lines.insert(0, preset)
        if len(lines) < 2 or not lines[0].strip() or not lines[1]:
            raise SystemExit("Podaj login w 1. linii i nowe hasło w 2. linii stdin.")
        return lines[0].strip(), lines[1]

    print("Konta w portalu:", ", ".join(usernames))
    username = preset or input("Login, któremu zmienić hasło: ").strip()
    password = getpass.getpass("Nowe hasło: ")
    if not password:
        raise SystemExit("Hasło nie może być puste — nic nie zmieniono.")
    if getpass.getpass("Powtórz hasło: ") != password:
        raise SystemExit("Hasła się różnią — nic nie zmieniono.")
    return username, password


async def main(argv: list[str]) -> None:
    async with async_session() as session:
        accounts = (await session.execute(select(User).order_by(User.username))).scalars().all()
        if not accounts:
            raise SystemExit("W portalu nie ma jeszcze żadnego konta — załóż je w kreatorze w przeglądarce.")
        username, password = _ask([f"{u.username} ({u.role})" for u in accounts], argv[1] if len(argv) > 1 else None)
        if not await reset(session, username, password):
            raise SystemExit(f"Nie ma konta „{username}” — nic nie zmieniono.")
    print(f"Hasło zmienione: {username}. Zalogowane sesje tego konta wygasły.")


if __name__ == "__main__":
    asyncio.run(main(sys.argv))
