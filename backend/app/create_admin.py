"""Jednorazowy bootstrap administratora. Czyta login (1. linia) i hasło (2. linia)
ze stdin — żeby hasło nie trafiło do argv/historii. W bazie ląduje tylko hash.

Użycie: printf 'login\\nhaslo\\n' | docker exec -i mtm-backend python -m app.create_admin
Idempotentny: istniejący user o tym loginie dostaje nowe hasło i rolę admin.
"""
import asyncio
import sys

from sqlalchemy import select

from app.auth import hash_password
from app.database import async_session
from app.models import User


async def main() -> None:
    lines = sys.stdin.read().splitlines()
    if len(lines) < 2 or not lines[0].strip() or not lines[1]:
        print("Podaj login w 1. linii i hasło w 2. linii stdin.")
        raise SystemExit(1)
    username, password = lines[0].strip(), lines[1]

    async with async_session() as session:
        existing = (
            await session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        if existing:
            existing.password_hash = hash_password(password)
            existing.role = "admin"
            existing.location_id = None
            action = "zaktualizowany"
        else:
            session.add(User(username=username, password_hash=hash_password(password), role="admin"))
            action = "utworzony"
        await session.commit()

    print(f"Administrator {action}: {username}")


if __name__ == "__main__":
    asyncio.run(main())
