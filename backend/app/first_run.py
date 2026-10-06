"""Wykrywanie pierwszego uruchomienia: brak użytkowników = kreator. Wynik pozytywny
(userzy istnieją) cache'ujemy — nie znika w trakcie życia procesu."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User

_users_exist = False


async def users_exist(session: AsyncSession) -> bool:
    global _users_exist
    if _users_exist:
        return True
    row = (await session.execute(select(User.id).limit(1))).first()
    _users_exist = row is not None
    return _users_exist


def mark_users_exist() -> None:
    global _users_exist
    _users_exist = True
