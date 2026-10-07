"""Reset hasla z serwera (`python -m app.reset_password`)."""
import asyncio
import io

import pytest

from app import reset_password as rp
from app.auth import verify_password
from app.models import User


class _Result:
    def __init__(self, user):
        self.user = user

    def scalar_one_or_none(self):
        return self.user


class _Session:
    def __init__(self, user):
        self.user, self.commits = user, 0

    async def execute(self, stmt):
        wanted = stmt.compile().params.get("username_1")
        return _Result(self.user if self.user and self.user.username == wanted else None)

    async def commit(self):
        self.commits += 1


def test_reset_changes_only_password():
    user = User(username="admin", password_hash="stary", role="operator")
    s = _Session(user)
    assert asyncio.run(rp.reset(s, "admin", "Nowe-haslo-1")) is True
    assert verify_password("Nowe-haslo-1", user.password_hash)
    assert user.role == "operator" and s.commits == 1


def test_reset_unknown_account_changes_nothing():
    user = User(username="admin", password_hash="stary", role="admin")
    s = _Session(user)
    assert asyncio.run(rp.reset(s, "nie-ma", "x")) is False
    assert user.password_hash == "stary" and s.commits == 0


def test_stdin_mode_reads_login_and_password(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("admin\nHaslo z spacja\n"))
    assert rp._ask(["admin (admin)"], None) == ("admin", "Haslo z spacja")


def test_stdin_mode_with_login_in_argument(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("Haslo-2\n"))
    assert rp._ask(["admin (admin)"], "admin") == ("admin", "Haslo-2")


def test_stdin_mode_without_password_refuses(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("admin\n"))
    with pytest.raises(SystemExit):
        rp._ask(["admin (admin)"], None)


class _Tty(io.StringIO):
    def isatty(self):
        return True


@pytest.mark.parametrize("answers,ok", [
    (["Haslo-1", "Haslo-1"], True),
    (["Haslo-1", "Haslo-2"], False),   # rozne — nic nie zmieniamy
    ([""], False),                      # puste
])
def test_terminal_mode_confirms_password(monkeypatch, answers, ok):
    monkeypatch.setattr("sys.stdin", _Tty(""))
    it = iter(answers)
    monkeypatch.setattr(rp.getpass, "getpass", lambda prompt="": next(it))
    if ok:
        assert rp._ask(["admin (admin)"], "admin") == ("admin", "Haslo-1")
    else:
        with pytest.raises(SystemExit):
            rp._ask(["admin (admin)"], "admin")
