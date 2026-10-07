"""Wersja portalu i sprawdzanie aktualizacji w rejestrze obrazow."""
import asyncio

import httpx
import pytest

from app import portal_update as pu
from app import version as v


@pytest.mark.parametrize("value,parsed", [
    ("0.6.8", (0, 6, 8)), ("10.0.12", (10, 0, 12)),
    ("dev", None), ("latest", None), ("0.6", None), ("1.0.0-rc1", None), ("v0.6.8", None), ("", None), (None, None),
])
def test_parse(value, parsed):
    assert v.parse(value) == parsed


def test_newest_ignores_non_releases_and_sorts_numerically():
    assert v.newest(["latest", "0.6", "0.6.9", "0.6.10", "0.5.3", "sha-abc"]) == "0.6.10"
    assert v.newest(["latest", "0.6"]) is None


@pytest.mark.parametrize("cand,cur,newer", [
    ("0.6.9", "0.6.8", True), ("0.6.8", "0.6.8", False), ("0.6.7", "0.6.8", False),
    ("0.6.9", "dev", False), (None, "0.6.8", False),
])
def test_is_newer(cand, cur, newer):
    assert v.is_newer(cand, cur) is newer


@pytest.mark.parametrize("repo,api,name", [
    ("ghcr.io/zaba44/mikrotik-manager-backend", "https://ghcr.io", "zaba44/mikrotik-manager-backend"),
    ("localhost:5000/mtm-backend", "https://localhost:5000", "mtm-backend"),
    ("someone/mtm-backend", "https://registry-1.docker.io", "someone/mtm-backend"),
])
def test_registry_of(monkeypatch, repo, api, name):
    monkeypatch.delenv("MTM_REGISTRY_API", raising=False)
    assert pu.registry_of(repo) == (api, name)


def test_registry_api_override(monkeypatch):
    monkeypatch.setenv("MTM_REGISTRY_API", "http://rejestr:5000/")
    assert pu.registry_of("localhost:5000/mtm-backend") == ("http://rejestr:5000", "mtm-backend")


def _registry(tags_by_repo):
    """Rejestr jak ghcr.io: bez tokenu 401 z naglowkiem WWW-Authenticate, z tokenem lista tagow."""
    def handler(req: httpx.Request):
        if req.url.path == "/token":
            assert req.url.params["service"] == "ghcr.io" and req.url.params["scope"].startswith("repository:")
            return httpx.Response(200, json={"token": "T"})
        repo = req.url.path.removeprefix("/v2/").removesuffix("/tags/list")
        if req.headers.get("authorization") != "Bearer T":
            return httpx.Response(401, headers={"www-authenticate":
                f'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:{repo}:pull"'})
        return httpx.Response(200, json={"name": repo, "tags": tags_by_repo[repo]})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_fetch_tags_with_anonymous_token():
    client = _registry({"zaba44/mikrotik-manager-backend": ["0.6.8", "latest"]})
    tags = asyncio.run(pu.fetch_tags("ghcr.io/zaba44/mikrotik-manager-backend", client))
    assert tags == ["0.6.8", "latest"]


class _S:
    def __init__(self, store):
        self.store = store

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def commit(self):
        pass


def test_check_needs_both_images(monkeypatch):
    """Wersja jest „dostępna", gdy sa obrazy backendu I agenta — tag wypchniety w trakcie
    budowania (jeden obraz gotowy, drugi nie) nie moze uruchomic aktualizacji."""
    monkeypatch.delenv("MTM_REGISTRY_API", raising=False)
    monkeypatch.setenv("MTM_IMAGE", "ghcr.io/zaba44/mikrotik-manager")
    store = {}

    async def fake_set(s, k, val):
        store[k] = val
    monkeypatch.setattr(pu, "set_setting", fake_set)
    monkeypatch.setattr(pu, "async_session", lambda: _S(store))
    client = _registry({"zaba44/mikrotik-manager-backend": ["0.6.8", "0.6.9", "0.7.0", "latest"],
                        "zaba44/mikrotik-manager-wireguard": ["0.6.8", "0.6.9", "latest"]})
    result = asyncio.run(pu.check(client))
    assert result["latest"] == "0.6.9" and result["error"] is None
    assert store[pu._KEY_LATEST] == "0.6.9" and pu.LATEST == "0.6.9"


def test_check_reports_registry_error(monkeypatch):
    store = {}

    async def fake_set(s, k, val):
        store[k] = val
    monkeypatch.setattr(pu, "set_setting", fake_set)
    monkeypatch.setattr(pu, "async_session", lambda: _S(store))
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    result = asyncio.run(pu.check(client))
    assert result["latest"] is None and "503" in result["error"]
    assert pu._KEY_LATEST not in store  # nieudane sprawdzenie nie kasuje ostatniego wyniku


@pytest.mark.parametrize("ros,t", [
    ("7.13.5 (stable)", (7, 13, 5)), ("7.15 (stable)", (7, 15)), ("7.20rc2 (testing)", (7, 20)), (None, None), ("", None),
])
def test_routeros_tuple(ros, t):
    assert pu.routeros_tuple(ros) == t


def test_dev_build_cannot_update_from_panel(monkeypatch):
    monkeypatch.setattr(v, "VERSION", "dev")
    import app.portal_backup as pb
    monkeypatch.setattr(pb, "pending_restore", lambda: None)

    class Count:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def execute(self, stmt):
            class R:
                def scalar(self):
                    return 0
            return R()
    monkeypatch.setattr(pu, "async_session", lambda: Count())
    out = asyncio.run(pu.blockers("0.6.9", {"state": "idle", "stack": {"project": "p", "host_dir": "/x"}}))
    assert any("deweloperska" in b for b in out)


def test_about_template_keys_do_not_shadow_dict_methods():
    """`about.update.checked_at` w Jinja trafialo w metode dict.update — pole bylo zawsze puste.
    Zaden klucz uzywany w szablonie nie moze miec nazwy metody slownika."""
    import re as _re
    html = open("app/templates/settings_about.html", encoding="utf-8").read()
    used = set(_re.findall(r"\babout\.(\w+)", html)) | set(_re.findall(r"\bp\.(\w+)", html))
    assert not used & set(dir(dict)), used & set(dir(dict))


@pytest.mark.parametrize("ros,old", [
    ("7.13.5 (stable)", True), ("7.14.3 (stable)", True), ("6.49.10 (long-term)", True),
    ("7.15 (stable)", False), ("7.24.5 (stable)", False), ("7.20rc2 (testing)", False), ("8.0", False),
    (None, False), ("", False),   # nieznana wersja — nie ostrzegamy na slepo
])
def test_routeros_too_old(ros, old):
    assert pu.routeros_too_old(ros) is old


def test_old_routeros_warnings_render():
    """Ostrzezenia w szablonach: pulpit, plakietka na liscie, strona urzadzenia."""
    from app.templating import templates
    assert templates.env.globals["ros_min"] == "7.15"
    tpl = templates.env.from_string(
        "{% if ros_too_old(v) %}STARY {{ ros_min }}{% else %}OK{% endif %}")
    assert tpl.render(v="7.13.5 (stable)") == "STARY 7.15" and tpl.render(v="7.24.5 (stable)") == "OK"
