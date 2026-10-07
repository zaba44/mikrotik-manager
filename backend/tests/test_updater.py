"""Usluga aktualizacji (infra/updater/updater.py) — logika bez prawdziwego Dockera."""
import importlib.util
import json
import os

import pytest

PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    "infra", "updater", "updater.py")
pytestmark = pytest.mark.skipif(not os.path.exists(PATH), reason="brak infra/updater/updater.py")


@pytest.fixture
def up(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("updater_under_test", PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    stack = tmp_path / "stack"
    stack.mkdir()
    (stack / ".env").write_text("WG_PORT=42403\nMTM_VERSION=0.6.8\nPOSTGRES_PASSWORD=tajne\n")
    os.chmod(stack / ".env", 0o600)
    monkeypatch.setattr(mod, "STACK_DIR", str(stack))
    monkeypatch.setattr(mod, "STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    mod.stack_dir = stack
    return mod


@pytest.mark.parametrize("value,ok", [
    ("0.6.9", True), ("10.20.30", True),
    ("latest", False), ("0.6", False), ("0.6.9; rm -rf /", False), ("../0.6.9", False), (None, False), (7, False),
])
def test_only_release_numbers_accepted(up, value, ok):
    assert up.valid_version(value) is ok


def test_env_version_replaced_rest_untouched(up):
    out = up.set_env_version("A=1\nMTM_VERSION=latest\n# komentarz\nB=2", "0.6.9")
    assert out == "A=1\nMTM_VERSION=0.6.9\n# komentarz\nB=2\n"
    assert up.set_env_version("A=1\n", "0.6.9").endswith("MTM_VERSION=0.6.9\n")
    assert up.env_version("X=1\nMTM_VERSION=0.6.8\n") == "0.6.8"


def test_stack_discovered_from_own_container(up):
    info = {"Config": {"Labels": {"com.docker.compose.project": "mikrotik-manager"}},
            "Mounts": [{"Type": "volume", "Destination": "/data/updater", "Source": "/var/lib/docker/x"},
                       {"Type": "bind", "Destination": up.STACK_DIR, "Source": "/opt/mikrotik-manager"}]}
    assert up.stack_from_inspect(info) == {"project": "mikrotik-manager", "host_dir": "/opt/mikrotik-manager"}
    assert "error" in up.stack_from_inspect({"Config": {"Labels": {}}, "Mounts": []})
    assert "error" in up.stack_from_inspect({"Config": {"Labels": {"com.docker.compose.project": "p"}}, "Mounts": []})


def test_compose_uses_host_path_and_stack_files(up):
    cmd = up.compose_base({"project": "mtm", "host_dir": "/opt/mikrotik-manager"})
    assert cmd[:4] == ["docker", "compose", "-p", "mtm"]
    assert "--project-directory" in cmd and cmd[cmd.index("--project-directory") + 1] == "/opt/mikrotik-manager"
    assert f"{up.STACK_DIR}/.env" in cmd and f"{up.STACK_DIR}/docker-compose.yml" in cmd


class _Docker:
    """Atrapa `docker compose`: zapisuje polecenia, pull moze sie nie udac."""

    def __init__(self, up, pull_ok=True, image_tag=None):
        self.up, self.pull_ok, self.image_tag, self.calls = up, pull_ok, image_tag, []

    def run(self, cmd, timeout=900):
        self.calls.append(cmd)
        if "pull" in cmd:
            return (0, "Pulled") if self.pull_ok else (1, "manifest unknown")
        if "up" in cmd:
            return 0, "Recreated"
        if "ps" in cmd:
            tag = self.image_tag or self.up.env_version((self.up.stack_dir / ".env").read_text())
            return 0, "\n".join(json.dumps({"Service": s, "Image": f"ghcr.io/x/mtm-{s}:{tag}", "State": "running"})
                                for s in ("backend", "wireguard", "postgres"))
        return 0, ""


def _go(up, docker, monkeypatch, target="0.6.9"):
    monkeypatch.setattr(up, "_run", docker.run)
    monkeypatch.setattr(up, "_stack", lambda: {"project": "mtm", "host_dir": "/opt/mikrotik-manager"})
    up._lock.acquire()
    up._state.update({"state": "running", "target": target, "log": []})
    up._update(target)
    return up._state


def test_successful_update(up, monkeypatch):
    docker = _Docker(up)
    state = _go(up, docker, monkeypatch)
    assert state["state"] == "done" and state["from"] == "0.6.8"
    env = (up.stack_dir / ".env").read_text()
    assert "MTM_VERSION=0.6.9" in env and "POSTGRES_PASSWORD=tajne" in env
    assert (up.stack_dir / ".env.bak").read_text().count("MTM_VERSION=0.6.8") == 1
    if os.name != "nt":  # prawa i wlasciciel jak oryginal — .env.bak zawiera haslo do bazy
        for name in (".env", ".env.bak"):
            st = os.stat(up.stack_dir / name)
            assert st.st_mode & 0o777 == 0o600, name
            assert st.st_uid == os.getuid(), name
    ups = [c for c in docker.calls if "up" in c]
    assert ups and ups[0][-3:] == ["--no-deps", "backend", "wireguard"]  # bez updatera, postgresa, caddy
    assert not up._lock.locked()


def test_failed_pull_restores_env_and_touches_nothing(up, monkeypatch):
    docker = _Docker(up, pull_ok=False)
    state = _go(up, docker, monkeypatch)
    assert state["state"] == "failed" and "nic nie zmieniono" in state["error"]
    assert "MTM_VERSION=0.6.8" in (up.stack_dir / ".env").read_text()
    assert not any("up" in c for c in docker.calls)
    assert not up._lock.locked()


def test_wrong_image_after_up_is_failure(up, monkeypatch):
    docker = _Docker(up, image_tag="0.6.8")  # kontenery wstaly, ale na starym obrazie
    state = _go(up, docker, monkeypatch)
    assert state["state"] == "failed" and "nowej wersji" in state["error"]


@pytest.mark.parametrize("name,ok", [
    ("Europe/Warsaw", True), ("../../etc/passwd", False), ("Europe/Narnia", False), (None, False), (5, False),
])
def test_updater_zone_only_real_names(up, monkeypatch, name, ok):
    monkeypatch.setattr(up.os.path, "isfile", lambda p: p == "/usr/share/zoneinfo/Europe/Warsaw")
    monkeypatch.setattr(up.time, "tzset", lambda: None)
    monkeypatch.setenv("TZ", "UTC")
    assert up.apply_zone(name) is ok
    assert os.environ["TZ"] == ("Europe/Warsaw" if ok else "UTC")
