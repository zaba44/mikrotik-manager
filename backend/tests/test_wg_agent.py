"""Agent WireGuard (infra/wireguard/agent.py) — trwalosc konfiguracji peerow.

Agent to osobny skrypt w kontenerze wireguard; tu ladujemy go jako modul i podmieniamy
`wg`/`wg-quick` atrapa, ktora trzyma stan interfejsu w pamieci. Sprawdzamy plik
konfiguracyjny na dysku — to on decyduje, co hub zna po restarcie kontenera."""
import importlib.util
import os
import threading

import pytest

AGENT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                          "infra", "wireguard", "agent.py")
pytestmark = pytest.mark.skipif(not os.path.exists(AGENT_PATH), reason="brak infra/wireguard/agent.py")


class _FakeWg:
    """Interfejs wg-mt w pamieci: `wg set ... peer`, `wg show dump`, `wg-quick up/down`."""

    def __init__(self):
        self.up = True
        self.peers: dict[str, str] = {}
        self.commands: list[list[str]] = []

    def run(self, cmd, check=True):
        self.commands.append(cmd)
        if cmd[:2] == ["wg", "set"]:
            pk = cmd[4]
            if cmd[5] == "remove":
                self.peers.pop(pk, None)
            else:
                self.peers[pk] = cmd[6]
            return ""
        if cmd[:3] == ["wg", "show", "wg-mt"] and cmd[3] == "dump":
            rows = ["priv\tpub\t51820\toff"]
            rows += [f"{pk}\t(none)\t(none)\t{ip}\t0\t0\t0\toff" for pk, ip in self.peers.items()]
            return "\n".join(rows) + "\n"
        if cmd[:2] == ["wg-quick", "down"]:
            self.up = False
            self.peers.clear()
        return ""


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv("WG_AGENT_TOKEN", "test")
    monkeypatch.setenv("WG_INTERFACE", "wg-mt")
    spec = importlib.util.spec_from_file_location("wg_agent_under_test", AGENT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "CONF_FILE", str(tmp_path / "wg-mt.conf"))
    monkeypatch.setattr(mod, "KEY_FILE", str(tmp_path / "wg-mt.key"))
    monkeypatch.setattr(mod, "CONF_DIR", str(tmp_path))
    fake = _FakeWg()
    monkeypatch.setattr(mod, "run", fake.run)
    monkeypatch.setattr(mod, "interface_up", lambda: fake.up)
    monkeypatch.setattr(mod, "public_key", lambda: "PUB" if fake.up else None)

    def fake_bring_up():
        fake.up = True
    monkeypatch.setattr(mod, "bring_up", fake_bring_up)
    (tmp_path / "wg-mt.conf").write_text("[Interface]\nAddress = 10.9.0.1/24\nListenPort = 51820\nPrivateKey = K\n")
    (tmp_path / "wg-mt.key").write_text("K")
    mod.fake = fake
    return mod


def _conf(agent):
    return open(agent.CONF_FILE).read()


def test_failed_save_rolls_peer_back_from_interface(agent, monkeypatch):
    """Zapis na dysk zawiodl: peer NIE moze zostac w dzialajacym interfejsie (dzialalby do
    restartu, a portal uznalby go za zalatwionego)."""
    def broken_write(content):
        raise OSError("dysk pelny")
    monkeypatch.setattr(agent, "_write_conf", broken_write)
    with pytest.raises(OSError):
        agent.add_peer("PEER1", "10.9.0.2")
    assert "PEER1" not in agent.fake.peers


def test_peers_report_whether_saved(agent):
    agent.add_peer("ZAPISANY", "10.9.0.2")
    agent.fake.peers["TYLKO-W-PAMIECI"] = "10.9.0.3/32"
    state = {p["public_key"]: p["persisted"] for p in agent.get_peers()}
    assert state == {"ZAPISANY": True, "TYLKO-W-PAMIECI": False}


def test_rebuilding_interface_keeps_saved_peers(agent):
    """Dawniej setup_interface przepisywal plik samym [Interface] — kazda przebudowa
    kasowala z dysku cala flote."""
    agent.add_peer("A", "10.9.0.2", "PSK-A")
    agent.add_peer("B", "10.9.0.3")
    agent.setup_interface("10.9.0.0/24", "10.9.0.1", "NOWY-KLUCZ")
    conf = _conf(agent)
    assert conf.startswith("[Interface]") and "PrivateKey = NOWY-KLUCZ" in conf
    assert agent.persisted_keys() == {"A", "B"}
    assert "PresharedKey = PSK-A" in conf and "AllowedIPs = 10.9.0.3/32" in conf


def test_remove_then_rebuild_does_not_resurrect(agent):
    agent.add_peer("A", "10.9.0.2")
    agent.add_peer("B", "10.9.0.3")
    agent.remove_peer("A")
    agent.setup_interface("10.9.0.0/24", "10.9.0.1", None)
    assert agent.persisted_keys() == {"B"}


def test_parallel_adds_lose_nothing(agent):
    """Serwer agenta jest wielowatkowy; zapis to odczyt-zmiana-zapis pliku."""
    threads = [threading.Thread(target=agent.add_peer, args=(f"P{i}", f"10.9.0.{i + 2}")) for i in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert agent.persisted_keys() == {f"P{i}" for i in range(30)}


def test_interrupted_write_keeps_old_file(agent, monkeypatch):
    agent.add_peer("A", "10.9.0.2")
    before = _conf(agent)

    def broken_replace(src, dst):
        raise OSError("przerwane")
    with monkeypatch.context() as m:
        m.setattr(agent.os, "replace", broken_replace)
        with pytest.raises(OSError):
            agent.add_peer("B", "10.9.0.3")
    assert _conf(agent) == before
    assert "B" not in agent.fake.peers


def test_masquerade_skips_tunnel_traffic(agent, monkeypatch):
    """Ruch peer -> hub -> peer nie jest maskowany (Winbox z peera admina ma dotrzec z jego
    adresem), a stara regula „maskuj wszystko" z poprzedniej wersji znika."""
    calls = []
    existing = "-P POSTROUTING ACCEPT\n-A POSTROUTING -o wg-mt -j MASQUERADE\n" \
               "-A POSTROUTING -d 172.22.0.3/32 -p tcp -m tcp --dport 8443 -j MASQUERADE\n"

    def fake_run(cmd, check=True):
        calls.append(cmd)
        if cmd[:3] == ["ip", "-4", "-o"]:
            return "5: wg-mt    inet 10.77.0.1/22 scope global wg-mt\\       valid_lft forever\n"
        if cmd[-2:] == ["-S", "POSTROUTING"]:
            return existing
        return ""
    monkeypatch.setattr(agent, "run", fake_run)
    monkeypatch.setattr(agent.socket, "gethostbyname", lambda name: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr("time.sleep", lambda s: None)
    agent._ensure_nat_dnat()
    assert ["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "wg-mt", "-j", "MASQUERADE"] in calls
    assert ["iptables", "-t", "nat", "-A", "POSTROUTING", "!", "-s", "10.77.0.0/22",
            "-o", "wg-mt", "-j", "MASQUERADE"] in calls
    # regula panelu (Caddy) nietknieta
    assert not any(c[:5] == ["iptables", "-t", "nat", "-D", "POSTROUTING"] and "8443" in c for c in calls)


def test_masquerade_without_subnet_falls_back(agent, monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "run", lambda cmd, check=True: calls.append(cmd) or "")
    monkeypatch.setattr(agent.socket, "gethostbyname", lambda name: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr("time.sleep", lambda s: None)
    agent._ensure_nat_dnat()
    assert ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "wg-mt", "-j", "MASQUERADE"] in calls
