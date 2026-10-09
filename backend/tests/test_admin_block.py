"""Blok administracyjny: wyliczenie bloku, przydzial adresow (zwykle urzadzenia nigdy
w bloku, administracyjne tylko w bloku), walidacja zmiany wielkosci, skrypt Winboxa."""
import asyncio
import ipaddress
import types

import pytest

from app import admin_block, security
from app.models import AdminPeer, Device, Setting


class _Res:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows

    def scalars(self):
        return self

    def __iter__(self):
        return iter(self._rows)


class _Session:
    """Atrapa: urzadzenia i peery w pamieci, ustawienia jako slownik."""

    def __init__(self, devices=(), peers=(), prefix=None):
        self.devices = [types.SimpleNamespace(id=n, name=n, wg_ip=ip) for n, ip in devices]
        self.peers = [types.SimpleNamespace(id=n, name=n, wg_ip=ip) for n, ip in peers]
        self.settings = {} if prefix is None else {admin_block.SETTING_KEY: str(prefix)}

    async def execute(self, stmt, *a, **kw):
        sql = str(stmt)
        if "advisory" in sql:
            return _Res([])
        table = self.peers if "admin_peers" in sql else self.devices
        if "wg_ip" in sql and "SELECT" in sql and sql.split("FROM")[0].count(",") == 0:
            return _Res([(x.wg_ip,) for x in table])  # select(Model.wg_ip)
        return _Res(list(table))

    async def get(self, model, key):
        if model is Setting and key in self.settings:
            return types.SimpleNamespace(value=self.settings[key])
        return None

    def add(self, obj):
        self.settings[obj.key] = obj.value

    async def commit(self):
        pass


@pytest.fixture(autouse=True)
def _wg(monkeypatch):
    monkeypatch.setattr(admin_block.wg, "subnet", "10.77.0.0/22")
    monkeypatch.setattr(admin_block.wg, "server_ip", "10.77.0.1")


def run(coro):
    return asyncio.run(coro)


def test_block_is_end_of_subnet():
    assert str(admin_block.block_for("10.77.0.0/22", 27)) == "10.77.3.224/27"
    assert str(admin_block.block_for("10.77.0.0/24", 28)) == "10.77.0.240/28"
    assert admin_block.default_prefix("10.77.0.0/22") == 27
    assert admin_block.default_prefix("10.0.0.0/26") == 28   # mala podsiec: cwierc
    assert admin_block.usable("10.77.0.0/22", 27) == 31       # bez rozgloszeniowego
    assert admin_block.choices("10.77.0.0/24") == [30, 29, 28, 27, 26, 25]


def test_unknown_or_foreign_setting_falls_back_to_default():
    assert run(admin_block.get_prefix(_Session(prefix=99))) == 27
    assert run(admin_block.get_prefix(_Session(prefix=26))) == 26


def test_regular_device_never_gets_block_address(monkeypatch):
    monkeypatch.setattr(admin_block.wg, "subnet", "10.0.0.0/27")
    monkeypatch.setattr(admin_block.wg, "server_ip", "10.0.0.1")
    # /27, blok /29 = .24-.31; wszystko ponizej zajete
    s = _Session(devices=[(f"d{i}", f"10.0.0.{i}") for i in range(2, 24)])
    with pytest.raises(RuntimeError):
        run(security.allocate_ip(s))
    s.devices.pop()  # zwolnione .23
    assert run(security.allocate_ip(s)) == "10.0.0.23"


def test_admin_addresses_from_top_of_block_and_full_block_refused(monkeypatch):
    s = _Session(peers=[("laptop", "10.77.3.254")], prefix=30)  # blok .252/30: .252 .253 .254
    assert run(security.allocate_admin_ip(s)) == "10.77.3.253"
    s.peers.append(types.SimpleNamespace(id="b", name="b", wg_ip="10.77.3.253"))
    s.devices.append(types.SimpleNamespace(id="biuro", name="biuro", wg_ip="10.77.3.252"))
    with pytest.raises(security.AdminBlockFull):
        run(security.allocate_admin_ip(s))   # NIE schodzi ponizej bloku


def test_shrinking_block_refused_when_admin_falls_out():
    s = _Session(peers=[("laptop", "10.77.3.254"), ("stary", "10.77.3.230")])
    problem = run(admin_block.change_problem(s, 28))
    assert problem and "stary" in problem
    assert run(admin_block.change_problem(s, 27)) is None


def test_growing_block_refused_over_regular_device():
    s = _Session(devices=[("klient", "10.77.3.200")], peers=[("laptop", "10.77.3.254")])
    problem = run(admin_block.change_problem(s, 26))
    assert problem and "klient" in problem
    assert run(admin_block.change_problem(s, 28)) is None


def test_block_may_not_cover_hub(monkeypatch):
    monkeypatch.setattr(admin_block.wg, "server_ip", "10.77.3.250")
    assert "huba" in run(admin_block.change_problem(_Session(), 27))


def test_admin_device_counted_as_member_and_kept_on_shrink():
    s = _Session(devices=[("klient", "10.77.0.2"), ("biuro", "10.77.3.240")])
    peers, devices = run(admin_block.members(s, ipaddress.ip_network("10.77.3.224/27")))
    assert [d.name for d in devices] == ["biuro"]
    assert "biuro" in run(admin_block.change_problem(s, 29))


def test_winbox_script_is_universal_and_cleans_old_entries():
    script = admin_block.winbox_script("10.77.3.224/27")
    assert script.startswith("{\n") and script.endswith("}\n")
    assert ':local adm "10.77.3.224/27"' in script
    assert 'comment~"^MTM admin: "' in script                 # dawne wpisy pojedynczych peerow
    assert "address] != $adm" in script                         # wpis bloku po zmianie wielkosci
    assert "find name=winbox" in script and '"connection") != true' in script
    assert '"dynamic") != true' in script                       # gora listy pod regula fasttracka
    assert "drop" not in script                                 # miejsce NIE wg pierwszego dropa
    assert script.count("{") == script.count("}")


def test_winbox_port_ignores_connection_entries(monkeypatch):
    """Od 7.23 /ip service ma dynamiczne wpisy polaczen — portal bral port z pierwszego."""
    from app import routeros_client
    services = [{"name": "winbox", "port": "51234", "connection": "true", "dynamic": "true"},
                {"name": "winbox", "port": "56614", "dynamic": "false"}]

    class _Resp:
        def __init__(self, data):
            self._data = data

        def raise_for_status(self):
            pass

        def json(self):
            return self._data

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, *a, **kw):
            if url.endswith("/ip/service"):
                return _Resp(services)
            return _Resp({"version": "7.24.5", "uptime": "1d", "name": "r"})

    monkeypatch.setattr(routeros_client.httpx, "AsyncClient", _Client)
    device = types.SimpleNamespace(wg_ip="10.77.0.7", api_username="u", api_password_encrypted="x")
    monkeypatch.setattr(routeros_client, "_auth", lambda d: None)
    status = run(routeros_client.get_status(device))
    assert status["winbox_port"] == "56614"
