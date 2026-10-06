"""Odbiornik syslog (UDP) dla floty — urządzenia PUSHUJĄ wpisy przez tunel.

Dlaczego push, a nie odpytywanie: RouterOS nie potrafi filtrować `/rest/log` po
stronie routera (`?topics=error` zwraca pustkę mimo istniejących wpisów) ani wydać
„tylko nowe od czasu X" — przy 200–300 urządzeniach trzeba by w kółko ściągać cały
1000-elementowy bufor i odsiewać duplikaty. Push oddaje zdarzenie raz, w momencie
powstania. Filtrowanie robi samo urządzenie (reguły `topics=` w `/system logging`),
więc przez tunel leci wyłącznie to, co nas interesuje.

Format ramki: `remote-log-format=default`, czyli `"<topics> <wiadomość>"`, np.
`dhcp,warning DHCP_SERVER lease limit reached`. Świadomie NIE używamy formatu
`syslog` (RFC3164) — daje czas i priorytet, ale GUBI topiki, a to one niosą podsystem
(dhcp/interface/script). Wszystko, co tamten format dokłada, i tak mamy: urządzenie
z adresu źródłowego, czas z chwili odbioru (przy pushu to milisekundy różnicy),
a poziom siedzi w topikach jako jeden z tokenów.

Osiągalny wyłącznie przez `wg-mt` (DNAT w kontenerze wireguard, port nigdzie nie
publikowany na hosta) — ta sama zasada co przy odbiorze kopii zapasowych.
"""
import asyncio
import ipaddress
import logging

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.database import async_session
from app.log_store import enforce_device_cap
from app.models import Device, DeviceLogEntry
from app.notifications import notify
from app.settings_store import get_int_setting, get_setting

logger = logging.getLogger(__name__)

# Kolejność ma znaczenie: `critical` przed `error`, bo RouterOS potrafi wysłać
# oba topiki naraz i chcemy zapisać ten poważniejszy.
_LEVELS = ("critical", "error", "warning", "info", "debug")

# Zapisujemy paczkami: przy fladze `info` na kilkuset urządzeniach pojedynczy
# INSERT na wpis zarżnąłby bazę. Bufor jest opróżniany co _FLUSH_SECONDS albo
# po uzbieraniu _FLUSH_MAX wpisów — co nastąpi wcześniej.
_FLUSH_SECONDS = 2.0
_FLUSH_MAX = 200
# Zabezpieczenie przed zalaniem pamięci, gdy baza przestanie przyjmować zapisy.
_QUEUE_MAX = 20000
# Jak czesto odswiezamy globalny przelacznik i limit z bazy (sekundy).
_CONFIG_TTL = 5.0
# Po ilu wpisach z jednego urzadzenia sprawdzamy jego limit.
_TRIM_EVERY = 200
# Mapa adres -> urzadzenie: odswiezana co _IP_MAP_TTL sekund i od reki po zmianach
# urzadzen (invalidate_device_map). Nieznany nadawca wymusza odswiezenie, ale nie
# czesciej niz co _UNKNOWN_REFRESH sekund — zalew z obcego adresu nie moze zamienic sie
# w zapytanie do bazy na kazdy pakiet.
_IP_MAP_TTL = 30.0
_UNKNOWN_REFRESH = 5.0


def parse_frame(data: bytes) -> tuple[str, str, str] | None:
    """`b"dhcp,warning DHCP_SERVER ..."` -> ("warning", "dhcp,warning", "DHCP_SERVER ...").

    RouterOS potrafi wstawić bajty spoza UTF-8 (potwierdzone: 0xea = 'ę' w cp1250
    w logu MIECIA), dlatego dekodujemy tolerancyjnie zamiast odrzucać ramkę."""
    text = data.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    topics, _, message = text.partition(" ")
    if not message:
        # Ramka bez spacji — nie znamy topików, ratujemy samą treść.
        return ("info", "", topics)
    tokens = {t.strip() for t in topics.split(",")}
    level = next((lv for lv in _LEVELS if lv in tokens), "info")
    return (level, topics, message)


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue):
        self._queue = queue

    def datagram_received(self, data: bytes, addr) -> None:
        parsed = parse_frame(data)
        if parsed is None:
            return
        level, topics, message = parsed
        try:
            self._queue.put_nowait((addr[0], level, topics, message))
        except asyncio.QueueFull:
            logger.warning("Kolejka syslog pełna — odrzucam wpis z %s", addr[0])


class SyslogReceiver:
    def __init__(self, port: int):
        self.port = port
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAX)
        self._transport = None
        self._task: asyncio.Task | None = None
        # wg_ip -> device_id. Dawniej odswiezane TYLKO dla nieznanego nadawcy, wiec po
        # usunieciu urzadzenia A i nadaniu jego adresu urzadzeniu B adres byl dalej „znany"
        # i wpisy szly na A — konczac sie bledem klucza obcego i utrata calej paczki
        # (wytkniete w drugiej recenzji).
        self._ip_map: dict[str, object] = {}
        self._ip_map_at = 0.0
        self._ip_map_stale = False
        self._enabled = False       # globalny przelacznik z ustawien
        self._cap = 0               # limit wpisow na urzadzenie
        self._config_at = 0.0
        self._since_trim: dict = {}  # ile wpisow od ostatniego przyciecia, per urzadzenie

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(self._queue), local_addr=("0.0.0.0", self.port)
        )
        self._task = asyncio.create_task(self._consume())
        logger.info("Odbiornik syslog nasłuchuje na UDP %s", self.port)

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()
        if self._task:
            self._task.cancel()

    def invalidate(self) -> None:
        self._ip_map_stale = True

    async def _refresh_ip_map(self) -> None:
        async with async_session() as session:
            rows = (await session.execute(select(Device.id, Device.wg_ip))).all()
        self._ip_map = {str(ip): dev_id for dev_id, ip in rows}
        self._ip_map_at = asyncio.get_running_loop().time()
        self._ip_map_stale = False

    async def _resolve(self, ip: str):
        """Urządzenie rozpoznajemy po adresie źródłowym — DNAT nie robi SNAT, więc
        adres zostaje adresem routera w tunelu (ten sam trik co przy kopiach SFTP)."""
        age = asyncio.get_running_loop().time() - self._ip_map_at
        if (self._ip_map_stale or age > _IP_MAP_TTL
                or (ip not in self._ip_map and age > _UNKNOWN_REFRESH)):
            await self._refresh_ip_map()
        return self._ip_map.get(ip)

    async def _store(self, batch: list[DeviceLogEntry]) -> None:
        """Zapis paczki. Gdy urzadzenie zniknelo miedzy rozpoznaniem a zapisem (klucz obcy),
        odswiezamy mape i zapisujemy reszte — jeden usuniety router nie moze zabrac ze soba
        wpisow calej floty z tej samej paczki. Ponawiany jest wylacznie INSERT (wycofany
        w calosci), zgloszenia ida dopiero po udanym zapisie — nic sie nie zdubluje."""
        try:
            await self._insert(batch)
        except IntegrityError:
            await self._refresh_ip_map()
            known = set(self._ip_map.values())
            for device_id in [d for d in self._since_trim if d not in known]:
                del self._since_trim[device_id]
            rest = [DeviceLogEntry(device_id=e.device_id, level=e.level, topics=e.topics, message=e.message)
                    for e in batch if e.device_id in known]
            logger.info("Syslog: %d wpisów usuniętego urządzenia odrzucone, zapisuję %d",
                        len(batch) - len(rest), len(rest))
            if not rest:
                return
            await self._insert(rest)
            batch = rest
        await self._after_insert(batch)

    @staticmethod
    async def _insert(batch: list[DeviceLogEntry]) -> None:
        async with async_session() as session:
            session.add_all(batch)
            await session.commit()

    async def _after_insert(self, batch: list[DeviceLogEntry]) -> None:
        alerts = [e for e in batch if e.level in ("error", "critical", "warning")]
        async with async_session() as session:
            # Zgłoszenia po zapisie — dedup w notify() i tak scala powtórki,
            # więc przy zalewie nie zamieni się to w lawinę maili.
            for entry in alerts[:20]:
                await notify(
                    session,
                    event_key=f"syslog.{'warning' if entry.level == 'warning' else 'error'}",
                    device_id=entry.device_id,
                    dedup_key=f"syslog:{entry.device_id}:{entry.topics}",
                    subject=f"[MTM] {entry.level}: {entry.topics}",
                    body=(f"Zdarzenie z urządzenia.\n\nPoziom: {entry.level}\n"
                          f"Topiki: {entry.topics}\n\n{entry.message}"),
                )
            # Limit egzekwujemy dopiero po _TRIM_EVERY wpisach z danego
            # urządzenia — przycinanie po każdej paczce byłoby marnotrawstwem.
            for device_id, count in list(self._since_trim.items()):
                if count >= _TRIM_EVERY:
                    await enforce_device_cap(session, device_id, self._cap)
                    self._since_trim[device_id] = 0

    async def _refresh_config(self) -> None:
        """Globalny przełącznik i limit czytamy z bazy co kilka sekund, nie przy każdym
        pakiecie — przy zalewie zapytanie na pakiet byłoby gorsze niż sam zalew."""
        async with async_session() as session:
            self._enabled = (await get_setting(session, "syslog_enabled")) == "1"
            self._cap = await get_int_setting(session, "syslog_max_entries_per_device")
        self._config_at = asyncio.get_running_loop().time()

    async def _consume(self) -> None:
        await self._refresh_ip_map()
        await self._refresh_config()
        batch: list[DeviceLogEntry] = []
        while True:
            try:
                if asyncio.get_running_loop().time() - self._config_at > _CONFIG_TTL:
                    await self._refresh_config()

                try:
                    item = await asyncio.wait_for(self._queue.get(), timeout=_FLUSH_SECONDS)
                    ip, level, topics, message = item
                    if not self._enabled:
                        # Globalny przełącznik wyłączony: odrzucamy natychmiast.
                        # Routery mogą dalej wysyłać (świadomie ich nie przekonfigurowujemy
                        # przy wyłączaniu) — po prostu nic z tym nie robimy.
                        continue
                    device_id = await self._resolve(ip)
                    if device_id is None:
                        logger.debug("Syslog z nieznanego adresu %s — pomijam", ip)
                    else:
                        batch.append(DeviceLogEntry(
                            device_id=device_id, level=level,
                            topics=topics[:255], message=message[:8000],
                        ))
                        self._since_trim[device_id] = self._since_trim.get(device_id, 0) + 1
                except asyncio.TimeoutError:
                    pass

                if batch and (len(batch) >= _FLUSH_MAX or self._queue.empty()):
                    await self._store(batch)
                    batch = []
            except asyncio.CancelledError:
                raise
            except Exception as e:  # zapis nie może ubić odbiornika
                logger.warning("Zapis wpisów syslog nie powiódł się: %s", e)
                batch = []


receiver: SyslogReceiver | None = None


async def start_receiver() -> None:
    global receiver
    if receiver is not None:
        return
    receiver = SyslogReceiver(settings.syslog_port)
    await receiver.start()


async def stop_receiver() -> None:
    global receiver
    if receiver is not None:
        await receiver.stop()
        receiver = None


def is_valid_wg_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def invalidate_device_map() -> None:
    """Wolane po dodaniu i usunieciu urzadzenia — odbiornik odswiezy mape przy nastepnym
    pakiecie zamiast czekac na _IP_MAP_TTL."""
    if receiver is not None:
        receiver.invalidate()
