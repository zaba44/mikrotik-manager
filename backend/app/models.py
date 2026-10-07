import datetime
import uuid

from sqlalchemy import BigInteger, ForeignKey, Identity, Text, func, UniqueConstraint
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Location(Base):
    __tablename__ = "locations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(unique=True)
    notes: Mapped[str | None]
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())

    devices: Mapped[list["Device"]] = relationship(back_populates="location")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(unique=True)
    location_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("locations.id"))

    wg_public_key: Mapped[str] = mapped_column(unique=True)
    wg_private_key_encrypted: Mapped[str]
    wg_preshared_key_encrypted: Mapped[str | None]
    wg_ip: Mapped[str] = mapped_column(INET, unique=True)

    api_username: Mapped[str | None]
    api_password_encrypted: Mapped[str | None]

    last_handshake_at: Mapped[datetime.datetime | None]
    wg_reachable: Mapped[bool | None]
    api_reachable: Mapped[bool | None]
    routeros_version: Mapped[str | None]
    routeros_uptime: Mapped[str | None]
    routeros_identity: Mapped[str | None]
    last_polled_at: Mapped[datetime.datetime | None]

    available_routeros_version: Mapped[str | None]
    # Sprzet: board_name (nazwa handlowa, np. „hAP ax^2") z /system/resource przy kazdym
    # odpytaniu; model (kod produktu, np. „C52iG-5HaxD2HaxD") i numer seryjny z
    # /system/routerboard przy sprawdzaniu aktualizacji; has_lte — czy jest modem LTE/5G
    # (None = jeszcze nie sprawdzano; /interface/lte bez modemu zwraca pusta liste).
    board_name: Mapped[str | None]
    model: Mapped[str | None]
    serial_number: Mapped[str | None]
    has_lte: Mapped[bool | None]
    current_firmware: Mapped[str | None]
    available_firmware: Mapped[str | None]
    routeros_winbox_port: Mapped[str | None]

    # Syslog: podpięcie urządzenia włącza warning/error/critical. `info` osobno, bo
    # generuje setki wpisów na dobę — trzymamy je na czas diagnostyki, nie na stałe.
    syslog_enabled: Mapped[bool] = mapped_column(default=False, server_default="false")
    syslog_info_enabled: Mapped[bool] = mapped_column(default=False, server_default="false")

    # Adres lokalny WSKAZANY RECZNIE. Zadnego zgadywania: przy switchu bez serwera DHCP,
    # przy kilku VLAN-ach albo przy bridge nazwanym po firmie kazda heurystyka predzej czy
    # pozniej klamie. Portal pokazuje pelna liste i zapamietuje to, co wybral czlowiek.
    #
    # Sledzenie zalezy od tego, czym adres jest na urzadzeniu:
    #  - dynamiczny -> tozsamoscia jest INTERFEJS (wartosc ma sie zmieniac, na tym polega),
    #  - statyczny   -> tozsamoscia jest para interfejs + adres.
    local_addr_interface: Mapped[str | None]
    local_addr_value: Mapped[str | None]
    local_addr_dynamic: Mapped[bool] = mapped_column(default=False, server_default="false")
    local_addr_note: Mapped[str | None]
    # Adres publiczny trzymamy w bazie, zeby tabela Status renderowala sie z bazy, bez
    # odpytywania routera przy kazdym wejsciu na strone.
    public_address: Mapped[str | None]
    public_behind_nat: Mapped[bool | None]
    # Ile portow PoE ma to urzadzenie. NULL = jeszcze nie wiemy, 0 = model bez PoE
    # (RouterOS odpowiada wtedy HTTP 400, nie pusta lista — sprawdzone na sprzecie).
    # Dzieki temu sekcja PoE nie zasmieca stron urzadzen, ktore jej nie potrzebuja.
    poe_port_count: Mapped[int | None]
    addr_checked_at: Mapped[datetime.datetime | None]

    notes: Mapped[str | None]
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    location: Mapped[Location | None] = relationship(back_populates="devices")


class PoeLockedPort(Base):
    """Port PoE oznaczony jako UPLINK — portal odmawia jego wylaczenia i restartu.

    Jedyne realne ryzyko przy sterowaniu PoE to odciecie zasilania urzadzeniu, przez
    ktore sie do niego idzie (switch zasilany PoE z innego switcha). Blokada jest
    egzekwowana PO STRONIE SERWERA, nie tylko w interfejsie — inaczej byloby to
    zabezpieczenie na oko."""

    __tablename__ = "poe_locked_ports"
    __table_args__ = (UniqueConstraint("device_id", "interface", name="uq_poe_lock_device_iface"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    interface: Mapped[str]
    note: Mapped[str | None]
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class DeviceLogEntry(Base):
    """Wpis syslog przysłany PRZEZ urządzenie (push, UDP przez tunel). Portal nie
    odpytuje routerów o logi — przy 200–300 urządzeniach pobieranie całego bufora
    w kółko byłoby nie do utrzymania (RouterOS nie umie filtrować ani wydać „tylko
    nowe od czasu X" — sprawdzone empirycznie).

    `id` jest BigInteger, nie UUID: wpisów będą miliony, a rosnący klucz daje zwarty
    indeks i tanie kasowanie retencyjne po czasie."""

    __tablename__ = "device_log_entries"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    received_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    level: Mapped[str]  # warning|error|critical|info — wyłuskane z topics
    topics: Mapped[str]  # pełna lista RouterOS, np. "dhcp,warning"
    message: Mapped[str] = mapped_column(Text)

    device: Mapped["Device"] = relationship()


class Notification(Base):
    """Dziennik powiadomień — wysłanych ORAZ wyciszonych, z powodem.

    Trwały, bo trzy bezpieczniki antyspamowe (limit na urządzenie/godzinę, globalny
    sufit, wyciszanie powtórek) liczone w pamięci resetowałyby się przy restarcie
    backendu, czyli dokładnie wtedy, gdy coś się sypie. Przy okazji daje wgląd w to,
    co portal wysłał i czego świadomie nie wysłał."""

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    event_key: Mapped[str]        # np. "syslog.error", "device.offline", "portal.login"
    dedup_key: Mapped[str]        # to samo zdarzenie z tego samego źródła
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    subject: Mapped[str]
    status: Mapped[str]           # sent | suppressed | failed
    reason: Mapped[str | None]
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class NotificationOverride(Base):
    """Nadpisanie powiadomień dla lokalizacji albo urządzenia.

    Jeden wiersz na zakres. `mode="muted"` = cisza (z opcjonalnym terminem; NULL
    oznacza bezterminowo i jest wyróżniane w panelu, bo to najczęstsza droga do
    „zapomniałem, że to wyciszyłem"). `mode="custom"` = ZASTĘPUJE poziom wyższy
    listą typów w `event_keys`, a nie dokleja się do niego — dzięki temu patrząc na
    urządzenie widzisz komplet, bez sprawdzania, co jeszcze obowiązuje wyżej."""

    __tablename__ = "notification_overrides"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_type: Mapped[str]   # device | location
    scope_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    mode: Mapped[str]         # muted | custom
    event_keys: Mapped[str | None]
    muted_until: Mapped[datetime.datetime | None]
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class UpdateRun(Base):
    __tablename__ = "update_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope: Mapped[str]  # "device" | "location"
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id"))
    location_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("locations.id"))
    status: Mapped[str] = mapped_column(default="running")  # running|succeeded|failed|aborted
    started_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    finished_at: Mapped[datetime.datetime | None]
    error_message: Mapped[str | None]

    steps: Mapped[list["UpdateRunStep"]] = relationship(back_populates="run", order_by="UpdateRunStep.started_at")


class UpdateRunStep(Base):
    __tablename__ = "update_run_steps"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("update_runs.id"))
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id"))
    step_type: Mapped[str]  # software|firmware|reboot|wait_online
    status: Mapped[str] = mapped_column(default="running")  # running|succeeded|failed
    started_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    finished_at: Mapped[datetime.datetime | None]
    detail: Mapped[str | None]

    run: Mapped[UpdateRun] = relationship(back_populates="steps")
    device: Mapped[Device] = relationship()


class Backup(Base):
    __tablename__ = "backups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id"))
    backup_type: Mapped[str]  # export | binary | wg-snapshot (zrzut przed zapisem w module WireGuard/BTH)
    content_text_encrypted: Mapped[str | None]  # export: zaszyfrowany tekst wprost w DB
    file_path: Mapped[str | None]  # binary: ścieżka do zaszyfrowanego pliku na wolumenie
    size_bytes: Mapped[int | None]
    status: Mapped[str]  # success | failed
    error_message: Mapped[str | None]
    # Opis zrzutu: przed jaka zmiana powstal (np. „dodanie 5 peerow na WG_BIURO").
    note: Mapped[str | None]
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())

    device: Mapped[Device] = relationship()


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(primary_key=True)
    value: Mapped[str]


class AdminPeer(Base):
    """Peer WireGuard dla komputera administracyjnego (nie MikroTik) — dostaje config
    klienta z AllowedIPs = cała podsieć, żeby widzieć wszystkie urządzenia przez tunel.
    Adres z końca puli WG (schodząc od góry). Status = świeżość handshake WG, jak przy
    urządzeniach."""

    __tablename__ = "admin_peers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(unique=True)
    wg_public_key: Mapped[str] = mapped_column(unique=True)
    wg_private_key_encrypted: Mapped[str]
    wg_preshared_key_encrypted: Mapped[str | None]
    wg_ip: Mapped[str] = mapped_column(INET, unique=True)

    last_handshake_at: Mapped[datetime.datetime | None]
    wg_reachable: Mapped[bool | None]
    last_polled_at: Mapped[datetime.datetime | None]

    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class PingTarget(Base):
    """Adres IP/host do testów sieci per urządzenie — pingowany z tego MikroTika przez
    REST. Do diagnozy sprzętu (też nie-MikroTikowego) w sieci routera."""

    __tablename__ = "device_ping_targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("devices.id"))
    ip: Mapped[str]
    label: Mapped[str | None]
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(unique=True)
    password_hash: Mapped[str]
    role: Mapped[str] = mapped_column(default="operator")
    # Dotyczy operatorów: True = tylko podgląd statusów (read-only); False = może też
    # wykonywać akcje operacyjne (aktualizacja/restart/sprawdzanie) na swoich urządzeniach.
    status_only: Mapped[bool] = mapped_column(default=True, server_default="true")
    location_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("locations.id"))
    created_at: Mapped[datetime.datetime] = mapped_column(server_default=func.now())

    location: Mapped[Location | None] = relationship()
