"""Zrzut stanu PRZED kazdym zapisem w module WireGuard/BTH.

To siatka na wypadek bledu, nie archiwum i nie zrodlo prawdy: portal nigdy z niej nie
czyta przy dzialaniu. Pozwala zobaczyc, co bylo przed zmiana, i odtworzyc to recznie.

* Bez kluczy prywatnych i PSK (decyzja uzytkownika). Klucze publiczne zostaja — nie sa
  tajne, a bez nich nie da sie jednoznacznie wskazac peera.
* Ląduje w istniejacym systemie kopii jako typ `wg-snapshot`: szyfrowanie Fernetem,
  pobieranie i obecnosc w kopii portalu dostajemy za darmo.
* Retencja czasowa, osobna od kopii urzadzen (te licza sie po typach export/binary,
  wiec zrzuty ich nie wypieraja). 30 dni: blad w polach client-* zwykle wychodzi dopiero,
  gdy klient probuje sie polaczyc po zmianie telefonu czy reinstalacji — tydzien byl
  za krotki. Dluzej nie ma sensu: po miesiacu router ma juz inna historie zmian.
"""
from __future__ import annotations

import datetime
import json
import uuid

from sqlalchemy import delete

from app.database import async_session
from app.models import Backup
from app.routerwg.model import Peer
from app.security import encrypt

SNAPSHOT_TYPE = "wg-snapshot"
RETENTION_DAYS = 30


def peer_record(p: Peer) -> dict:
    return {
        "id": p.id, "interface": p.interface, "name": p.name, "comment": p.comment,
        "public_key": p.public_key, "allowed_address": ",".join(p.allowed),
        "has_private_key": p.has_private_key, "has_preshared_key": bool(p.preshared_key),
        "disabled": p.disabled, "client_address": p.client_address, "client_dns": p.client_dns,
        "client_endpoint": p.client_endpoint, "client_keepalive": p.client_keepalive,
        "client_listen_port": p.client_listen_port, "client_allowed_address": p.client_allowed,
    }


def bth_user_record(u: dict) -> dict:
    """Uzytkownik BTH bez klucza prywatnego i bez tokenu dostepu do plikow."""
    return {k: v for k, v in u.items() if k not in ("private-key", "file-access-token")}


async def save(device_id: uuid.UUID, *, operation: str, scope: str, items: list[dict],
               extra: dict | None = None) -> uuid.UUID:
    payload = {
        "format": "mtm-wg-snapshot-1",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "operation": operation,
        "scope": scope,
        "items": items,
        **({"extra": extra} if extra else {}),
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    async with async_session() as s:
        b = Backup(
            device_id=device_id, backup_type=SNAPSHOT_TYPE,
            content_text_encrypted=encrypt(text), size_bytes=len(text.encode("utf-8")),
            status="success", note=operation[:240],
        )
        s.add(b)
        await s.commit()
        return b.id


async def purge_old() -> int:
    cutoff = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(days=RETENTION_DAYS)
    async with async_session() as s:
        result = await s.execute(
            delete(Backup).where(Backup.backup_type == SNAPSHOT_TYPE, Backup.created_at < cutoff)
        )
        await s.commit()
        return result.rowcount or 0
