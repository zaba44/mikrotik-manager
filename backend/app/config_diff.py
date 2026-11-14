"""Porownanie dwoch eksportow konfiguracji (`/export`) tego samego routera: co sie zmienilo
miedzy kopiami. Porownujemy surowy tekst, a POKAZUJEMY z ukrytymi sekretami — eksport jest
`show-sensitive`, wiec zawiera hasla, a strona roznic bywa ogladana przy kims."""
import difflib
import re
from dataclasses import dataclass

# Pierwsza linia eksportu to data i wersja („# 2026-10-12 15:05:32 by RouterOS 7.24.5") —
# rozni sie w kazdej kopii i nic nie mowi o konfiguracji.
_HEADER = re.compile(r"^# (\d{4}-\d\d-\d\d|[a-z]{3}/\d\d/\d{4}) \d\d:\d\d:\d\d by RouterOS", re.I)
_SECRET = re.compile(
    r'((?:password|passphrase|secret|private-key|preshared-key|pre-shared-key|wpa-pre-shared-key|'
    r'authentication-password|encryption-password|key)=)("(?:[^"\\]|\\.)*"|\S+)', re.I)
MASK = "•••"


@dataclass
class Row:
    kind: str  # add | del | ctx | hunk
    text: str
    secret_changed: bool = False


def _clean(text: str) -> list[str]:
    return [line for line in text.replace("\r\n", "\n").split("\n") if not _HEADER.match(line)]


def mask(line: str) -> str:
    return _SECRET.sub(lambda m: m.group(1) + MASK, line)


def diff(old: str, new: str, context: int = 3) -> list[Row]:
    """Wiersze do wyswietlenia; pusta lista = konfiguracje identyczne (poza naglowkiem)."""
    rows: list[Row] = []
    for line in difflib.unified_diff(_clean(old), _clean(new), lineterm="", n=context):
        if line.startswith(("---", "+++")):
            continue
        if line.startswith("@@"):
            rows.append(Row("hunk", line))
        elif line.startswith("+"):
            rows.append(Row("add", mask(line[1:])))
        elif line.startswith("-"):
            rows.append(Row("del", mask(line[1:])))
        else:
            rows.append(Row("ctx", mask(line[1:])))
    # Zmiana samego hasla: po ukryciu linie „-" i „+" wygladaja identycznie — oznaczamy to,
    # zamiast pokazywac dwie takie same linie bez wyjasnienia.
    for a, b in zip(rows, rows[1:]):
        if a.kind == "del" and b.kind == "add" and a.text == b.text and MASK in a.text:
            a.secret_changed = b.secret_changed = True
    return rows


def stats(rows: list[Row]) -> tuple[int, int]:
    return sum(1 for r in rows if r.kind == "add"), sum(1 for r in rows if r.kind == "del")
