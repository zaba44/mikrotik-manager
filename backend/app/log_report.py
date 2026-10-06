"""Raport zdarzeń na żądanie — jednorazowy odczyt logów z urządzeń, bez włączania
syslogu i bez zapisywania czegokolwiek u nas. Uzupełnia push: syslog łapie zdarzenia
od chwili podłączenia, raport sięga wstecz w bufor routera (zmierzone: 3–5 dni).

Wynik to zwykły plik tekstowy do przejrzenia — świadomie nie CSV, bo wiadomości
RouterOS same zawierają przecinki i cytowanie robiłoby się nieczytelne.
"""
import datetime

from app.filenames import ascii_part
from app.filenames import content_disposition as _cd
from app.models import Device
from app.routeros_client import REPORT_LEVELS, fetch_log

_HEADER_WIDTH = 78


def _format_section(device: Device, result: dict) -> list[str]:
    title = f"{device.name}  ({device.wg_ip})"
    lines = ["=" * _HEADER_WIDTH, title, "=" * _HEADER_WIDTH]

    if not result.get("ok"):
        lines += [f"  BŁĄD ODCZYTU: {result.get('error')}", ""]
        return lines

    entries, total = result["entries"], result["total_in_buffer"]
    lines.append(f"  {len(entries)} zdarzeń z {total} wpisów w buforze routera")
    if not entries:
        lines += ["  (brak ostrzeżeń i błędów — na spokojnym urządzeniu to normalne)", ""]
        return lines

    lines.append("")
    for e in entries:
        lines.append(f"  {e['time']:20s} [{e['level']:8s}] {e['topics']:22s} {e['message']}")
    lines.append("")
    return lines


async def build_report(devices: list[Device], *, scope_name: str, levels=REPORT_LEVELS) -> str:
    """Urządzenia odpytywane po kolei — przy lokalizacji z kilkunastoma routerami
    równoległy odczyt całych buforów byłby niepotrzebnym uderzeniem w tunel."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = [
        "MikroTik Manager — raport zdarzeń",
        f"Zakres:   {scope_name}",
        f"Pobrano:  {now}",
        f"Poziomy:  {', '.join(levels)}",
        f"Urządzeń: {len(devices)}",
        "",
        "Uwaga: to jednorazowy odczyt bufora logów routera (kilka dni wstecz).",
        "Portal nie przechowuje tych danych — plik powstaje w chwili pobrania.",
        "",
    ]

    total_hits, failed = 0, 0
    sections: list[str] = []
    for device in devices:
        result = await fetch_log(device, levels)
        if result.get("ok"):
            total_hits += len(result["entries"])
        else:
            failed += 1
        sections += _format_section(device, result)

    out.insert(5, f"Zdarzeń:  {total_hits}" + (f"  (nieosiągalnych urządzeń: {failed})" if failed else ""))
    return "\n".join(out + sections)


def report_filename(scope_name: str) -> str:
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    return f"zdarzenia-{ascii_part(scope_name, 'raport')}-{stamp}.txt"


def content_disposition(scope_name: str) -> str:
    """Nazwa ASCII w naglowku + pelna (z polskimi znakami) w filename* — patrz
    app/filenames.py, gdzie opisana jest pulapka isalnum()."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    return _cd(report_filename(scope_name), pretty=f"zdarzenia-{scope_name}-{stamp}.txt")
