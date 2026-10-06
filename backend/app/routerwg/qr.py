"""Kody QR z configow WireGuard.

Generujemy SYNCHRONICZNIE po stronie serwera. Generator www robi to asynchronicznie
w przegladarce i poza Firefoksem ZIP z kodami bywal niekompletny — tutaj ZIP powstaje
dopiero, gdy kazdy PNG juz istnieje, wiec z definicji jest kompletny.

`segno.make_qr` (a nie `make`): zwykle `make` dla krotkiego tekstu potrafi wybrac Micro QR,
ktorego aplikacja WireGuard nie odczyta. Poziom korekcji M — jak w implementacji
referencyjnej; config z PSK miesci sie wtedy w rozsadnym rozmiarze kodu.

Kod zawsze ciemny na bialym, takze w ciemnym motywie panelu — odwrocony QR wiele
skanerow (w tym aparat w telefonie) po prostu ignoruje.
"""
from __future__ import annotations

import io

import segno


def _normalize(text: str) -> str:
    return text.replace("\r\n", "\n").strip()


def svg(text: str, scale: int = 4) -> str:
    qr = segno.make_qr(_normalize(text), error="m")
    # omitsize=True: segno daje wtedy viewBox zamiast stalych width/height. Bez tego CSS
    # zmniejszajacy obrazek PRZYCINAL kod zamiast go skalowac — QR na ekranie byl obciety
    # i telefon nie mogl go odczytac (zgloszone przez uzytkownika).
    return qr.svg_inline(scale=scale, border=3, dark="#000000", light="#ffffff", omitsize=True)


def png(text: str, scale: int = 6) -> bytes:
    qr = segno.make_qr(_normalize(text), error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="png", scale=scale, border=4, dark="#000000", light="#ffffff")
    return buf.getvalue()
