"""Tekst wysylany na router — bez polskich (i innych) znakow diakrytycznych.

RouterOS nie jest przyjazny dla UTF-8: wklejony w terminal komentarz gubi litery („SWITCH C
24P GÓRA" przyszlo jako „GRA"), a zapisany przez REST pokazuje sie w Winboksie jako krzaki.
Dlatego wszystko, co portal wpisuje na router z tekstu uzytkownika (komentarze), przechodzi
przez `ros_ascii`: „Ó" -> „O", „ł" -> „l", „é" -> „e". W samym portalu nazwy zostaja
z polskimi znakami — zmienia sie tylko to, co trafia na sprzet.

Nazwy (interfejsy, prefiksy peerow, uzytkownicy BTH) nie potrzebuja tego: walidacja i tak
dopuszcza w nich tylko ASCII.
"""
import unicodedata

# Litery, ktorych NFKD nie rozklada na litere + znak diakrytyczny.
_SPECIAL = {"ł": "l", "Ł": "L", "ß": "ss", "æ": "ae", "Æ": "AE", "ø": "o", "Ø": "O",
            "đ": "d", "Đ": "D", "œ": "oe", "Œ": "OE", "þ": "th", "Þ": "Th",
            # Typografia wklejana z Worda i maili: polpauza, cudzyslowy, wielokropek, twarda spacja.
            "–": "-", "—": "-", "‒": "-", "−": "-", "„": '"', "”": '"', "“": '"', "«": '"', "»": '"',
            "‘": "'", "’": "'", "‚": "'", "…": "...", " ": " "}


def ros_ascii(value) -> str:
    """Transliteracja do ASCII; czego nie da sie zamienic (emoji, znaki spoza alfabetu
    lacinskiego), to wypada. Biale znaki (takze nowe linie) zwiniete do pojedynczych spacji."""
    out = []
    for ch in str(value or ""):
        if ch.isascii():
            out.append(ch)
        elif ch in _SPECIAL:
            out.append(_SPECIAL[ch])
        else:
            out.append(unicodedata.normalize("NFKD", ch).encode("ascii", "ignore").decode())
    return " ".join("".join(out).split())
