"""Nazwy plików w pobieraniach — JEDNO miejsce, bo ten sam błąd wystąpił już dwa razy.

Nazwy w portalu nadaje użytkownik i mogą zawierać cokolwiek („AP DÓŁ", „Świrch POE").
Nagłówki HTTP są kodowane **latin-1**, więc każdy znak spoza tego zakresu wywala całą
odpowiedź 500 (`'latin-1' codec can't encode character '\\u0141'`).

PUŁAPKA, która to spowodowała: `str.isalnum()` zwraca True dla „Ł" i „Ą" — to litery
Unicode. Filtr `c if c.isalnum() else "-"` wygląda na bezpieczny, a przepuszcza polskie
znaki wprost do nagłówka. Jedyny pewny sposób to biała lista ASCII (albo jawne
`.encode("ascii")`), nigdy `isalnum()`.
"""
from urllib.parse import quote

_PL_ASCII = str.maketrans("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ", "acelnoszzACELNOSZZ")


def ascii_part(value: str, fallback: str = "plik") -> str:
    """Fragment nazwy pliku bezpieczny dla nagłówka HTTP. Polskie znaki transliterowane
    (żeby „AP DÓŁ" dało czytelne „AP-DOL", a nie „AP-D--"), reszta spoza ASCII odrzucona."""
    ascii_value = value.translate(_PL_ASCII).encode("ascii", "ignore").decode()
    safe = "".join(c if (c.isascii() and (c.isalnum() or c in "_.-")) else "-" for c in ascii_value)
    safe = "-".join(part for part in safe.split("-") if part)
    return safe or fallback


def content_disposition(filename: str, *, pretty: str | None = None) -> str:
    """`filename=` w ASCII (zgodność i bezpieczeństwo nagłówka) + `filename*` w UTF-8
    (RFC 5987), dzięki czemu przeglądarka pokazuje pełną nazwę z polskimi znakami."""
    ascii_name = ascii_part(filename)
    utf8_name = quote(pretty or filename, safe="")
    return f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{utf8_name}'
