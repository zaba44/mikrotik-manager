import hashlib
import os

from fastapi.templating import Jinja2Templates

class _Templates(Jinja2Templates):
    """Zgodnosc ze stylem wywolania sprzed Starlette 1.x.

    Starlette 1.x przyjmuje juz WYLACZNIE `TemplateResponse(request, name, context)`;
    stary styl `TemplateResponse(name, {"request": request, ...})` zostal usuniety.
    Aktualizacja byla konieczna (Starlette 0.38.6 mial 7 znanych podatnosci, poprawki
    dopiero w 1.3.1), a portal ma ~60 wywolan w starym stylu. Zamiast zmieniac je
    wszystkie naraz — duzy diff, latwo cos przeoczyc — tlumaczymy stary styl w jednym
    miejscu. Nowy kod moze pisac juz w nowym stylu; oba dzialaja."""

    def TemplateResponse(self, *args, **kwargs):
        if args and isinstance(args[0], str):
            name = args[0]
            context = args[1] if len(args) > 1 else kwargs.pop("context", {})
            return super().TemplateResponse(context.get("request"), name, context, *args[2:], **kwargs)
        return super().TemplateResponse(*args, **kwargs)


templates = _Templates(directory="app/templates")


def humanbytes(value) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


templates.env.filters["humanbytes"] = humanbytes


def plural(n, one: str, few: str, many: str) -> str:
    """Polska odmiana po liczebniku: 1 peer, 2–4 peery (ale 12–14 peerów), 5+ peerów."""
    n = abs(int(n))
    if n == 1:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


templates.env.globals["plural"] = plural


def _asset_version() -> str:
    """Odcisk zawartosci CSS i JS dopinany do adresow (`style.css?v=...`).

    Serwer wydaje pliki statyczne bez Cache-Control, wiec przegladarka sama zgaduje, jak
    dlugo je trzymac — i po aktualizacji portalu potrafila dalej uzywac starego CSS
    (dwa razy: zwijane sekcje i zawijanie adresow w kafelkach). Nowa zawartosc = nowy
    adres = przegladarka musi pobrac plik od nowa. Liczone raz przy starcie procesu."""
    h = hashlib.sha1()
    static = os.path.join(os.path.dirname(__file__), "static")
    for name in sorted(os.listdir(static)):
        if name.endswith((".css", ".js")):
            with open(os.path.join(static, name), "rb") as f:
                h.update(name.encode() + f.read())
    return h.hexdigest()[:10]


templates.env.globals["asset_v"] = _asset_version()

# Wersja portalu w panelu bocznym i znaczek „dostępna nowa" (wynik ostatniego sprawdzenia
# trzymany w pamieci — bez zapytania do bazy przy kazdej stronie).
from app import portal_update as _portal_update  # noqa: E402
from app import version as _version  # noqa: E402

templates.env.globals["portal_version"] = _version.VERSION
templates.env.globals["portal_update_available"] = _portal_update.update_available
