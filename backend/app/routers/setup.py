import ipaddress
import re

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app import setup_token
from app.auth import hash_password
from app.config import settings
from app.database import get_session
from app.first_run import mark_users_exist, users_exist
from app.models import User
from app.portal_backup import RestoreUncertain, restore_portal
from app.templating import templates
from app.wg_bringup import ensure_wg_up
from app.wg_config import save_wg_config

router = APIRouter(prefix="/setup")

_TOKEN_HELP = ("Znajdziesz go w logach kontenera: docker compose logs backend | grep TOKEN")


@router.get("")
async def setup_landing(request: Request, session: AsyncSession = Depends(get_session)):
    if await users_exist(session):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("setup.html", {"request": request})


@router.get("/wizard")
async def wizard(request: Request, session: AsyncSession = Depends(get_session)):
    if await users_exist(session):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        "setup_wizard.html", {"request": request, "wg_port": settings.wg_port}
    )


# Docker rozdaje sieci stackom z puli zaczynającej się od 172.17.0.0/16 w górę.
# Podsieć tunelu, która się z nią przecina, rozjedzie routing w sposób trudny do
# zdiagnozowania — dlatego blokujemy wybór zamiast tylko ostrzegać.
# UWAGA: 172.16.0.0/16 leży PONIŻEJ tej puli i jest bezpieczne (tak stoi lab).
_DOCKER_POOL = [ipaddress.ip_network(f"172.{o}.0.0/16") for o in range(17, 32)]
_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
# Adres huba trafia wprost do skryptów RouterOS (endpoint-address=...), więc dopuszczamy
# tylko nazwę hosta albo IP — bez spacji, cudzysłowów, $ i innych znaków składni skryptu.
_ENDPOINT = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def _validate_network(server_ip: str, mask: str):
    """Zwraca (network, error). Walidacja po stronie serwera, bo podpowiedzi w JS
    użytkownik może pominąć, a błędna podsieć to potem przepisywanie configu na całej
    flocie."""
    try:
        addr = ipaddress.ip_address(server_ip.strip())
        bits = int(mask)
        if not 8 <= bits <= 30:
            return None, "Maska musi być z zakresu /8–/30."
        net = ipaddress.ip_network(f"{addr}/{bits}", strict=False)
    except ValueError:
        return None, "Nieprawidłowy adres huba albo maska (podaj np. 10.22.20.1 i /22)."

    # NIE `is_private`: dla Pythona prywatne są też 127.0.0.0/8, 169.254.0.0/16 i fc00::/7,
    # a żadna z nich nie nadaje się na podsieć tunelu (wytknięte w recenzji zewnętrznej).
    # Tylko trzy pule RFC 1918, i to w całości — maska nie może wyprowadzić sieci poza pulę.
    if addr.version != 4 or not any(net.subnet_of(p) for p in _RFC1918):
        return None, "Podsieć huba musi być IPv4 z puli prywatnej: 10.x, 172.16–31.x albo 192.168.x."
    if addr == net.network_address or addr == net.broadcast_address:
        return None, ("Podany adres to adres sieci albo rozgłoszeniowy — wybierz adres hosta, "
                      f"np. {next(net.hosts())}.")
    for docker_net in _DOCKER_POOL:
        if net.overlaps(docker_net):
            return None, (f"Podsieć {net} przecina się z pulą, z której Docker rozdaje adresy "
                          f"kontenerom ({docker_net}). Wybierz inną — np. z zakresu 10.x.")
    return net, None


def _validate_endpoint(value: str) -> str | None:
    value = (value or "").strip()
    if not value:
        return "Podaj adres/domenę huba."
    if not _ENDPOINT.match(value):
        return "Adres huba: nazwa domeny albo adres IP, bez portu, spacji i znaków specjalnych."
    return None


@router.post("/wizard")
async def wizard_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    server_ip: str = Form(...),
    mask: str = Form("22"),
    hub_endpoint: str = Form(...),
    token: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    if await users_exist(session):
        return RedirectResponse(url="/", status_code=303)

    # Token sprawdzamy PIERWSZY: bez niego nie zdradzamy nawet, czy reszta formularza
    # byłaby poprawna.
    if not setup_token.check(token):
        error = f"Nieprawidłowy token instalacyjny. {_TOKEN_HELP}"
        net = None
    else:
        net, error = _validate_network(server_ip, mask)
        error = error or _validate_endpoint(hub_endpoint)
        if not username.strip() or not password:
            error = "Podaj login i hasło administratora."

    if error:
        return templates.TemplateResponse(
            "setup_wizard.html",
            {"request": request, "wg_port": settings.wg_port, "error": error,
             "prefill": {"username": username, "server_ip": server_ip, "mask": mask,
                         "hub_endpoint": hub_endpoint}},
            status_code=400,
        )

    await save_wg_config(
        session, subnet=str(net), server_ip=server_ip.strip(), hub_endpoint=hub_endpoint.strip()
    )
    session.add(User(username=username.strip(), password_hash=hash_password(password), role="admin"))
    await session.commit()
    mark_users_exist()
    setup_token.consume()
    await ensure_wg_up()  # świeży klucz huba + trasa + interfejs
    return RedirectResponse(url="/login", status_code=303)


@router.post("/restore")
async def restore(
    request: Request,
    archive: UploadFile = File(...),
    token: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    if await users_exist(session):
        return RedirectResponse(url="/", status_code=303)
    if not setup_token.check(token):
        return templates.TemplateResponse(
            "setup.html", {"request": request, "error": f"Nieprawidłowy token instalacyjny. {_TOKEN_HELP}"},
            status_code=400,
        )

    data = await archive.read()
    try:
        result = await restore_portal(data)
    except RestoreUncertain as e:
        # Nie porazka i nie sukces: pliki odtwarzania czekaja, wznowienie rozstrzygnie.
        return templates.TemplateResponse(
            "setup.html", {"request": request, "error": str(e)}, status_code=503,
        )
    except Exception as e:
        return templates.TemplateResponse(
            "setup.html", {"request": request, "error": f"Przywracanie nie powiodło się: {e}"},
            status_code=400,
        )
    # Tu baza jest juz zatwierdzona (bledy sprzed commitu to wyjatki powyzej), wiec kreator
    # i tak sie zamyka. Niedokonczona reszta (tunel, peery) NIE ginie razem z tym zadaniem:
    # dziennik i klucz huba czekaja na dysku, a portal ponawia sam — strona mowi to wprost.
    mark_users_exist()
    setup_token.consume()
    return templates.TemplateResponse("setup_restore_done.html", {"request": request, "result": result})
