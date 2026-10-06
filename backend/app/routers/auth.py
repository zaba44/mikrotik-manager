import datetime
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_user, hash_password, verify_password, session_fingerprint
from app.notifications import notify
from app.database import get_session
from app.models import User
from app.templating import templates

router = APIRouter()


@router.get("/login")
async def login_form(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    user = (
        await session.execute(select(User).where(User.username == username.strip()))
    ).scalar_one_or_none()

    client_ip = request.client.host if request.client else "?"
    if user is None or not verify_password(password, user.password_hash):
        await notify(
            session, event_key="portal.login_failed",
            dedup_key=f"portal.login_failed:{username.strip()}:{client_ip}",
            subject="[MTM] Nieudane logowanie do panelu",
            body=(f"Nieudana próba logowania.\n\nLogin: {username.strip()}\n"
                  f"Adres: {client_ip}\nCzas: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}"),
        )
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Nieprawidłowy login lub hasło."},
            status_code=401,
        )

    request.session["user_id"] = str(user.id)
    request.session["pwv"] = session_fingerprint(user.password_hash)
    await notify(
        session, event_key="portal.login",
        dedup_key=f"portal.login:{user.username}:{client_ip}",
        subject=f"[MTM] Logowanie do panelu: {user.username}",
        body=(f"Zalogowano do panelu.\n\nUżytkownik: {user.username} ({user.role})\n"
              f"Adres: {client_ip}\nCzas: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}"),
    )
    return RedirectResponse(url="/", status_code=303)


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@router.get("/account")
async def account_page(request: Request):
    return templates.TemplateResponse("account.html", {"request": request})


@router.post("/account/password")
async def change_own_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    user = await session.get(User, current_user(request).id)

    error = None
    if not verify_password(current_password, user.password_hash):
        error = "Aktualne hasło jest nieprawidłowe."
    elif not new_password:
        error = "Podaj nowe hasło."
    elif new_password != confirm_password:
        error = "Nowe hasła nie są takie same."

    if error:
        return templates.TemplateResponse(
            "account.html", {"request": request, "error": error}, status_code=400
        )

    user.password_hash = hash_password(new_password)
    await session.commit()
    # Wlasna sesja zostaje (nowy odcisk), wszystkie pozostale sesje tego konta wygasaja.
    request.session["pwv"] = session_fingerprint(user.password_hash)
    return templates.TemplateResponse("account.html", {"request": request, "ok": True})
