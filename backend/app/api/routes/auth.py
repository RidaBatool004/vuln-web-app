import os
import html

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.services import auth_service
from app.db.session import get_db

router = APIRouter()

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
TEMPLATE_DIR = os.path.join(BASE_DIR, "frontend", "templates")


@router.get("/")
async def index():
    return RedirectResponse(url="/signup", status_code=302)


@router.get("/signup")
async def signup_page():
    with open(os.path.join(TEMPLATE_DIR, "signup.html"), "r") as f:
        html = f.read()
    return HTMLResponse(content=html)


@router.post("/signup")
async def signup_post(
    username: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
):
    return auth_service.signup(username, email, password)


@router.get("/login")
async def login_page():
    with open(os.path.join(TEMPLATE_DIR, "login.html"), "r") as f:
        html = f.read()
    return HTMLResponse(content=html)


@router.post("/login")
async def login_post(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
):
    return auth_service.login(request, username, password)


@router.get("/search")
async def search_user(q: str = ""):
    if not q:
        return HTMLResponse(content="<h3>No search query provided</h3>")

    # FIXED: SQL Injection closed by using parameterized query
    # VULNERABILITY #3: Reflected XSS still preserved -- query interpolated into HTML without escaping
    query = "SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?"

    conn = get_db()
    try:
        cursor = conn.execute(query, [f"%{q}%", f"%{q}%"])
        rows = cursor.fetchall()

        results = ""
        for row in rows:
            results += f"<li>{row[0]} ({row[1]})</li>"

        html = f"<h3>Search results for: {q}</h3><ul>{results}</ul>"
        return HTMLResponse(content=html)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error: {str(e)}</h3>")
    finally:
        conn.close()


@router.get("/welcome")
async def welcome_page(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    username = request.session.get("username", "")

    with open(os.path.join(TEMPLATE_DIR, "dashboard.html"), "r") as f:
        page = f.read()

    # FIXED: Stored XSS closed -- username escaped before substitution.
    # The raw value remains in the session/database (output-encoding fix, not input filtering).
    safe_username = html.escape(username, quote=True)
    page = page.replace("{{username}}", safe_username)

    return HTMLResponse(content=page)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)
