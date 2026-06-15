# Vulnerable Web Application Build via Claude Code

An intentionally vulnerable web application designed to teach common security vulnerabilities through hands-on exploitation. Rather than studying vulnerabilities in theory, you'll exploit them in a working application to understand how real attacks work.

Built with FastAPI and SQLite — simple enough to read in one sitting, realistic enough to demonstrate actual attack techniques.

**Live Demo of v0.1.0:** https://vuln-web-app.onrender.com

> **WARNING:** This application is deliberately insecure. It is designed for educational use only and should never be deployed to production or used on systems you do not own.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | FastAPI, Uvicorn |
| Database | SQLite3 |
| Frontend | Vanilla HTML5, CSS3, JavaScript |
| Session Management | Starlette SessionMiddleware |
| Package Manager | uv |
| Python | 3.12+ |

## Project Structure

```
vuln-web-app/
├── backend/
│   ├── app/
│   │   ├── main.py                  # Entry point — starts the server
│   │   ├── core/
│   │   │   └── security.py          # Password hashing (bcrypt, work factor 12)
│   │   ├── db/
│   │   │   └── session.py           # Database connection and schema setup
│   │   ├── services/
│   │   │   └── auth_service.py      # Business logic for signup and login
│   │   └── api/routes/
│   │       └── auth.py              # All HTTP route handlers
│   └── pyproject.toml               # Backend package config
├── frontend/
│   ├── templates/
│   │   ├── login.html               # Login page (fetch-based, theme toggle)
│   │   ├── signup.html              # Registration page (form POST, theme toggle)
│   │   └── dashboard.html           # Protected dashboard (theme toggle)
│   └── static/
│       ├── css/styles.css           # Application styling (light/dark themes)
│       └── images/                  # Organization logos (PUCIT, Excaliat, FCCU)
├── docs/
│   ├── PRD.md                       # Product requirements
│   ├── TDD.md                       # Technical design
│   └── prompts/                     # Prompts used to generate specs & plans
├── .claude/specs/                   # Feature specs and implementation plans
├── pyproject.toml                   # Root project config
└── vulnerable_app.db                # SQLite database (auto-created)
```

---

## Releases & Versions

This repository ships in several tagged releases. The three below are the main anchors — pick the one that matches how you want to learn:

| Version | Who it's for | What you get |
|---------|--------------|--------------|
| **v0.1.0** | Students who want to fix the vulnerabilities **from scratch** | The baseline vulnerable app with **all 8 intentional vulnerabilities open** (including the MD5 weak password storage). Your job is to find and patch each one yourself. |
| **v0.1.1** | Students who want a **partial reference implementation** | Adds the **dark mode toggle** and replaces MD5 with **bcrypt** (VULN-5 fixed). A good starting point for comparing your own early fixes. |
| **v1.0.0** | Students who want the **complete reference implementation** | All **8 vulnerabilities fixed** (SQLi, stored & reflected XSS, session hijacking, weak passwords, exposed DB, no rate limiting, CSRF). Study it to see how every patch was implemented. |

The incremental tags between them (**v0.1.2 – v0.1.7**) each close one additional vulnerability — see the [Bug Fixes](#bug-fixes) table for the version-by-version mapping.

### Download the version you want

**Option A — Download a release archive (no Git required)**

- v0.1.0 (all vulnerabilities open): https://github.com/arifpucit/vuln-web-app/releases/tag/v0.1.0
- v0.1.1 (dark mode + bcrypt): https://github.com/arifpucit/vuln-web-app/releases/tag/v0.1.1
- v1.0.0 (all vulnerabilities fixed): https://github.com/arifpucit/vuln-web-app/releases/tag/v1.0.0

Download the `Source code (zip)` or `Source code (tar.gz)` asset for the version you want and extract it.

**Option B — Clone the repo and check out the tag**

```bash
git clone https://github.com/arifpucit/vuln-web-app.git
cd vuln-web-app

# Work on the fully vulnerable baseline from scratch
git checkout v0.1.0

# Or study the partial reference (dark mode + bcrypt)
git checkout v0.1.1

# Or study the complete reference (all 8 vulnerabilities fixed)
git checkout v1.0.0
```

---

## Getting Started

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/arifpucit/vuln-web-app.git
cd vuln-web-app

# Check out the version you want (see "Releases & Versions" above)
git checkout v0.1.0   # baseline (all open) — or v0.1.1 (partial) / v1.0.0 (all fixed)

# Install dependencies
uv sync
```

### Running the Application

From the project root:
```bash
uv run backend/app/main.py
```

The app starts at **http://localhost:3001**. The database file (`vulnerable_app.db`) is created automatically on first run.

---

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|:---:|
| GET | `/` | Redirect to signup | No |
| GET | `/signup` | Display signup form | No |
| POST | `/signup` | Create user account | No |
| GET | `/login` | Display login form | No |
| POST | `/login` | Authenticate user (returns JSON) | No |
| GET | `/welcome` | Protected dashboard | Yes |
| GET | `/logout` | Terminate session | No |
| GET | `/search?q=` | Search users | No |

---

## Intentional Vulnerabilities

| # | Vulnerability | OWASP Category | Location | Status |
|---|---------------|----------------|----------|--------|
| 1 | SQL Injection | A03:2021 - Injection | `auth_service.py` — string concatenation in queries | **Closed** |
| 2 | Stored XSS | A03:2021 - Injection | `auth.py` — was unescaped username on dashboard; now HTML-escaped before output | **Closed** |
| 3 | Reflected XSS | A03:2021 - Injection | `auth.py` — was unescaped query param in search; now HTML-escaped before output | **Closed** |
| 4 | Session Hijacking | A07:2021 - Auth Failures | `main.py` — was a hardcoded secret key; now sourced from `SECRET_KEY` env var with a strong random fallback | **Closed** |
| 5 | Weak Password Storage | A02:2021 - Crypto Failures | `security.py` — was MD5 (no salt); now bcrypt (cost 12) | **Closed** |
| 6 | Exposed Database | A01:2021 - Access Control | `auth.py` — unauthenticated `/download/db` (route removed) | **Closed** |
| 7 | No Rate Limiting | A07:2021 - Auth Failures | `core/rate_limit.py` + `main.py` — was no throttling; now per-IP sliding-window limit on every POST (HTTP 429 when exceeded) | **Closed** |
| 8 | CSRF | A01:2021 - Access Control | `core/csrf.py` + `main.py` + form templates — was no CSRF tokens on forms; now per-session synchronizer token validated on every POST (HTTP 403 when missing or mismatched) | **Closed** |

---

## Learning Path

1. **Explore the app** — Sign up, log in, and navigate the dashboard to understand normal functionality.
2. **Read the source code** — Each vulnerability is commented in the code with its vulnerability number.
3. **Exploit each flaw** — Use the vulnerability table above to locate and exploit each one.
4. **Fix it** — Patch each vulnerability using secure coding practices: parameterized queries, output escaping, strong password hashing, rate limiting, and CSRF tokens.

---

## Useful Commands

Check the database contents:
```bash
sqlite3 vulnerable_app.db "SELECT * FROM users;"
```

Reset the database (delete and restart):
```bash
rm vulnerable_app.db
uv run backend/app/main.py
```

Free port 3001 if already in use:
```bash
# macOS / Linux
lsof -ti:3001 | xargs kill

# Windows (PowerShell)
Get-NetTCPConnection -LocalPort 3001 | Select-Object OwningProcess
Stop-Process -Id <PID> -Force
```

---

## Bug Fixes
The **weak password storage** bug (VULN-5: MD5 → bcrypt) is **fixed** as of **v0.1.1**, the **SQL injection** vulnerability (VULN-1: string concatenation → parameterized queries) is **fixed** as of **v0.1.2**, the **exposed database** endpoint (VULN-6: unauthenticated `/download/db` → route removed) is **fixed** as of **v0.1.3**, the **session hijacking** vulnerability (VULN-4: hardcoded session secret → env-sourced secret with a strong random fallback) is **fixed** as of **v0.1.4**, the **stored XSS** vulnerability (VULN-2: unescaped dashboard username → HTML-escaped output) is **fixed** as of **v0.1.5**, the **reflected XSS** vulnerability (VULN-3: unescaped `/search` reflection → HTML-escaped output) is **fixed** as of **v0.1.6**, the **no rate limiting** vulnerability (VULN-7: no throttling → per-IP sliding-window POST rate limit returning HTTP 429) is **fixed** as of **v0.1.7**, and the **CSRF** vulnerability (VULN-8: no CSRF tokens → per-session synchronizer-token middleware returning HTTP 403) is **fixed** as of **v0.1.8**. **All 8 vulnerabilities are now closed**; the current codebase is a complete reference implementation. To study the original vulnerabilities, check out the `v0.1.0` tag (fully vulnerable baseline) and patch them yourself.

| # | Vulnerability | Description | Status |
|---|---------------|-------------|--------|
| 1 | Weak Password Storage | Passwords were hashed with unsalted MD5; replaced with bcrypt (cost 12). Login now verifies the hash in Python instead of matching it in the SQL query. | **Fixed (v0.1.1)** |
| 2 | SQL Injection | `auth_service.py` builds queries with raw string concatenation; crafted input can read data or bypass authentication. Fix with parameterized/prepared queries. | **Fixed (v0.1.2)** |
| 3 | Stored XSS | `auth.py` rendered the username on the dashboard without escaping, so a malicious script persisted in the database and executed for every viewer. Fixed by HTML-escaping the username (`html.escape(..., quote=True)`) before output; the raw value still lives in the DB (output-encoding fix, not input filtering). | **Fixed (v0.1.5)** |
| 4 | Reflected XSS | The `/search` endpoint echoed the `q` parameter (and result rows / error text) back unescaped, executing injected scripts in the victim's browser. Fixed by HTML-escaping every reflected sink (`html.escape(..., quote=True)`); the raw values still live in the URL/DB (output-encoding fix, not input filtering). | **Fixed (v0.1.6)** |
| 5 | Session Hijacking | `main.py` used a hardcoded session secret key, making session cookies guessable/forgeable. Fixed by loading `SECRET_KEY` from the environment with a strong `secrets.token_hex(32)` random fallback, so a fresh checkout never ships a known key. | **Fixed (v0.1.4)** |
| 6 | Exposed Database | `/download/db` served the entire SQLite file with no authentication or authorization. Fixed by removing the route entirely. | **Fixed (v0.1.3)** |
| 7 | No Rate Limiting | There was no throttling middleware, leaving login open to brute-force and credential-stuffing attacks. Fixed by adding a stdlib `RateLimitMiddleware` that enforces a per-IP sliding window on every POST (default 5 requests / 60 s), returning HTTP 429 with a `Retry-After` header before the handler runs. | **Fixed (v0.1.7)** |
| 8 | CSRF | Forms carried no CSRF tokens, allowing cross-site request forgery against authenticated users. Fixed by adding a stdlib pure-ASGI `CSRFMiddleware` plus a per-session synchronizer token (`secrets.token_urlsafe(32)`) stored in `request.session["csrf_token"]`, spliced into a hidden field in the login and signup forms by the GET handlers, and validated on every POST with `secrets.compare_digest` — mismatches return HTTP 403 before the handler runs. | **Fixed (v0.1.8)** |

---

## Feature Enhancements

The dark mode toggle is **done** (shipped in v0.1.1). The remaining items are **planned**.

| # | Feature | Description | Status |
|---|---------|-------------|--------|
| 0 | Dark Mode Toggle | Light/dark theme toggle on login, signup, and dashboard pages; preference saved in `localStorage`, restored before first paint to avoid FOUC, with `prefers-color-scheme` fallback. | **Done (v0.1.1)** |
| 1 | User Profile Page | A page where authenticated users can view and save their personal information and account settings. This also moves the dark-mode preference from per-browser (`localStorage`) to **per-user** — stored on the account so the theme choice follows the user across browsers and devices. | Planned |
| 2 | Email Verification on Signup | During registration, send a confirmation email containing a verification token/link to confirm the address actually exists; the account is activated only after the user clicks the link. | Planned |
| 3 | Password Strength Meter | A real-time indicator on the signup form that displays password strength and the acceptance criteria (length, complexity, character classes) as the user types. | Planned |
| 4 | Change Password | A dedicated page that lets authenticated users change their password, verifying the current password before setting a new one. | Planned |
| 5 | Continue with Google (OAuth 2.0) | Allow users to sign up and log in using their Google account via the OAuth 2.0 authorization flow. | Planned |
| 6 | Continue with GitHub (OAuth 2.0) | Allow users to sign up and log in using their GitHub account via the OAuth 2.0 authorization flow. | Planned |
| 7 | MFA via Authenticator App (TOTP) | Add two-factor authentication using a TOTP authenticator app (e.g., Google Authenticator or Authy) with QR-code enrollment. | Planned |
| 8 | OTP via Email | Send a one-time passcode to the user's registered email as a second authentication factor during login. | Planned |
| 9 | QR Code Login | Let users log in by scanning a QR code shown on the login page from an already-authenticated mobile device. | Planned |
| 10 | CAPTCHA on Login | Add a CAPTCHA (e.g., Google reCAPTCHA or hCaptcha) to the login form to block automated and bot-driven login attempts. | Planned |
| 11 | Account Lockout | Temporarily lock an account after a configured number of consecutive failed login attempts, with a cooldown timer before retry. | Planned |

---

## Legal Notice

This application is provided strictly for educational purposes. Unauthorized access to computer systems is illegal. Ensure you have explicit permission before testing security vulnerabilities on any system you do not own. The authors are not responsible for misuse of this project.

---

## Troubleshooting

**`uv command not found`**
Install uv: `pip install uv` or see https://docs.astral.sh/uv/getting-started/installation/

**`Port 3001 already in use`**
Kill the existing process using the commands in "Useful Commands" above.

**`ModuleNotFoundError: No module named 'app'`**
Run the app from the project root with `uv run backend/app/main.py`. The entry point automatically adds `backend/` to `sys.path`.

**Database seems corrupted or stale**
Delete `vulnerable_app.db` from the project root and restart the app. The database is recreated automatically on startup.

---