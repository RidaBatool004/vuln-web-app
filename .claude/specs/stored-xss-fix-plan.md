# Implementation Plan — Stored XSS Fix (Dashboard Username Escaping)

**Version:** 1.0.0
**Last Updated:** June 15, 2026
**Parent Spec:** [stored-xss-fix.md](./stored-xss-fix.md)
**Foundation Spec:** [app-foundation.md](./app-foundation.md)
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)
**Tracking Issue:** [Stored XSS — unescaped `{{username}}` substitution in dashboard](https://github.com/arifpucit/vuln-web-app/issues)

---

## 0. Plan Overview

This plan implements the fix specified in [stored-xss-fix.md](./stored-xss-fix.md). It closes the **Stored XSS** vulnerability and **only** that vulnerability, by adding `import html` to `backend/app/api/routes/auth.py` and routing the session's `username` value through `html.escape(username, quote=True)` before it reaches the `{{username}}` substitution inside `welcome_page`. The work is split into **three phases** so the change is small, individually verifiable, and easy to revert.

The other intentional vulnerabilities (Reflected XSS, No Rate Limiting, CSRF) MUST remain exploitable after every phase, and the already-closed fixes (bcrypt password hashing, SQL injection, exposed-DB endpoint, env-sourced session secret) stay closed. Each phase ends with an explicit "MUST NOT" callout listing things that would silently alter another vulnerability.

### Phase Summary

| # | Phase | Files Touched | Goal |
|---|-------|--------------|------|
| 1 | Apply the two edits in `auth.py` | `backend/app/api/routes/auth.py` | `import html`; escape `username` before splicing into the dashboard response |
| 2 | End-to-end verification | None (read-only) | Walk every Verification Step in spec §10 |
| 3 | Vulnerability preservation audit | None (read-only) | Confirm the other vulnerabilities behave as specified |

### Files Modified (Authored)

Exactly the one source file declared in spec §3:

- `backend/app/api/routes/auth.py`

No dependency change (`html` is in the Python standard library), so no `pyproject.toml` or `uv.lock` edit (and no `uv sync`).

### Files That MUST NOT Be Modified

- `backend/app/main.py` — preserves the env-sourced session secret (VULN-4 stays closed).
- `backend/app/services/auth_service.py` — preserves parameterized queries (VULN-1 stays closed) and bcrypt verification call (VULN-5 stays closed); also preserves the raw-username writes into the session and database that the spec deliberately leaves un-sanitized (per §FR-06 — output-encoding fix, not input filtering).
- `backend/app/core/security.py` — bcrypt stays; do not revert.
- `backend/app/db/session.py` — schema and connection layer; untouched.
- `frontend/templates/dashboard.html` — the `{{username}}` placeholder and its surrounding `<strong>` element MUST remain byte-for-byte identical.
- `frontend/templates/login.html`, `frontend/templates/signup.html` — no template-side change.
- Any CSS under `frontend/static/`.
- `CLAUDE.md`, `README.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, and every other prior spec.
- `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` (no dependency change — `html` is stdlib).

### Vulnerability Preservation Checklist (Carry Through Every Phase)

After the edit, re-confirm:

1. **SQL Injection.** Already CLOSED — `auth_service.py` uses parameterized queries (`WHERE username = ?`, `VALUES (?, ?, ?)`) and `/search` uses `LIKE ?`. Not touched by this plan; stays closed.
2. **Stored XSS.** **This is the only vulnerability being closed.** After Phase 1, the dashboard sink at `welcome_page` escapes `username` via `html.escape(..., quote=True)` before substitution.
3. **Reflected XSS.** `/search` still interpolates `q` into HTML unescaped (`<h3>Search results for: {q}</h3>` and the error response). The newly-imported `html` module MUST NOT be applied inside `search_user`.
4. **Session Hijacking.** Already CLOSED — `main.py` sources `SECRET_KEY` from the environment with a `secrets.token_hex(32)` fallback. Not touched; stays closed.
5. **Weak Password (bcrypt).** `security.py` still uses bcrypt at rounds ≥ 12 with the defensive `try/except` in `verify_password`. Not touched; stays closed.
6. **Exposed Database endpoint.** Already CLOSED — `/download/db` route removed. Not touched; stays closed.
7. **No Rate Limiting.** No throttling middleware, per-IP counter, or `time.sleep` added — not touched.
8. **CSRF.** No CSRF token field or middleware added — not touched.

---

## Phase 1 — Apply the Two Edits in `auth.py`

### 1.1 Goal

Add the standard-library `html` module and route the session's `username` through `html.escape(..., quote=True)` before it reaches the `{{username}}` placeholder substitution. All edits are confined to `backend/app/api/routes/auth.py`.

### 1.2 File to Modify

- `backend/app/api/routes/auth.py`

### 1.3 Edit A — Add the `html` Import

**Before** (L1):

```python
import os
```

**After**:

```python
import os
import html
```

`html.escape` is part of CPython's standard library; no third-party dependency is added. The import is placed at the top of the file alongside the other stdlib import (`os`), before the FastAPI / local-app imports — matching the existing import ordering convention in this module.

### 1.4 Edit B — Escape on Substitution Inside `welcome_page`

The current handler (L78–92) reads:

```python
@router.get("/welcome")
async def welcome_page(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    username = request.session.get("username", "")

    with open(os.path.join(TEMPLATE_DIR, "dashboard.html"), "r") as f:
        html = f.read()

    # VULNERABILITY #2: Stored XSS -- username substituted without escaping
    html = html.replace("{{username}}", username)

    return HTMLResponse(content=html)
```

**Naming caveat — IMPORTANT.** The current handler uses a local variable named `html` to hold the template string. After `import html` is added at module level, that local variable would shadow the imported module — and `html.escape(...)` inside the handler would raise `AttributeError: 'str' object has no attribute 'escape'` (because `html` resolves to the string returned by `f.read()`, not the module). The rename is therefore part of the fix, not an aesthetic cleanup.

**After** — replace the entire `welcome_page` body with:

```python
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
```

Three changes inside the handler:

1. `html = f.read()` → `page = f.read()` (rename the local to free the `html` name for the module).
2. Comment updated from "VULNERABILITY #2: ..." to "FIXED: Stored XSS closed ...".
3. The single `html = html.replace(...)` line is replaced by a two-line block: compute `safe_username = html.escape(username, quote=True)`, then `page = page.replace("{{username}}", safe_username)`.

The early `RedirectResponse(url="/login", status_code=302)` branch (anonymous request), the session lookup (`request.session.get("user_id")`, `request.session.get("username", "")`), and the file-read path (`open(os.path.join(TEMPLATE_DIR, "dashboard.html"), "r")`) are all unchanged. The final `HTMLResponse(content=...)` return wraps the renamed local but is otherwise identical (same status, same content type).

### 1.5 Edit Summary

Two edits inside `auth.py`:

1. **Top of file** — add `import html` on a new line directly after `import os`.
2. **`welcome_page` (L78–92)** — rename the local `html` variable to `page`, change the comment, and replace the unescaped `str.replace` with the two-line escape-then-replace block shown above.

No other line in the file changes. `index`, `signup_page`, `signup_post`, `login_page`, `login_post`, `search_user`, and `logout` are all untouched — in particular, `search_user`'s string interpolation of `q` is left exactly as it stands (preserves VULN-3).

### 1.6 Line-by-Line Justification

| Line / Block | Decision | Spec ref |
|---|---|---|
| `import html` at top of module | Standard library; no dependency delta | FR-05, NFR-06 |
| Rename local `html` → `page` in `welcome_page` | Prevents the local shadowing the imported module; the only way `html.escape(...)` resolves correctly | FR-01, NFR-03 |
| `safe_username = html.escape(username, quote=True)` | Required by spec: escape ALL five special chars including quotes | FR-01, FR-02, AC-02, AC-06 |
| `page = page.replace("{{username}}", safe_username)` | Same `str.replace` semantics (every occurrence) — only the inserted value is escaped | FR-01, EC-07 |
| Anonymous-redirect branch unchanged | Preserves the existing 302 contract for unauthenticated requests | FR-07, EC-05 |
| `session.get("username", "")` fallback unchanged | Empty fallback already safe under `html.escape("")` → `""` | EC-02 |
| Return type / status / content type unchanged | API stability | NFR-03, NFR-05, FR-07 |
| `search_user` body untouched | Preserves VULN-3 Reflected XSS | FR-04, AC-08 |
| `auth_service.signup()` / `login()` untouched | Session and DB still hold raw payload; preserves educational lesson | FR-06, EC-01, EC-04, AC-10 |
| `dashboard.html` untouched | `{{username}}` placeholder preserved verbatim | FR-03 |

### 1.7 What NOT to Change in Phase 1

- **DO NOT** escape `q` in `search_user`. That would close VULN-3 (Reflected XSS), which this fix explicitly preserves (spec §2.2, §2.3, FR-04). The newly-imported `html` module is used ONLY inside `welcome_page`.
- **DO NOT** call `html.escape` anywhere else in the module.
- **DO NOT** modify `frontend/templates/dashboard.html`. The `{{username}}` placeholder, the surrounding `<strong>` element, and every other character of the template stay byte-for-byte (spec FR-03).
- **DO NOT** modify `frontend/templates/login.html` or `frontend/templates/signup.html`.
- **DO NOT** sanitize the username in `auth_service.signup()` (the INSERT must still write the raw value to `users.username`) or in `auth_service.login()` (the session write must still copy the raw `users.username` value). The fix is **output encoding at the sink**, not input filtering — preserving the raw value in the database is part of the educational lesson (spec FR-06, EC-01, EC-04).
- **DO NOT** add `bleach`, `MarkupSafe`, Jinja2, or any other third-party dependency. The spec mandates standard-library-only (spec FR-05, NFR-06). No `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` edit; no `uv sync`.
- **DO NOT** switch the substitution to a template engine. Plain `str.replace` with an escaped value is the spec-mandated mechanism (spec §FR-03, "Switching to a template engine ... is out of scope").
- **DO NOT** drop the `quote=True` argument. The spec requires quote-aware escaping so the fix remains correct even if a future maintainer moves the placeholder into an HTML attribute (spec FR-02).
- **DO NOT** touch `main.py`, `services/auth_service.py`, `core/security.py`, `db/session.py`, or any CSS file.
- **DO NOT** re-introduce a closed vulnerability:
  - No re-adding `/download/db` (VULN-6 stays closed).
  - No reverting `main.py` to the hardcoded `"super-secret-key-12345"` (VULN-4 stays closed).
  - No reverting `security.py` to MD5 (VULN-5 stays closed).
  - No reverting `auth_service.py` / `search_user` to string-concatenated SQL (VULN-1 stays closed).
- **DO NOT** change HTTP status codes, headers, response timing, or log lines on `/welcome` (spec NFR-05).

### 1.8 Phase 1 Verification (Pre-Server)

```bash
# Import added
grep -n '^import html$' backend/app/api/routes/auth.py

# Escape on substitution present in welcome_page
grep -n 'html.escape(' backend/app/api/routes/auth.py

# Raw substitution removed
grep -n 'replace("{{username}}", username)' backend/app/api/routes/auth.py \
  || echo '(raw substitution removed)'

# Local rename applied — no leftover `html = html.replace` (which would AttributeError at runtime)
grep -n 'html = html.replace' backend/app/api/routes/auth.py \
  || echo '(no shadowing replace left)'

# Module imports cleanly under the runtime Python
cd backend && uv run python -c "from app.api.routes.auth import router; print('import ok')" && cd ..
```

Expected: the first two greps each match a single line; the third and fourth print their fallback (the raw `str.replace` form is gone); the import smoke test prints `import ok`.

---

## Phase 2 — End-to-End Verification

This phase walks every Verification Step in spec §10 in order. **No edits** are made; if any step fails, return to Phase 1 to repair.

### 2.1 Start the Application (spec §10.3 — AC-12, TC-20)

```bash
rm -f vulnerable_app.db
uv run backend/app/main.py
```

The DB reset is recommended so the test users registered below have predictable bcrypt hashes and a clean `users` table — pre-existing rows still work, but a fresh DB keeps the walkthrough reproducible. The server listens on `http://localhost:3001` with no import/boot error.

### 2.2 Confirm the New Import (spec §10.1 — AC-01, TC-01)

```bash
grep -n '^import html$' backend/app/api/routes/auth.py
```

Expected: a single matching line near the top of the file.

### 2.3 Confirm Escape on Substitution (spec §10.2 — AC-02, AC-03, TC-02)

```bash
grep -n 'html.escape(' backend/app/api/routes/auth.py
```

Expected: a matching line inside `welcome_page`. Manual inspection confirms `safe_username` is what reaches the `{{username}}` replacement and that no raw-value `str.replace` of `{{username}}` remains.

### 2.4 Benign Username Round-Trip (spec §10.4 — AC-07, TC-03)

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

Expected: the final command prints `Logged in as <strong>alice</strong>` (verbatim, no entity encoding — `html.escape` is a no-op on plain alphanumeric input).

### 2.5 `<script>` Payload Rendered Inert (spec §10.5 — AC-04, TC-04)

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

### 2.6 `<img onerror>` Payload Rendered Inert (spec §10.6 — AC-05, TC-05)

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

### 2.7 Attribute-Breakout Payload Neutralized (spec §10.7 — AC-06, TC-06)

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

Expected: the `&quot;` entity is printed (confirms `quote=True` is in effect).

### 2.8 Stored Data Still Malicious (spec §10.8 — AC-10, TC-21)

```bash
sqlite3 vulnerable_app.db "SELECT username FROM users WHERE username LIKE '<script>%';"
```

Expected: returns the raw `<script>alert(1)</script>` string — confirming the fix is output encoding at the sink, not input filtering. The session and database still hold the raw payload (per spec §FR-06).

### 2.9 Anonymous Redirect Preserved (spec §10.9 — TC-11)

```bash
curl -s -o /dev/null -w 'welcome_anon=%{http_code}\n' http://localhost:3001/welcome
```

Expected: `welcome_anon=302` (or `307`, matching the existing handler) — the anonymous-redirect branch of `welcome_page` is unchanged.

### 2.10 Affected-Files Audit (spec §10.11 — AC-11, TC-19)

```bash
git status --porcelain
```

Expected output — exactly one modified source file plus the two new spec docs:

```
 M backend/app/api/routes/auth.py
?? .claude/specs/stored-xss-fix.md
?? .claude/specs/stored-xss-fix-plan.md
```

No other path. In particular, no entry for `main.py`, `auth_service.py`, `security.py`, `db/session.py`, any template, any CSS file, or any pyproject/lock file.

---

## Phase 3 — Vulnerability Preservation Audit

Read-only confirmation that the other intentional vulnerabilities still fire (VULN-3, VULN-7, VULN-8) and that the already-closed ones stay closed (VULN-1, VULN-4, VULN-5, VULN-6). Mirrors spec §10.10.

### 3.1 VULN-3 Reflected XSS Still Fires (AC-08, TC-12)

```bash
curl -s 'http://localhost:3001/search?q=<script>alert(1)</script>' | grep -o '<script>alert(1)</script>'
```

Expected: the literal `<script>alert(1)</script>` is printed back (reflected unescaped). The `/search` handler was not modified — `q` is still interpolated raw into the response body.

### 3.2 VULN-1 SQL Injection Stays Closed (AC-09, TC-13)

```bash
grep -n 'WHERE username = ?' backend/app/services/auth_service.py
grep -n 'LIKE ?' backend/app/api/routes/auth.py
```

Expected: both parameterized-query patterns match. No regression to string-concatenated SQL.

### 3.3 VULN-4 Session Secret Stays Env-Sourced (AC-09, TC-14)

```bash
grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py
grep -n 'super-secret-key-12345' backend/app/main.py \
  || echo '(hardcoded secret absent — preserved)'
```

Expected: the `os.environ.get("SECRET_KEY"` line is present; the literal `super-secret-key-12345` does NOT appear. The fallback uses `secrets.token_hex(32)`.

### 3.4 VULN-5 Bcrypt Stays in Use (AC-09, TC-15)

```bash
grep -n 'bcrypt' backend/app/core/security.py
```

Expected: bcrypt is still imported and used. No reversion to MD5.

### 3.5 VULN-6 `/download/db` Stays Removed (AC-09, TC-16)

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/download/db
```

Expected: `404`. The route stays absent from the router.

### 3.6 VULN-7 No Rate Limiting (AC-09, TC-17)

```bash
for i in {1..50}; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
       --data-urlencode 'username=ghost' --data-urlencode "password=$i"
done | sort -u
```

Expected: only `401` appears in the deduplicated output — no `429`, no connection refusals, no throttling.

### 3.7 VULN-8 No CSRF Tokens (AC-09, TC-18)

```bash
curl -s http://localhost:3001/login  | grep -i csrf || echo '(no csrf field — preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo '(no csrf field — preserved)'
```

Expected: each command prints the `(no csrf field — preserved)` fallback. No CSRF token field, no CSRF middleware.

### 3.8 Spec Acceptance Criteria Roll-Up

Tick every AC from spec §8:

- [ ] AC-01 `html` Module Imported (Phase 1.3, Phase 2.2)
- [ ] AC-02 Username Escaped Before Substitution (Phase 1.4, Phase 2.3)
- [ ] AC-03 No Raw Substitution Remains in `welcome_page` (Phase 1.4, Phase 1.8)
- [ ] AC-04 `<script>` Username Renders as Text (Phase 2.5)
- [ ] AC-05 `<img onerror>` Username Renders as Text (Phase 2.6)
- [ ] AC-06 Quote-Aware Escaping in Use (Phase 1.4 `quote=True`, Phase 2.7)
- [ ] AC-07 Benign Usernames Unchanged (Phase 2.4)
- [ ] AC-08 Reflected XSS Preserved (VULN-3) (Phase 3.1)
- [ ] AC-09 Other Vulnerabilities Preserved (Phase 3.2–3.7)
- [ ] AC-10 Stored Data Untouched (Phase 2.8)
- [ ] AC-11 Only `auth.py` Modified (Phase 2.10)
- [ ] AC-12 Application Boots (Phase 2.1, Phase 1.8 import smoke test)

### 3.9 Stop the Server

`Ctrl+C` to stop. Plan complete.

---

## Risk Log & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Local variable `html` shadows the imported `html` module → `AttributeError: 'str' object has no attribute 'escape'` on the first `/welcome` request | Medium | High | Phase 1.4 explicitly renames the local to `page`; Phase 1.8 import smoke test surfaces the issue early; Phase 1.8 fourth grep (`grep 'html = html.replace'`) catches a leftover shadowed-replace; Phase 2.4 round-trip catches it at runtime |
| Forgetting `quote=True` — attribute-breakout payloads still execute if the placeholder is ever moved into an attribute | Low | Medium | Spec FR-02 + Phase 1.4 edit shows the literal call with `quote=True`; Phase 2.7 curl + grep verify `&quot;` is present in the rendered response |
| Escaping the wrong sink — accidentally applying `html.escape` to `q` in `/search` and silently closing VULN-3 | Medium | High | "MUST NOT" list in Phase 1.7; Phase 3.1 explicitly curls `/search?q=<script>...` and asserts the raw payload is returned |
| Sanitizing on input (in `auth_service.signup()` or `auth_service.login()`) instead of output — closes XSS but loses the educational demonstration and changes a file outside the declared scope | Medium | Medium | Spec §FR-06 + Phase 1.7 MUST-NOT explicitly forbid touching `auth_service.py`; Phase 2.8 sqlite check confirms raw payload is still stored; Phase 2.10 file audit catches the stray edit |
| Switching to a template engine (Jinja2, MarkupSafe) "while in here" — scope creep + dependency change | Low | Medium | Spec §FR-05 + Phase 1.7 MUST-NOT forbid new deps; Phase 2.10 file audit catches stray pyproject/lock edits |
| Modifying `dashboard.html` (e.g. moving `{{username}}` into an attribute or pre-escaping it) | Low | Medium | Spec §FR-03 + Phase 1.7 MUST-NOT; Phase 2.10 file audit catches the change |
| Accidentally re-opening a previously closed vulnerability while editing `auth.py` (e.g. re-adding `/download/db`) | Very Low | High | Phase 1.7 MUST-NOT enumerates all four closed vulns; Phase 3.2–3.5 grep/curl checks per closed vuln catch any regression |
| (Fallback) Implementer rejects the local-variable rename for style reasons | Low | Low | Spec FR-05 still allows an aliased import as an alternative: `from html import escape as html_escape`, keeping the local `html` name; only the call site changes (`html_escape(username, quote=True)`). Option 1 (rename to `page`) remains the recommended path. |

---

## Rollback Procedure

If a phase fails verification and cannot be repaired quickly:

```bash
git restore backend/app/api/routes/auth.py
```

The single authored file snaps back to its pre-fix state. No dependency, schema, or data migration is involved — the `vulnerable_app.db` file, the `users` table, and the session cookie format are all untouched by the fix in the first place.

---

## Out-of-Band: What This Plan Deliberately Does NOT Do

To make the negative space explicit:

- **No input filtering or sanitization.** The signup/login flow still writes the raw, unsanitized username into `users.username` and into `request.session["username"]`. Malicious payloads are still **stored**; they are merely rendered inert at the dashboard output sink. This preserves the educational lesson that the correct mitigation is output encoding at every sink, not "wash the data once at the source."
- **No template-engine adoption.** No Jinja2, no MarkupSafe, no auto-escape framework. The substitution stays as plain `str.replace` — only the value being inserted is escaped.
- **No template edits.** `dashboard.html` is byte-for-byte unchanged. The `{{username}}` placeholder stays exactly where it is, inside the `<strong>` element of the hero banner.
- **No change to `/search`.** VULN-3 (Reflected XSS) remains exploitable. The newly-imported `html` module is used ONLY inside `welcome_page`.
- **No change to rate-limiting posture.** VULN-7 remains. No throttling middleware is added.
- **No change to CSRF posture.** VULN-8 remains. No CSRF tokens are added to forms; no CSRF middleware is registered.
- **No reversal of prior fixes.** VULN-1 (parameterized SQL), VULN-4 (env-sourced session secret), VULN-5 (bcrypt), and VULN-6 (removed `/download/db`) all stay closed.
- **No new dependency.** `html` is a Python standard-library module; `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are not edited; no `uv sync` is required.
- **No database migration.** The `users` table schema, the existing rows, and the on-disk `vulnerable_app.db` file are unchanged. Pre-existing accounts (including any whose username column already contains malicious markup) continue to work without modification — their payloads simply render as inert text on `/welcome`.
- **No file** created or modified beyond `backend/app/api/routes/auth.py` and this spec/plan pair.
