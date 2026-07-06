# Software Specification Document — Account Lockout

**Version:** 1.0.0
**Last Updated:** 2026-06-20
**Target Release Tag:** v1.0.5
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [Account Lockout — README "Feature Enhancements" #9](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the **Account Lockout** enhancement. It is item #9 in the README's "Feature Enhancements" table. After a configured number of **consecutive failed login attempts** against a given account, the app **temporarily locks that account** and refuses to authenticate it — even with the correct password — until a cooldown window elapses. The lock then expires automatically (time-based; no admin action), and the user gets a fresh allowance.

**Relationship to rate limiting (already shipped — VULN-7).** Account lockout does **not** replace the per-IP rate limiter; it is a **second, complementary layer** keyed on a different dimension:

| Control | Keyed by | Catches | Blind spot it leaves |
|---------|----------|---------|----------------------|
| **Rate limit** (VULN-7, kept unchanged) | source **IP** | one IP flooding *any* POST (default 5 / 60 s) | a *distributed* attack — many IPs each trying one account a few times |
| **Account lockout** (this feature) | **account** (`users.id`) | one account guessed from *many* IPs / over time | a *spray* across many accounts (1 try each) — which the per-IP limiter still catches |

Because the two controls are keyed differently, each closes the other's gap. The rate limiter stays **registered and unchanged** (`main.py` / `core/rate_limit.py` are not touched); see §2.3.

The feature is built entirely on the project's existing primitives, with **no new third-party dependency**:

- Lockout state lives **server-side on the user's row** — two new columns — mirroring the schema-on-`users` precedent set by Continue-with-Google (v1.0.3) and Email Verification (v1.0.4). (Contrast the rate limiter, whose per-IP counters are intentionally in-memory: lockout is per-account state that should survive a restart, exactly like `verification_token`.)
- Lockout thresholds are read from the environment / git-ignored `.env` through the existing **`core/config.py`** loader — the same mechanism that already holds `EMAIL_VERIFICATION_TTL_SECONDS` (no hardcoded magic numbers; tunable for demos).
- All new SQL is **parameterized** (VULN-1). The lock check runs **before** the bcrypt verify, so a locked account never burns a hash (and an attacker cannot CPU-grind bcrypt on a locked account).
- The chosen **consecutive-failure** counter is reset to zero on any correct password, so a single later success clears the chain.

**Login posture:** **block-authentication-while-locked.** `auth_service.login()` checks the lock **first**; if the account is locked it returns `401 {"error": "<message with countdown>", "locked": true, "retry_after": <seconds>}` and writes **no** session, regardless of whether the submitted password is correct. The login page already renders `data.error` inline, so the countdown message is surfaced with **no template change**.

**Enumeration trade-off (deliberately accepted).** The lock message reveals that the named account exists, which is a small, intentional relaxation of the app's otherwise-strict login enumeration resistance. This is the product owner's chosen behaviour ("show the lock + countdown" — best UX, matches the spec's "cooldown timer"). The generic `401 {"error": "Invalid username or password"}` is **preserved** for every other failure (non-existent username, wrong-but-not-yet-locked password), so the relaxation is limited strictly to the locked state. See §2.4 and NFR-03.

This feature does **not** change any of the eight closed vulnerabilities. After this change, all eight remain closed and the app gains its **third** database-schema change.

The implementation touches:

- One new backend module: `backend/app/services/lockout_service.py` (lock-state helpers, parameterized SQL, shared by login and resend).
- The existing `backend/app/core/config.py` (two lockout settings + no new gate), `backend/app/db/session.py` (additive migration, two columns), `backend/app/services/auth_service.py` (`login()` enforces the lock), `backend/app/services/verification_service.py` (`resend_for_credentials()` shares the same enforcement).
- `.env.example`, `README.md`, and `CLAUDE.md` (documentation).

**No other file is touched.** In particular, `backend/app/main.py`, `backend/app/core/security.py`, `backend/app/core/csrf.py`, `backend/app/core/rate_limit.py`, `backend/app/core/oauth.py`, `backend/app/core/mailer.py`, `backend/app/services/oauth_service.py`, `backend/app/api/routes/auth.py`, and every template / CSS file remain byte-for-byte unchanged. No dependency is added.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- **Schema (additive, idempotent — third-ever schema change).** Add two columns to `users` in `init_db()`:
  - `failed_login_attempts INTEGER DEFAULT 0` — count of consecutive failed credential checks since the last success / lock.
  - `locked_until REAL` — Unix epoch seconds (`time.time()`-based) until which the account is locked, or `NULL` when not locked.
  - The migration adds any missing column with `ALTER TABLE users ADD COLUMN ...`, never dropping a row, exactly like the v1.0.3 / v1.0.4 migrations. **No grandfather `UPDATE` is needed:** the column defaults (`0` / `NULL`) already mean "no failures, not locked", so every existing row starts in the correct state.
- **Lockout configuration (`core/config.py`).** Read two settings from the environment / `.env`, both with safe defaults (no secret involved):
  - `ACCOUNT_LOCKOUT_MAX_ATTEMPTS` (default `6`) — the number of consecutive failures that triggers a lock.
  - `ACCOUNT_LOCKOUT_DURATION_SECONDS` (default `3600`, i.e. **1 hour**) — how long the lock lasts.
  - No new `is_*_configured()` gate: the feature is always on (it has safe defaults and needs no external service).
- **Lockout service (`services/lockout_service.py`, new).** Pure-ish helpers, all parameterized SQL, importable by both `auth_service` and `verification_service` without a circular import (it imports only `time`, `core.config`, and `db.session`):
  - `seconds_remaining(row) -> int` — given a `users` row, return the remaining lock seconds (`0` if `locked_until` is `NULL` or already in the past). No DB access (reads the already-fetched row).
  - `register_failure(user_id, current_attempts) -> int` — record one failed credential check via a **parameterized** `UPDATE`. If this failure reaches `ACCOUNT_LOCKOUT_MAX_ATTEMPTS`, set `locked_until = now + ACCOUNT_LOCKOUT_DURATION_SECONDS` **and reset `failed_login_attempts = 0`** in the same statement, returning the lock duration (`> 0`); otherwise just persist the incremented count and return `0`.
  - `reset(user_id) -> None` — `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?` (parameterized); called after any correct password.
  - `lock_message(remaining_seconds) -> str` — a fixed, server-controlled sentence with a minute-granularity countdown ("Account locked due to too many failed login attempts. Try again in about N minutes.").
  - Bookkeeping writes (`register_failure` / `reset`) are wrapped to **fail open** (log and return `0` / proceed) on any unexpected DB error — a broken lockout must never deny all logins, mirroring the rate limiter's NFR-07 posture.
- **Login enforcement (`services/auth_service.py`, `login()` only).**
  1. Fetch the user row by username (existing parameterized `SELECT *`).
  2. **Lock gate (before bcrypt):** if the row exists and `lockout_service.seconds_remaining(row) > 0`, return `401 {"error": lock_message, "locked": true, "retry_after": remaining}` immediately — no bcrypt verify, no session.
  3. Verify the password with bcrypt (unchanged primitive).
     - **Correct:** call `lockout_service.reset(user_id)`, then run the existing `is_verified` gate (unchanged), then write the session (unchanged).
     - **Incorrect, existing user:** call `lockout_service.register_failure(...)`; if it returns `> 0` (this miss triggered the lock) return the locked `401`, else return the existing generic `401 {"error": "Invalid username or password"}`.
     - **Incorrect, no such user:** return the existing generic `401` (no row to lock — lockout only protects real accounts).
- **Resend shares the same enforcement (`services/verification_service.py`, `resend_for_credentials()` only).** Because resend re-checks `username + password` with bcrypt, it is a second brute-force surface that must share the **same** counter (so an attacker cannot get N tries on `/login` plus N more on `/verify/resend`). The function's `SELECT` additionally fetches `failed_login_attempts, locked_until`; it applies the same lock gate, `register_failure` on a bad password, and `reset` on a correct one — then proceeds with its existing already-verified / re-issue / send branches.
- **Config docstring.** Update `core/config.py`'s module docstring to mention the account-lockout settings (no behaviour change to the Google / SMTP logic).
- **`.env.example`.** Append two commented placeholders (`ACCOUNT_LOCKOUT_MAX_ATTEMPTS`, `ACCOUNT_LOCKOUT_DURATION_SECONDS`) with the defaults shown — values, not secrets.
- **Docs.** Update `README.md` (move feature #9 to "Done (v1.0.5)"; add a v1.0.5 release row; note that lockout complements — does not replace — rate limiting) and `CLAUDE.md` (integration subsection, Important-Rules entry, Specification-Hierarchy entry, Vulnerability-Map note).

### 2.2 Out of Scope (Intentionally)

- **No change to the rate limiter.** `core/rate_limit.py` and its wiring in `main.py` stay byte-for-byte unchanged. The default 5-POST / 60-s per-IP window remains the first-line flood control; lockout is layered on top (§2.3). The earlier idea of "remove rate limiting from login because lockout exists" is explicitly **rejected** — the two defend different attack shapes, and removing the limiter would re-open VULN-7 for `/signup`, `/verify/resend`, etc.
- **No permanent / admin-unlock lockout.** The lock is purely time-based and self-clears; there is no "locked forever until an admin resets it" state, no unlock email, and no admin endpoint. (Keeps the feature schema-light and avoids a worse self-inflicted DoS.)
- **No CAPTCHA, no progressive/exponential backoff, no per-IP-plus-account composite key.** A single flat threshold + fixed duration is the chosen model (item #9's "configured number … cooldown timer"). Exponential backoff is a documented future hardening, not this slice.
- **No lockout on `/profile/password`'s current-password check.** That endpoint already requires an authenticated session (an attacker brute-forcing it is already logged in), so it is a low-value surface; it is intentionally left out to keep the change surgical. (Could be added later by reusing `lockout_service`.)
- **No notification to the user that a lock occurred (email/SMS).** The only surfaced signal is the inline `401` lock message on the next attempt.
- **No new dependency.** `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged. Lockout uses stdlib `time` + the existing `sqlite3`/`config` plumbing.

### 2.3 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

- **VULN-1 (SQL Injection):** every statement in `lockout_service.py` and the modified `login()` / `resend_for_credentials()` SELECT uses parameterized `?` placeholders. No string concatenation.
- **VULN-2 (Stored XSS):** no new value is rendered into any template; the lock message is a fixed, server-controlled string surfaced via the login page's existing `errorDiv.textContent` (text node assignment, not HTML).
- **VULN-3 (Reflected XSS):** `/search` is untouched; the lock message reflects no attacker input (it contains only a server-computed minute count).
- **VULN-4 (Session Hijacking):** `main.py` is not modified; the lockout thresholds come from env/`.env` (and have safe non-secret defaults), never hardcoded business secrets. A locked account is refused a session.
- **VULN-5 (Weak Password Storage):** `core/security.py` is unchanged; lockout adds no password handling. The lock gate runs **before** `verify_password`, so bcrypt remains the sole authentication primitive on the unlocked path.
- **VULN-6 (Exposed Database):** no `/download/db` route exists; none is added.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` stays registered and unchanged. Lockout is **additive** defense in depth, not a replacement (§2.1, §2.2).
- **VULN-8 (CSRF):** `POST /login` and `POST /verify/resend` keep their hidden `csrf_token`; `CSRFMiddleware` still validates them. No route signature changes.

### 2.4 Explicit Non-Goals

- This feature does **not** weaken the generic-`401` enumeration resistance for anything other than the **locked** state, which the product owner deliberately chose to surface (NFR-03). Non-existent usernames and not-yet-locked wrong passwords keep the identical generic `401`.
- This feature does **not** extend or "refresh" the lock on attempts made *during* the locked window — the lock gate returns before counting, so hammering a locked account does not lengthen the lock (the rate limiter throttles the hammering). The lock duration is fixed at issue time.
- This feature does **not** introduce a template engine, JS framework, or new UI element. The countdown rides the existing `#error-message` element on `login.html`.
- This feature does **not** modify `signup()`, `change_password()`, `password_meets_policy()`, `verify_email_token()`, or any route handler.

---

## 3. Affected Files

The change MUST touch only the following files (beyond this spec/plan pair and the prompt docs).

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/services/lockout_service.py` | **New** | `seconds_remaining()`, `register_failure()`, `reset()`, `lock_message()` — parameterized SQL, fail-open writes |
| `backend/app/core/config.py` | Modified | `ACCOUNT_LOCKOUT_MAX_ATTEMPTS` (default 6) + `ACCOUNT_LOCKOUT_DURATION_SECONDS` (default 3600); docstring note |
| `backend/app/db/session.py` | Modified | Additive idempotent migration (2 columns); no grandfather needed |
| `backend/app/services/auth_service.py` | Modified | `login()`: lock gate before bcrypt; reset on success; register failure on bad password |
| `backend/app/services/verification_service.py` | Modified | `resend_for_credentials()`: share the same lock gate / reset / register-failure |
| `.env.example` | Modified | Commented lockout placeholders (defaults shown) |
| `README.md` | Modified | Feature #9 → Done (v1.0.5); release row; "complements rate limiting" note |
| `CLAUDE.md` | Modified | Integration subsection, Important-Rules entry, hierarchy + vuln-map entries |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` — middleware wiring / `SECRET_KEY` / `RATE_LIMIT_*` / port (VULN-4 / VULN-7 / VULN-8 closures). The lockout logic is service-layer; no middleware is added.
- `backend/app/core/rate_limit.py` — rate-limit middleware (VULN-7 closure) stays exactly as-is.
- `backend/app/core/security.py` — bcrypt (VULN-5 closure).
- `backend/app/core/csrf.py` — CSRF middleware (VULN-8 closure).
- `backend/app/core/oauth.py`, `backend/app/core/mailer.py`, `backend/app/services/oauth_service.py` — unrelated.
- `backend/app/api/routes/auth.py` — `login_post` / `verify_resend` already forward to the service functions and return their JSON unchanged; no edit needed.
- All templates (`login.html`, `signup.html`, `dashboard.html`, `profile.html`, `check_email.html`, `verify_result.html`, `email_not_configured.html`, `oauth_not_configured.html`) and `frontend/static/css/styles.css` — the lock message rides the existing `#error-message` element.
- `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` — no dependency change.

---

## 4. Functional Requirements

### FR-01: Additive, Idempotent Schema Migration
- `init_db()` MUST add `failed_login_attempts INTEGER DEFAULT 0` and `locked_until REAL` to a fresh `CREATE TABLE users`, and MUST add either that is missing from a pre-existing DB via `ALTER TABLE users ADD COLUMN ...`. No row is dropped or rewritten.
- No grandfather `UPDATE` is run: the defaults (`0` / `NULL`) already place every existing row in the "no failures, unlocked" state.

### FR-02: Lockout Configuration
- `config.ACCOUNT_LOCKOUT_MAX_ATTEMPTS` MUST be read from the environment as an `int`, defaulting to `6`.
- `config.ACCOUNT_LOCKOUT_DURATION_SECONDS` MUST be read from the environment as an `int`, defaulting to `3600`.
- Neither value is a secret; both are documented in `.env.example` with their defaults. No `is_*_configured()` gate is added (the feature is always on).

### FR-03: Lock-State Helpers (`lockout_service.py`)
- `seconds_remaining(row) -> int` MUST return `0` when `row["locked_until"]` is `NULL` or `<= time.time()`, else the integer seconds remaining. It MUST NOT open a DB connection (it reads the already-fetched row).
- `register_failure(user_id, current_attempts) -> int` MUST, via parameterized SQL, set the new consecutive count to `current_attempts + 1`. If that count `>= ACCOUNT_LOCKOUT_MAX_ATTEMPTS`, it MUST set `locked_until = time.time() + ACCOUNT_LOCKOUT_DURATION_SECONDS` AND `failed_login_attempts = 0` in the same `UPDATE`, and return `ACCOUNT_LOCKOUT_DURATION_SECONDS` (`> 0`). Otherwise it MUST persist the incremented count and return `0`.
- `reset(user_id) -> None` MUST set `failed_login_attempts = 0, locked_until = NULL` via parameterized `UPDATE`.
- `lock_message(remaining_seconds) -> str` MUST return a fixed, server-controlled string containing a minute-granularity countdown and no attacker input.
- `register_failure` and `reset` MUST fail open (log + return `0` / proceed) on any unexpected DB exception; they MUST NOT propagate an exception into the calling handler.

### FR-04: Login Enforces the Lock (before bcrypt)
- After fetching the user row, if the row exists and `seconds_remaining(row) > 0`, `login()` MUST return `JSONResponse({"error": lock_message(remaining), "locked": true, "retry_after": remaining}, status_code=401)` **without** calling `verify_password` and **without** writing a session.
- On a correct password, `login()` MUST call `lockout_service.reset(user_id)` **before** the `is_verified` gate, so the counter clears even for a correct-password-but-unverified login.
- On a wrong password for an existing user, `login()` MUST call `lockout_service.register_failure(user_id, row["failed_login_attempts"])`; if it returns `> 0`, return the locked `401`; otherwise return the existing generic `401 {"error": "Invalid username or password"}`.
- On a wrong password for a non-existent user, `login()` MUST return the existing generic `401` (no counter to touch).

### FR-05: Resend Shares the Same Lock Counter
- `resend_for_credentials()`'s `SELECT` MUST additionally fetch `failed_login_attempts` and `locked_until`.
- It MUST apply the **same** lock gate (locked → `401` locked response, before bcrypt), the **same** `register_failure` on a wrong password, and the **same** `reset` on a correct password — operating on the **same** `users` row, so login and resend share one counter.
- Its existing branches (generic `401` for bad creds, `200` already-verified, `200` sent, `400` send-failed) are otherwise preserved.

### FR-06: Lock Response Shape
- A locked response MUST be HTTP `401` with a JSON body containing `"locked": true`, a human-readable `"error"` string (the countdown message), and `"retry_after"` (integer seconds). The `login.html` script renders `data.error` into `#error-message`; because `data.locked` is truthy and `data.unverified` is absent, the resend affordance stays hidden (no template change).

### FR-07: Counter / Lock Reset Semantics
- A correct password resets the counter to `0` and clears any lock (`reset`).
- Reaching the threshold sets a fresh `locked_until` and zeroes the counter, so that when the lock expires the account has a full new allowance (no instant re-lock on the first post-expiry miss).
- An attempt made while locked does NOT increment the counter or extend the lock (the gate returns first).
- A `locked_until` timestamp left in the past after expiry is harmless (treated as unlocked by `seconds_remaining`) and is cleared on the next successful login.

### FR-08: Parameterized SQL Everywhere (VULN-1 Preserved)
- Every SQL statement added or modified by this feature MUST use `?` placeholders with a separate parameter list. String concatenation into SQL is forbidden.

### FR-09: Rate Limiting Unchanged (VULN-7 Preserved)
- `RateLimitMiddleware`, its registration in `main.py`, and the `RATE_LIMIT_*` env handling MUST remain byte-for-byte unchanged. Lockout is added alongside it.

### FR-10: No New Dependency, No Other Schema
- Only `failed_login_attempts` and `locked_until` are added to `users`. No other column. No entry is added to `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock`.

### FR-11: Untouched Functions / Files
- `signup()`, `change_password()`, `password_meets_policy()` (in `auth_service.py`), `verify_email_token()` and `start_verification()` (in `verification_service.py`), every route handler in `auth.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `main.py`, all templates, and all CSS MUST remain unchanged.

### FR-12: Frontend Surfaces the Lock via the Existing Error Path
- No template or CSS edit is made. The countdown is shown by the existing `errorDiv.textContent = data.error` path in `login.html`; the resend button (gated on `data.unverified`) stays hidden for a locked response.

---

## 5. Non-Functional Requirements

### NFR-01: Surgical Scope
Exactly the files in §3 change (plus the spec/plan/prompt docs). No `main.py`, no `core/rate_limit.py`, no `core/security.py`, no `core/csrf.py`, no route handler, no template, no CSS, no lockfile.

### NFR-02: Configuration, Not Hardcoded Magic Numbers
The threshold and duration come from `core/config.py` (env/`.env`) with documented defaults, mirroring `EMAIL_VERIFICATION_TTL_SECONDS`. Demos can set `ACCOUNT_LOCKOUT_MAX_ATTEMPTS=3 ACCOUNT_LOCKOUT_DURATION_SECONDS=30` to observe the lock quickly.

### NFR-03: Deliberate, Bounded Enumeration Trade-off
The lock message reveals that a named account exists — an intentional, product-owner-approved relaxation chosen for UX ("tell the user why they're blocked and when to retry"). It is bounded: only the **locked** state is distinguishable; every other failure keeps the identical generic `401`. This trade-off MUST be documented in the code comments, `CLAUDE.md`, and this spec.

### NFR-04: Fail-Open Bookkeeping
A DB error inside `register_failure`/`reset` MUST NOT deny a legitimate login. These writes fail open (log + proceed), matching the rate limiter's NFR-07 rationale: a broken lockout that refuses everyone is worse than a momentarily absent lockout. (Contrast `CSRFMiddleware`, which fails closed — different trade-off.)

### NFR-05: Defense in Depth With the Rate Limiter
Lockout (per-account) and the rate limiter (per-IP) are independent layers; neither is sufficient alone, and removing either re-opens a gap. The spec, README, and CLAUDE.md MUST state that lockout complements rather than replaces VULN-7.

### NFR-06: Performance — Lock Check Before bcrypt
The lock gate MUST short-circuit before `verify_password`, so a locked (or attacker-targeted) account never triggers the intentionally-slow bcrypt hash. This also denies an attacker a bcrypt-CPU-burn oracle on locked accounts.

### NFR-07: Consistency With Existing Patterns
Thin route → service (unchanged routes); `get_db()` + `try/finally` per call; parameterized SQL; env config via `core/config.py`; additive idempotent migration like v1.0.3/v1.0.4; `time.time()`-based epoch column like `verification_token_expires`; stdlib only.

### NFR-08: No Information Leakage Beyond the Deliberate Message
The lock message contains only a server-computed minute count. DB exceptions are logged server-side, never reflected. No token, hash, attempt count, or internal field is exposed to the client.

---

## 6. Success Paths

### SP-01: Normal Login Unaffected
1. A verified user submits the correct password on the first try.
2. The lock gate sees `locked_until = NULL` → `seconds_remaining = 0`; bcrypt verifies; `reset()` zeroes the (already-zero) counter; the session is written; `200 {"success": true, "redirect": "/welcome"}`.

### SP-02: Failures Accumulate, Then Lock
1. An attacker submits 6 wrong passwords for `alice` (across one or many IPs, subject to the per-IP rate limit).
2. Failures 1–5 each return the generic `401` and increment `failed_login_attempts`.
3. Failure 6 triggers `register_failure` to set `locked_until = now + 3600` and zero the counter; the response is `401 {"locked": true, "retry_after": ~3600, "error": "Account locked … try again in about 60 minutes."}`.

### SP-03: Locked Account Refuses Even the Correct Password
1. During the locked window, `alice` (the real owner) submits the **correct** password.
2. The lock gate fires before bcrypt → `401 {"locked": true, ...}`. No session. (This is the deliberate cost of lockout; the owner waits or the demo lowers the duration.)

### SP-04: Lock Expires → Fresh Allowance
1. After `locked_until` passes, `alice` submits the correct password.
2. `seconds_remaining = 0` → bcrypt verifies → `reset()` clears the stale past `locked_until` → session written → `200`.

### SP-05: Resend Shares the Counter
1. An attacker exhausts some attempts on `POST /login`, then pivots to `POST /verify/resend` with wrong passwords for the same account.
2. The shared counter continues from where login left off; the account locks at the **combined** 6th failure, and `/verify/resend` returns the same locked `401`.

---

## 7. Edge Cases

- **EC-01 — Wrong password, non-existent username:** generic `401`; no row, so nothing is counted or locked (lockout protects only real accounts).
- **EC-02 — Correct password while not locked, but unverified:** `reset()` runs (counter cleared), then the existing `401 {"unverified": true}` is returned. The unverified state is independent of lockout.
- **EC-03 — Correct password during an active lock:** still `401 {"locked": true}` (gate precedes verify). The owner cannot "log in past" their own lock.
- **EC-04 — First miss after the lock expires:** counter was zeroed at lock time, so this is failure #1 again — no instant re-lock.
- **EC-05 — Attempts during the locked window:** rejected by the gate without counting; the lock duration is not extended. The per-IP rate limiter throttles rapid repeats (`429`).
- **EC-06 — Concurrent failed logins (same account):** each `register_failure` is a short committed `UPDATE`; in this single-process SQLite lab the worst case is an off-by-one in the count near the threshold, which only changes *when* the lock trips by one attempt — acceptable (documented).
- **EC-07 — DB error during `register_failure`/`reset`:** fail open — logged, login proceeds on its normal path (NFR-04).
- **EC-08 — Pre-migration DB:** existing rows gain the two columns at defaults (`0` / `NULL`) and are immediately usable; no row is locked by the migration.
- **EC-09 — Google / grandfathered accounts:** they authenticate through `login()` only if they have a password; OAuth-only rows have `password = NULL` and already fail closed in `verify_password`. Lockout neither helps nor harms them and never creates a session for them.
- **EC-10 — Operator sets `ACCOUNT_LOCKOUT_MAX_ATTEMPTS=0` or a negative value:** treated as "lock on the first failure" (defensive: the first `register_failure` returns a lock). Documented as an extreme tuning choice; default is `6`.

---

## 8. Acceptance Criteria

- **AC-01:** A fresh DB's `users` table has `failed_login_attempts` (default 0) and `locked_until` (default NULL) per `PRAGMA table_info(users)`.
- **AC-02:** A pre-existing DB gains both columns on first boot with existing rows reading `failed_login_attempts = 0`, `locked_until = NULL`; no row is locked and no grandfather `UPDATE` runs.
- **AC-03:** With defaults, the 6th consecutive wrong-password `POST /login` for an existing user returns `401` with `"locked": true` and a `retry_after` near `3600`; attempts 1–5 return the generic `401`.
- **AC-04:** During the lock, a `POST /login` with the **correct** password for that user returns `401 {"locked": true}` and writes no session.
- **AC-05:** After `locked_until` passes (e.g. with `ACCOUNT_LOCKOUT_DURATION_SECONDS=2`), the correct password returns `200` and the row reads `failed_login_attempts = 0`, `locked_until = NULL`.
- **AC-06:** A correct password before the threshold resets `failed_login_attempts` to `0`.
- **AC-07:** Failures on `POST /verify/resend` for the same account increment the **same** counter and can trigger / observe the lock (shared counter).
- **AC-08:** A wrong password for a **non-existent** username returns the generic `401` and creates/locks nothing.
- **AC-09:** All SQL in `lockout_service.py` and the modified `login()` / `resend_for_credentials()` uses `?` placeholders (no concatenation).
- **AC-10:** The lock gate runs before `verify_password` (no bcrypt call on a locked account) — verifiable by code inspection / ordering.
- **AC-11:** `git diff` is empty for `main.py`, `core/rate_limit.py`, `core/security.py`, `core/csrf.py`, `core/oauth.py`, `core/mailer.py`, `oauth_service.py`, `api/routes/auth.py`, every template, `styles.css`, and the lockfiles.
- **AC-12:** No new dependency: `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` unchanged.
- **AC-13:** `uv run backend/app/main.py` boots with no traceback; a normal correct-password login still succeeds (`200`).
- **AC-14:** VULN-1…VULN-8 all remain closed (parameterized SQL; bcrypt intact and still the unlocked-path authenticator; rate-limit + CSRF middleware unchanged; no `/download/db`; env-sourced config; no raw reflection).
- **AC-15:** `README.md` shows feature #9 as "Done (v1.0.5)", adds a v1.0.5 release row, and states lockout complements rate limiting. `CLAUDE.md` has the new subsection, rule, hierarchy, and vuln-map entries.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Columns on fresh DB | `rm` DB, boot | `PRAGMA table_info(users)` shows `failed_login_attempts`, `locked_until` |
| TC-02 | Migration on old DB | Pre-migration DB copy | Both columns added; existing rows `0` / `NULL`; not locked |
| TC-03 | Lock after threshold | Existing user, defaults | 6th wrong `POST /login` → `401 {"locked":true,"retry_after":~3600}` |
| TC-04 | Pre-threshold generic 401 | Existing user | Wrong-password attempts 1–5 → generic `401`, no `locked` flag |
| TC-05 | Correct pw during lock | Account locked | `POST /login` correct pw → `401 {"locked":true}`, no session |
| TC-06 | Auto-unlock | `DURATION_SECONDS=2`, locked, wait 3 s | correct pw → `200`; row `0` / `NULL` |
| TC-07 | Reset on success | 3 failures then correct pw | `failed_login_attempts` back to `0` |
| TC-08 | Shared counter via resend | 3 login fails + 3 resend fails | account locks on the 6th (combined) |
| TC-09 | No-such-user | wrong username | generic `401`; no row created/locked |
| TC-10 | No bcrypt on locked | Account locked | lock gate returns before `verify_password` (inspection) |
| TC-11 | Fail-open bookkeeping | Simulated DB error in `register_failure` | login still returns its normal `401`/`200`, error logged |
| TC-12 | Parameterized SQL | Repo checkout | `lockout_service.py` uses `?` placeholders; no concatenation |
| TC-13 | Untouched files | Repo checkout | `git diff --stat` empty for the forbidden files + lockfiles |
| TC-14 | No new dep | Repo checkout | `git diff --stat` empty for pyproject/uv.lock |
| TC-15 | App boots + normal login | Repo checkout | `uv run …` no traceback; correct pw → `200` |
| TC-16 | Docs updated | Repo checkout | feature #9 "Done (v1.0.5)"; v1.0.5 row; "complements rate limiting" note; CLAUDE entries present |

---

## 10. Verification Steps

Run from the repo root. (Use a fast lockout window for the demo.)

### 10.1 Schema (AC-01, TC-01)
```bash
rm -f vulnerable_app.db
uv run backend/app/main.py &
sqlite3 vulnerable_app.db "PRAGMA table_info(users);" | grep -E 'failed_login_attempts|locked_until'   # both present
```

### 10.2 Lock After Threshold (AC-03, TC-03, TC-04)
```bash
# Create + verify a user first (SMTP-configured signup → click link), then:
TOKEN=$(curl -s -c jar.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
for i in 1 2 3 4 5 6; do
  curl -s -b jar.txt -X POST http://localhost:3001/login \
    --data-urlencode 'username=alice' --data-urlencode 'password=wrongpass' \
    --data-urlencode "csrf_token=$TOKEN" -w "\nattempt$i=%{http_code}\n"
done
# attempts 1-5: {"error":"Invalid username or password"}; attempt 6: {"locked":true,"retry_after":...}
```
> Note: the default per-IP rate limit (5 POST / 60 s) will return `429` before the 6th attempt from a single IP — expected. To exercise lockout from one IP, temporarily raise it (`RATE_LIMIT_MAX=100 uv run backend/app/main.py`) or space the requests out. This is the rate limiter and lockout working *together*.

### 10.3 Locked Refuses Correct Password + Auto-Unlock (AC-04, AC-05, TC-05, TC-06)
```bash
# With ACCOUNT_LOCKOUT_DURATION_SECONDS=3 and the account locked:
curl -s -b jar.txt -X POST http://localhost:3001/login \
  --data-urlencode 'username=alice' --data-urlencode 'password=CorrectHorse1!' \
  --data-urlencode "csrf_token=$TOKEN" -w "\nlocked=%{http_code}\n"    # 401 locked
sleep 3
curl -s -b jar.txt -X POST http://localhost:3001/login \
  --data-urlencode 'username=alice' --data-urlencode 'password=CorrectHorse1!' \
  --data-urlencode "csrf_token=$TOKEN" -w "\nunlocked=%{http_code}\n"  # 200 success
sqlite3 vulnerable_app.db "SELECT failed_login_attempts, locked_until FROM users WHERE username='alice';"   # 0|
```

### 10.4 File Audit (AC-11, AC-12, TC-13, TC-14)
```bash
git diff --stat -- backend/app/main.py backend/app/core/rate_limit.py backend/app/core/security.py \
  backend/app/core/csrf.py backend/app/core/oauth.py backend/app/core/mailer.py \
  backend/app/services/oauth_service.py backend/app/api/routes/auth.py \
  frontend/ pyproject.toml backend/pyproject.toml uv.lock     # all empty
```

Expected `git status --porcelain` (declared files + docs only):
```
?? backend/app/services/lockout_service.py
 M backend/app/core/config.py
 M backend/app/db/session.py
 M backend/app/services/auth_service.py
 M backend/app/services/verification_service.py
 M .env.example
 M README.md
 M CLAUDE.md
?? .claude/specs/account-lockout.md
?? .claude/specs/account-lockout-plan.md
?? docs/prompts/account-lockout-spec-prompt.txt
?? docs/prompts/account-lockout-spec-plan-prompt.txt
?? docs/prompts/account-lockout-spec-execution-prompt.txt
```
