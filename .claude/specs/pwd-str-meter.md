# Software Specification Document — Password Strength Meter (Signup, Frontend-Only, Advisory)

**Version:** 1.0.0
**Last Updated:** 2026-06-16
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [Password Strength Meter — README "Feature Enhancements" #3](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the **Password Strength Meter** enhancement on the signup form. It is item #3 in the README's "Feature Enhancements" table ("A real-time indicator on the signup form that displays password strength and the acceptance criteria as the user types"). The feature is **purely additive UX**: it shows the user how strong their typed password is, with a live checklist of five acceptance criteria, while they type into the `#password` input on `frontend/templates/signup.html`.

The five criteria are:

1. Minimum length of 8 characters.
2. At least one lowercase letter (`a–z`).
3. At least one uppercase letter (`A–Z`).
4. At least one digit (`0–9`).
5. At least one special character (any character that is not `[A-Za-z0-9]`).

A simple "strength level" is derived from how many of the five criteria are met — `Very Weak`, `Weak`, `Fair`, `Good`, `Strong` — and is shown as a labeled text plus a colored fill in a horizontal bar. Both the level and the checklist update on every `input` event of the password field, with **no debounce** (the work is trivial and per-keystroke feedback is the whole point).

The feature is **frontend-only and advisory**:

- No server-side policy change. The backend continues to accept any non-empty password (the only validation in `auth_service.signup()` is `if not username or not email or not password`). A user who submits a "Very Weak" password still successfully creates an account — the meter informs, it does **not** gate.
- No new HTTP endpoint, no new form field, no new request shape, no new response shape, no new session key, no new DB column.
- No third-party JS library, no CSS framework, no build step. The implementation uses vanilla DOM APIs and the existing CSS-custom-property theming (the same `data-theme` light/dark switch the rest of the app uses).
- No accessibility regressions: the meter is announced via `aria-live="polite"` so screen-reader users hear strength updates without being interrupted; the checklist items use semantic list markup.

This enhancement does **not** touch any of the eight closed vulnerabilities. The signup form's CSRF hidden input (VULN-8), the bcrypt hashing on the server (VULN-5), the parameterized signup INSERT (VULN-1), the rate-limit middleware (VULN-7), the env-sourced session secret (VULN-4), the escaped dashboard username (VULN-2), the escaped `/search` reflection (VULN-3), and the removed `/download/db` route (VULN-6) all remain byte-for-byte intact.

The implementation lives in:

- A new `<div>` block inside `frontend/templates/signup.html`, placed between the `password` `<div class="form-group">` and the `confirm_password` `<div class="form-group">`.
- A new inline `<script>` block in the same template (mirroring the existing password-match script's style — vanilla JS, no module system).
- New CSS rules appended to `frontend/static/css/styles.css`, using the same CSS-custom-property pattern as the rest of the file so light and dark themes are handled automatically.

**No other file is touched.** In particular, `login.html`, `dashboard.html`, and every backend file remain unchanged.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- Add a new strength-meter UI block inside the signup form, between the `password` field and the `confirm_password` field. It contains:
  - A horizontal bar (`.password-strength-bar`) whose colored fill (`.password-strength-bar-fill`) grows from 0% to 100% as the password gets stronger.
  - A text label (`.password-strength-label`) showing the current strength level (one of `Very Weak`, `Weak`, `Fair`, `Good`, `Strong`, or an empty initial state).
  - A `<ul class="password-criteria-list">` with five `<li>` items, one per acceptance criterion, each showing a leading status marker (`✗` while unmet, `✓` once met) and the criterion's human-readable description.
- Add a vanilla JS block at the bottom of `signup.html` that, on every `input` event on `#password`, recomputes the five criteria, updates each `<li>`'s state class and marker, and updates the strength bar's fill width, fill color, and label text.
- Append CSS rules to `frontend/static/css/styles.css` for the new classes, using the existing `var(--...)` custom-property pattern so light and dark themes share one rule set. Define new color custom properties on `:root` (light) and `[data-theme="dark"]` for the five strength levels and for met/unmet criterion text.
- Update `README.md` to move "Password Strength Meter" out of the "Planned" rows of the Feature Enhancements table into a "Done" row, mirroring the existing "Dark Mode Toggle" entry.
- Update `CLAUDE.md` to:
  - Add a short "Password Strength Meter" subsection under "Frontend-Backend Integration" describing the advisory-UX posture (mirrors the existing "Theme" bullet).
  - Add an "Important Rules" entry: the meter is frontend-only and advisory; do not push strength state into the backend, the session, or the database, and do not block form submission on a weak password.
  - Append the new spec/plan pair to the Specification Hierarchy list.

### 2.2 Out of Scope (Intentionally)

- **No backend policy.** `auth_service.signup()` MUST NOT add a length check, a character-class check, a regex check, or any other server-side strength gate. The bcrypt hashing call MUST stay byte-for-byte; the parameterized INSERT MUST stay byte-for-byte.
- **No form-submission gate.** The signup form's existing client-side submit handler (the password-match check) is the **only** thing that can `preventDefault()`. The strength meter never calls `preventDefault()`, never disables the submit button, and never sets `required` / `pattern` / `minlength` attributes on the password input.
- **No login-form meter.** `login.html` is unchanged. Showing strength on login would be pointless (the user is not choosing a new password) and would risk a misleading "weak password" warning on a legitimately strong existing password that was typed into a field with no live validation.
- **No "have-i-been-pwned" check, no zxcvbn library, no dictionary lookup, no entropy estimator beyond the five-criterion count.** The strength level is **purely** the count of satisfied criteria — 0/5 → `Very Weak`, 1/5 → `Weak`, 2/5 → `Fair`, 3/5 or 4/5 → `Good`, 5/5 → `Strong`. The spec deliberately favors a transparent, auditable mapping over a sophisticated one. Students reading the source learn the mapping in five lines.
- **No password reveal toggle.** The existing `type="password"` input stays as-is; adding an "eye" toggle is its own UX feature and out of scope.
- **No debounce, throttle, or async update.** The compute work per keystroke is five constant-time character-class checks and one DOM update — well under a millisecond. Debouncing would only add perceived latency.
- **No persistence.** No `localStorage`, no cookie, no session field. The strength state lives entirely in the DOM and dies when the page is unloaded. This mirrors how the password-match check works today.
- **No telemetry, no event posting, no analytics.** The meter does not call `fetch`, `XMLHttpRequest`, `navigator.sendBeacon`, or any other network primitive. Whatever the user types into the password field never leaves their browser via this feature.
- **No keyboard-layout-specific or locale-specific class definitions.** "Lowercase" is `[a-z]`, "uppercase" is `[A-Z]`, "digit" is `[0-9]`, "special" is everything else. The spec is intentionally ASCII-anchored to keep the mapping explainable in a single sentence; a Unicode-aware definition is a future enhancement, not this one.
- **No CSRF interaction.** The meter does not read, modify, or submit the `csrf_token` hidden input. The CSRF middleware sees the signup POST exactly as it does today.
- **No new dependency.** `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged.

### 2.3 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

Every already-closed fix MUST remain byte-for-byte intact after this change:

- **VULN-1 (SQL Injection):** `auth_service.py` and `/search` keep their parameterized `?` queries. This feature does not touch `auth_service.py` or `auth.py` at all.
- **VULN-2 (Stored XSS):** `welcome_page` keeps escaping `{{username}}` with `html.escape(..., quote=True)`. Unaffected — `dashboard.html` is not modified.
- **VULN-3 (Reflected XSS):** `/search` keeps escaping `q`, both row columns, and the exception text. Unaffected.
- **VULN-4 (Session Hijacking):** `main.py` keeps sourcing `SECRET_KEY` from the environment. Unaffected — `main.py` is not modified.
- **VULN-5 (Weak Password Storage):** `core/security.py` keeps bcrypt at rounds ≥ 12 and `verify_password`'s defensive `try/except`. Unaffected — `core/security.py` is not modified, and the meter does NOT replace, supplement, or pre-empt the server-side hashing.
- **VULN-6 (Exposed Database):** no `/download/db` route exists. Unaffected.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` stays registered. Unaffected — `main.py` and `core/rate_limit.py` are not modified.
- **VULN-8 (CSRF):** the `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` stays as the first child of `<form id="signup-form">`. The meter UI is inserted between two later `<div class="form-group">` blocks; it does not touch the hidden field, the form's `action`, or the form's `method`.

### 2.4 Explicit Non-Goals

- This feature does **not** change the password validation contract. A 1-character password is still accepted by the server; the meter just shows "Very Weak" with four red `✗` markers.
- This feature does **not** change the submit button's enabled state. It stays enabled at all times (modulo the existing browser-native `required` constraints already present on the inputs).
- This feature does **not** alter the password-match check (the existing submit-handler `preventDefault()` when password and confirm differ). That check stays exactly as it is.
- This feature does **not** introduce a new template engine, build step, JS module system, or transpiler. The implementation is one inline `<script>` block plus CSS rules in the existing single stylesheet.
- This feature does **not** add any `console.log` / `console.warn` calls in production code paths. (One-time defensive logs for caught exceptions are permitted; see §EC-04.)

---

## 3. Affected Files

The fix MUST touch only the following files. No other repository file may be created or modified.

| Path | Change Type | Purpose |
|------|-------------|---------|
| `frontend/templates/signup.html` | Modified | Insert the meter+checklist DOM between `password` and `confirm_password` form groups; add one inline `<script>` block driving the live updates |
| `frontend/static/css/styles.css` | Modified | Append rules for `.password-strength-meter`, `.password-strength-bar`, `.password-strength-bar-fill`, `.password-strength-label`, `.password-criteria-list`, `.password-criteria-item`, `.is-met` / `.is-unmet` modifier classes; add five strength-level color custom properties under `:root` and `[data-theme="dark"]` |
| `README.md` | Modified | Move "Password Strength Meter" from a "Planned" to a "Done (vX.Y.Z)" row in the Feature Enhancements table |
| `CLAUDE.md` | Modified | Add a short "Password Strength Meter" bullet under Frontend-Backend Integration; add an "Important Rules" entry; append the spec/plan pair to the Specification Hierarchy |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` — middleware wiring, `SECRET_KEY` sourcing, port binding (VULN-4 / VULN-7 / VULN-8 closures).
- `backend/app/services/auth_service.py` — parameterized queries + bcrypt verify (VULN-1 / VULN-5 closures).
- `backend/app/core/security.py` — bcrypt (VULN-5 closure).
- `backend/app/core/csrf.py` — synchronizer-token middleware (VULN-8 closure).
- `backend/app/core/rate_limit.py` — per-IP rate-limit middleware (VULN-7 closure).
- `backend/app/db/session.py` — SQLite schema and connection layer. **No schema column for strength state** — strength lives in the DOM, not the DB.
- `backend/app/api/routes/auth.py` — all route handlers, including `signup_page`, `signup_post`, `login_page`, `login_post`, `welcome_page`, `search_user`, `logout`, `index`.
- `frontend/templates/login.html` — login is not a place to choose a new password.
- `frontend/templates/dashboard.html` — no password field on the dashboard.
- `frontend/static/images/*` — no image change.
- `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, and every prior spec/plan pair.
- `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` — no dependency change.

---

## 4. Functional Requirements

### FR-01: Meter UI Lives Inside the Signup Form

- The meter DOM MUST be a single `<div class="password-strength-meter">` block inserted as a child of `<form id="signup-form">`, positioned **between** the existing `<div class="form-group">` that wraps the `#password` input and the existing `<div class="form-group">` that wraps the `#confirm_password` input.
- The meter block MUST NOT wrap, replace, or move any other child of the form. The hidden `csrf_token` input MUST remain the **first** child of the form; the `username`, `email`, `password`, `confirm_password` form groups MUST remain in document order; the submit `<button>` MUST remain the last child.

### FR-02: Meter UI Structure

- The meter block MUST contain exactly these descendants, in this order:
  1. A `<div class="password-strength-bar">` whose child is `<div class="password-strength-bar-fill"></div>`. The fill element's width is driven by inline `style.width = "<n>%"` from the JS.
  2. A `<div class="password-strength-label" aria-live="polite"></div>`. Its text content is the current strength level name (or empty for an empty password).
  3. A `<ul class="password-criteria-list">` with **exactly five** `<li class="password-criteria-item">` children, one per criterion, each containing a leading `<span class="password-criteria-marker" aria-hidden="true">` (holding `✗` or `✓`) and a trailing text node describing the criterion. The five `<li>` elements MUST appear in this order, identified by stable `data-criterion` attributes:
     - `data-criterion="length"` → "At least 8 characters"
     - `data-criterion="lowercase"` → "At least one lowercase letter (a–z)"
     - `data-criterion="uppercase"` → "At least one uppercase letter (A–Z)"
     - `data-criterion="digit"` → "At least one digit (0–9)"
     - `data-criterion="special"` → "At least one special character"
- Each `<li>` MUST carry exactly one of two state classes at any time: `is-unmet` (default) or `is-met`.

### FR-03: Five Criterion Definitions (ASCII-Anchored)

- **length:** `password.length >= 8`.
- **lowercase:** `/[a-z]/.test(password)`.
- **uppercase:** `/[A-Z]/.test(password)`.
- **digit:** `/[0-9]/.test(password)`.
- **special:** `/[^A-Za-z0-9]/.test(password)`. Whitespace and all non-ASCII characters count as "special" by this definition.
- The five checks MUST be computed in JS only — no server round-trip, no async work.

### FR-04: Strength Level Mapping

- Let `met = number of criteria currently satisfied (0..5)`. The strength level name and bar-fill width and bar-fill color custom property MUST be:

| met | level name | fill width | fill color custom property |
|-----|------------|------------|-----------------------------|
| 0   | `""` (empty) | `0%`    | `--strength-color-empty`   |
| 1   | `Very Weak`  | `20%`   | `--strength-color-very-weak` |
| 2   | `Weak`       | `40%`   | `--strength-color-weak`    |
| 3   | `Fair`       | `60%`   | `--strength-color-fair`    |
| 4   | `Good`       | `80%`   | `--strength-color-good`    |
| 5   | `Strong`     | `100%`  | `--strength-color-strong`  |

- The "empty" row (met == 0) MUST be the state shown when `#password.value === ""` AND when the user has typed only characters that satisfy zero criteria (e.g., a single space — which is technically "special" so met=1 → `Very Weak`; only a literal empty input is "empty").
- The label text MUST be set via `textContent` (never `innerHTML`) so any future change to the level-name source cannot become an XSS vector.

### FR-05: Live Update on Every Keystroke

- The JS MUST attach a single `input` event listener to `#password`. Every `input` event MUST trigger:
  1. Recompute the five criterion booleans.
  2. For each `<li>`, toggle `is-met` / `is-unmet` and set the marker `<span>`'s `textContent` to `"✓"` or `"✗"` accordingly.
  3. Set the fill `<div>`'s inline `style.width` and `style.backgroundColor` (the latter via `var(--strength-color-*)` resolved through a style mutation, or via toggling a state class on the fill element — see §FR-06).
  4. Set the label `<div>`'s `textContent` to the level name.
- No `change` listener, no `keyup` listener, no `paste` listener — `input` covers all three plus IME composition.
- No debounce.

### FR-06: Color Mapped via State Class, Not Inline Color

- To keep the JS free of color literals and let CSS handle theme switching:
  - The fill `<div>` MUST carry **exactly one** state class at any time, drawn from this fixed set: `strength-empty`, `strength-very-weak`, `strength-weak`, `strength-fair`, `strength-good`, `strength-strong`. The JS swaps the class on every update; the CSS rule for each state class sets `background-color: var(--strength-color-<state>)`.
  - The same state class MUST also be applied to the outer `.password-strength-meter` block, so the label text color can pick up the same custom property if desired without re-reading state.
- The inline `style.width` is the **only** inline style the JS may set on the fill `<div>`. No `style.color`, `style.backgroundColor`, `style.border`, etc.

### FR-07: ARIA / Accessibility

- The label `<div>` MUST carry `aria-live="polite"`. When the level changes, assistive tech reads the new level without interrupting in-flight speech.
- The criteria `<ul>` MUST carry `aria-label="Password requirements"` (or equivalent — see plan for exact text).
- Each `<li>`'s marker `<span>` MUST carry `aria-hidden="true"` so the `✓`/`✗` glyph is not announced redundantly with the surrounding text.
- The criterion text itself MUST be plain readable text inside the `<li>`, so screen readers read "At least 8 characters" rather than "✓ At least 8 characters" (the `✓` is decorative, the text already conveys "met" implicitly via the visible state — and the `aria-live` label provides the overall strength).
- No `role="alert"` on the label — `polite` is correct because the meter is advisory, not an error condition.

### FR-08: No Submit-Time Coupling

- The meter MUST NOT attach a `submit` listener to the form, MUST NOT call `form.checkValidity()`, MUST NOT call `event.preventDefault()`, MUST NOT toggle the `disabled` attribute of any element, and MUST NOT mutate the `required`, `pattern`, `minlength`, or `maxlength` attributes of the password input.
- The existing password-match submit handler (lines ~95–109 of the pre-fix `signup.html`) MUST remain byte-for-byte unchanged.

### FR-09: No Network, No Persistence

- The meter JS MUST NOT call `fetch`, `XMLHttpRequest.open`, `navigator.sendBeacon`, `localStorage.setItem`, `sessionStorage.setItem`, `document.cookie = ...`, or any other persistence / network API.
- The only DOM mutations permitted are: `textContent` writes on the label and the marker spans; class list toggles on the `<li>`s, on the fill `<div>`, and on the outer meter block; and the single inline `style.width` write on the fill `<div>`.

### FR-10: Initial State

- On `DOMContentLoaded` (or immediately if the script runs after the form), the meter MUST be in the "empty" state: fill width `0%`, fill state class `strength-empty`, label text `""`, every `<li>` carries `is-unmet`, every marker shows `✗`.
- The initial state MUST be set by reading the current `#password.value` (which is `""` on a fresh load and may be non-empty on a back-button restore) and running the same update path the `input` listener uses — i.e., the update function is called **once** at script start.

### FR-11: Standard-Library / Stdlib-Only on the Frontend Too

- No third-party JS, no `<script src=...>` to a CDN, no NPM package, no transpiler. The implementation uses only DOM APIs available in evergreen browsers since 2018: `querySelector`, `querySelectorAll`, `addEventListener`, `classList`, `textContent`, `style`, `dataset`.
- No CSS framework. Only hand-written rules appended to the existing `styles.css`, using existing CSS custom property conventions.

### FR-12: Theme Compatibility

- The five strength-color custom properties MUST be defined under both `:root` (light theme) and `[data-theme="dark"]`. The light-theme values use the existing PRD palette family (deep blue accents, warm reds/oranges for weak, greens for strong); the dark-theme values use the corresponding dimmer hues already established in the dark-mode toggle work.
- The criterion-met / criterion-unmet text colors MUST also use custom properties (`--criterion-met-color`, `--criterion-unmet-color`), so the bullets recolor automatically when the user toggles dark mode.

### FR-13: No Conflicting Class Names

- All new CSS classes are prefixed with `password-strength-` or `password-criteria-` to avoid collisions with existing classes (`.password-error`, `.form-group`, `.form-input`, `.form-label`, `.btn`, etc.). The single state-class set `is-met` / `is-unmet` is namespaced via the parent `.password-criteria-list` selectors so it cannot accidentally match other elements (rules use `.password-criteria-item.is-met`, never bare `.is-met`).

---

## 5. Non-Functional Requirements

### NFR-01: Frontend-Only, Advisory

- The feature is purely frontend UX. No backend behavior changes. A user who types `a` and submits gets the same backend response today and after this change: account created, redirect to `/login`.

### NFR-02: Surgical Scope

- Exactly four files change: `frontend/templates/signup.html`, `frontend/static/css/styles.css`, `README.md`, `CLAUDE.md`. No backend file changes. No new file is created.

### NFR-03: API Stability

- `POST /signup` request shape, response shape, status codes, and headers are byte-for-byte unchanged. `GET /signup` HTML response gains the new meter DOM and the new inline `<script>` but no headers change.

### NFR-04: Per-Keystroke Overhead

- The update path runs five constant-time regex tests + ~10 DOM mutations on a fixed set of 5 `<li>` elements and 3 single-element targets. Sub-millisecond on any modern device. No layout thrash (all reads first, then writes — see plan).

### NFR-05: No Information Leakage

- The meter never sends the password (or any derivative) over the network. It never writes the password (or any derivative) to `localStorage`, `sessionStorage`, IndexedDB, or `document.cookie`. The only place it lives is the `#password` input's value attribute, which is already where the browser keeps it.

### NFR-06: Resilience to Missing DOM

- If `#password` is missing (e.g., a future template refactor removes it), the meter init MUST exit cleanly without throwing. The script's top-level `if (!password) return;` guard achieves this.
- If any of the meter's internal DOM lookups fail (e.g., the `<ul>` or one `<li>` is missing), the init MUST also exit cleanly. No "partial meter" — either the whole UI wires up or none of it does.

### NFR-07: Fail-OPEN on Unexpected JS Errors

- The whole `input` listener body MUST be wrapped in a `try { ... } catch (e) { /* swallow; meter degrades to silent */ }`. The meter is advisory; a thrown exception here MUST NOT block typing, MUST NOT prevent form submission, and MUST NOT raise a visible error dialog. (Contrast with `CSRFMiddleware`'s fail-closed posture — the trade-off is different because a broken meter doesn't re-open a vulnerability.)

### NFR-08: Determinism

- For a given password string, the level name, bar width, fill state class, and per-`<li>` met/unmet state are a **pure function** of the string. No randomness, no timestamp dependency, no global state read.

### NFR-09: Zero Dependency Delta

- No entry added to `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock`. No `<script src=...>` to any CDN. No npm/yarn/pnpm artefact.

### NFR-10: Theme Switching Cost

- Toggling `data-theme` between `light` and `dark` MUST NOT require re-running the meter JS. The state class on the fill `<div>` + the CSS custom properties under each theme block handle the color swap automatically.

---

## 6. Success Paths

### SP-01: Empty Password (Page Load)

1. User visits `GET /signup`. The page renders with the meter DOM present but in its "empty" state: fill width `0%`, label text `""`, all five `<li>`s in `is-unmet` with `✗` markers.
2. Screen readers announce the form normally; the `aria-live` label is empty so no extraneous speech.

### SP-02: User Types `a` (1/5 — Very Weak)

1. `#password.value === "a"`. Criteria: length=false, lowercase=true, uppercase=false, digit=false, special=false. met=1.
2. Fill width → `20%`. Fill state class → `strength-very-weak`. Label text → `Very Weak`. The `lowercase` `<li>` flips to `is-met` and its marker → `✓`. The other four stay `is-unmet` with `✗`.

### SP-03: User Types `Abcdef1!` (5/5 — Strong)

1. Criteria: length=true (8), lowercase=true, uppercase=true, digit=true, special=true. met=5.
2. Fill width → `100%`. Fill state class → `strength-strong`. Label text → `Strong`. All five `<li>`s in `is-met` with `✓`.

### SP-04: User Pastes a Long Password

1. The browser fires `input` once for the paste. The update path runs once.
2. State reflects the pasted value. No extra event, no double update.

### SP-05: User Submits a Weak Password

1. User types `a`. Meter shows `Very Weak`. User clicks "Create Account".
2. The form's existing submit handler runs — only the password-match check fires (confirm matches). No `preventDefault`. The form submits.
3. Backend accepts the request (same code path as today), hashes with bcrypt, inserts, redirects to `/login`. **Meter did not gate.**

### SP-06: User Toggles Dark Mode Mid-Typing

1. User has typed `Abc1`. Meter shows `Good` (4/5) with the light-theme green fill.
2. User clicks the theme toggle. `data-theme` flips to `dark`. The fill's state class (`strength-good`) does not change; the CSS custom property `--strength-color-good` resolves to its dark-theme value; the fill recolors instantly with no JS involvement.

### SP-07: Form Re-Render (Back Button From Login)

1. User signs up successfully, lands on `/login`, hits browser back. The browser restores the form, including `#password.value`.
2. The meter init (run once at script start) reads the restored value and updates the UI accordingly — no manual interaction needed to re-sync.

---

## 7. Edge Cases

### EC-01: Empty String After Typing-Then-Deleting

- User types `Abc1!`, then `Backspace`s back to empty. The `input` event fires on each deletion. On the final empty state, met=0, the meter MUST transition to the "empty" row of §FR-04: width `0%`, state class `strength-empty`, label text `""`, all `<li>`s back to `is-unmet`/`✗`.

### EC-02: Whitespace-Only Password

- `password = "   "` (three spaces). Each space is `[^A-Za-z0-9]` so `special` is met; nothing else is. met=1 → `Very Weak`. Correct: a space-only string is one criterion away, not zero.

### EC-03: Very Long Password

- `password.length === 1000`. The five regex tests are still O(n) and complete in microseconds. The label remains `Strong` (assuming all classes are present); the bar stays at `100%`. No truncation, no warning.

### EC-04: JS Exception Inside the Update Path

- A future browser quirk or unexpected DOM removal causes the update function to throw. The `try/catch` swallows the exception. The user can keep typing; subsequent `input` events retry. A single `console.warn(e)` is permitted (advisory UX — silent failures are user-hostile, but a thrown dialog is worse).

### EC-05: Unicode / Emoji in the Password

- `password = "Pässwörd1!"` — `ä` and `ö` are matched by `[^A-Za-z0-9]` and count as `special`. `lowercase` is also met (the `P`/`a`/`s`/`s`/`w`/`r`/`d` matches; the umlauted chars don't, but they don't need to). length=10. met=5 → `Strong`. Correct under the ASCII-anchored definitions (§FR-03).
- `password = "🔒"` — single code point, `length === 2` in JavaScript due to surrogate pairs, `[^A-Za-z0-9]` matches both halves. length=false (2 < 8), lowercase=false, uppercase=false, digit=false, special=true. met=1 → `Very Weak`. The surrogate-pair length quirk is documented as known behavior, not a bug.

### EC-06: Browser Without `classList`

- All evergreen browsers since 2018 support `classList`. If the script runs in an environment without it, the script throws on the first `classList.toggle` call; the `try/catch` (§EC-04) swallows it; the meter is silently absent. The signup form keeps working. No polyfill is added (out of scope, §2.4).

### EC-07: `#password` Field Removed in a Future Refactor

- The script's top-level `if (!password) return;` guard exits before any listener attaches. No error, no meter, no impact on the rest of the page.

### EC-08: User Has JavaScript Disabled

- The inline `<script>` does not run. The meter DOM is still in the page (it is server-rendered HTML), but its `<li>`s show `✗` for every criterion (the static initial state) and the fill is at `0%` with label empty. The form still submits normally. **No regression** vs. today's no-JS state — the signup form already requires JS for the password-match check, so a no-JS submission was never strength-gated anyway.

### EC-09: Two Signup Forms on One Page

- Out of scope — the app has exactly one signup form per page. The script uses `document.getElementById('password')`, which returns the first match. A future template that renders two forms would need to scope by form id; this is a known limitation.

### EC-10: User Pastes a Password via Right-Click Paste Menu

- The browser fires a single `input` event for the paste. Same path as SP-04.

### EC-11: User Drags Text Into the Password Field

- Some browsers fire `input`, others fire `drop` + `input`. The listener responds to `input`, so the drag-paste path produces one (or sometimes two adjacent) updates — both produce the same DOM state because the function is idempotent (§NFR-08).

### EC-12: Autofill From a Password Manager

- 1Password / Bitwarden / Chrome autofill writes to the field and fires `input`. The meter updates to reflect the manager-generated password (typically `Strong`). The user sees the meter validate the manager's choice — pleasant UX.

---

## 8. Acceptance Criteria

### AC-01: Meter DOM Present in Rendered Signup Page

- `curl -s http://localhost:3001/signup` returns HTML containing `<div class="password-strength-meter` and exactly five `<li class="password-criteria-item"` substrings, with `data-criterion="length"`, `data-criterion="lowercase"`, `data-criterion="uppercase"`, `data-criterion="digit"`, `data-criterion="special"` appearing in this order.

### AC-02: Meter Inserted Between Password and Confirm-Password Form Groups

- In `frontend/templates/signup.html`, the `<div class="password-strength-meter">` block appears strictly between the `<div class="form-group">` containing `#password` and the `<div class="form-group">` containing `#confirm_password`.

### AC-03: CSRF Hidden Input Still First Child of Form

- `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` is still the first child of `<form id="signup-form">`. VULN-8 closure preserved.

### AC-04: Submit Handler Unchanged

- The existing form `submit` listener in `signup.html` is byte-for-byte identical to the pre-change version: same `e.preventDefault()` on password mismatch, same `passwordError.style.display` toggles, no new branches added inside.

### AC-05: No Backend File Changed

- `git diff --stat main..HEAD -- backend/` reports zero changes.

### AC-06: No New Dependency

- `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged. `git status --porcelain` shows no entry for any of those files.

### AC-07: No Network Calls Added

- `grep -nE 'fetch\(|XMLHttpRequest|sendBeacon' frontend/templates/signup.html` returns only the pre-existing matches (currently none in signup.html — login.html has the only `fetch` in the app, and it is unchanged).

### AC-08: No Persistence Calls Added

- `grep -nE 'localStorage|sessionStorage|document\.cookie' frontend/templates/signup.html` returns only the pre-existing theme-toggle matches (one `localStorage.getItem('theme')`, one `localStorage.setItem('theme', next)`). No new entry.

### AC-09: Live Update on `input` Event

- The script registers exactly one `input` listener on `#password`. No `keyup`, `keydown`, `change`, or `paste` listeners are added.

### AC-10: No `preventDefault` Outside the Existing Submit Handler

- The new script body contains no `preventDefault()`, no `disabled` mutation, no `required`/`pattern`/`minlength`/`maxlength` mutation.

### AC-11: Strength Mapping Matches §FR-04

- Manual verification (or a small browser test): `""` → empty label, `"a"` → `Very Weak`, `"Aa"` → `Weak` (2/5), `"Aa1"` → `Fair` (3/5), `"Aa1!"` → `Good` (4/5), `"Aaaaaaa1!"` → `Strong` (5/5).

### AC-12: All Five Closed-Vulnerability Files Untouched

- `git diff --stat main..HEAD -- backend/app/main.py backend/app/services/auth_service.py backend/app/core/security.py backend/app/core/csrf.py backend/app/core/rate_limit.py backend/app/db/session.py backend/app/api/routes/auth.py` reports zero changes for every path listed.

### AC-13: Login and Dashboard Templates Untouched

- `git diff --stat main..HEAD -- frontend/templates/login.html frontend/templates/dashboard.html` reports zero changes.

### AC-14: CSS Rules Use Custom Properties for Theming

- The new rules in `styles.css` reference `var(--strength-color-...)` and `var(--criterion-...)` rather than hex literals in the rule bodies. New custom properties are defined under `:root` and `[data-theme="dark"]`.

### AC-15: README and CLAUDE.md Updated

- `README.md`'s Feature Enhancements table has "Password Strength Meter" in a "Done" row.
- `CLAUDE.md`'s "Frontend-Backend Integration" section has a new bullet for the meter.
- `CLAUDE.md`'s "Important Rules" section has an entry forbidding pushing strength state into the backend, session, or DB, or blocking submission on a weak password.
- `CLAUDE.md`'s "Specification Hierarchy" appends the new spec/plan pair.

### AC-16: Application Boots

- `uv run backend/app/main.py` starts with no traceback. `GET /signup` returns HTTP 200 with the meter DOM rendered.

### AC-17: Other Vulnerabilities Preserved

- VULN-1: parameterized queries still in `auth_service.py` and `auth.py`.
- VULN-2: `welcome_page` still escapes `username`.
- VULN-3: `/search` still escapes `q`, row columns, exception text.
- VULN-4: `main.py` still sources `SECRET_KEY` from env.
- VULN-5: `core/security.py` still uses bcrypt.
- VULN-6: `GET /download/db` still returns 404.
- VULN-7: `RateLimitMiddleware` still registered, still returns 429 on the 6th POST in 60s.
- VULN-8: `CSRFMiddleware` still registered, signup form still carries the hidden `csrf_token` input as its first child, POST without a valid token still returns 403.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Meter DOM present | App running | `curl -s http://localhost:3001/signup` contains `<div class="password-strength-meter` |
| TC-02 | Five `<li>` criteria in correct order | App running | The output contains `data-criterion="length"`, `data-criterion="lowercase"`, `data-criterion="uppercase"`, `data-criterion="digit"`, `data-criterion="special"` in that source order |
| TC-03 | CSRF hidden input still first child | Repo checkout | `awk '/<form id="signup-form"/{flag=1; next} flag && /<input/{print; exit}' frontend/templates/signup.html` shows the `csrf_token` input first |
| TC-04 | Submit handler unchanged | Repo checkout | `grep -c 'e.preventDefault()' frontend/templates/signup.html` reports `1`; the surrounding handler is byte-for-byte the pre-change version |
| TC-05 | No backend file changed | Repo checkout | `git diff --stat main..HEAD -- backend/` shows no entries |
| TC-06 | No new dependency | Repo checkout | `git diff --stat main..HEAD -- pyproject.toml backend/pyproject.toml uv.lock` shows no entries |
| TC-07 | No new network calls in signup.html | Repo checkout | `grep -nE 'fetch\(|XMLHttpRequest|sendBeacon' frontend/templates/signup.html` returns no new matches beyond pre-change baseline |
| TC-08 | No new persistence calls in signup.html | Repo checkout | `grep -nE 'localStorage\.|sessionStorage\.|document\.cookie' frontend/templates/signup.html` returns only the two pre-existing theme-toggle lines |
| TC-09 | Single `input` listener | Repo checkout | `grep -c "addEventListener('input'" frontend/templates/signup.html` reports `1`; `grep -cE "addEventListener\('(keyup|keydown|change|paste)'" frontend/templates/signup.html` reports `0` |
| TC-10 | Empty password initial state | Browser, fresh load | Fill width `0%`, label text empty, all five markers `✗` |
| TC-11 | `a` → `Very Weak` | Browser, type `a` | Fill `20%`, label `Very Weak`, `lowercase` marker `✓` only |
| TC-12 | `Aa1!aaaa` → `Strong` | Browser, type the string | Fill `100%`, label `Strong`, all five markers `✓` |
| TC-13 | Weak password still submits | Browser, type `a`, confirm `a`, click submit | Form POSTs; backend creates account; browser ends on `/login` |
| TC-14 | Theme toggle recolors fill instantly | Browser, type `Aa1!aaaa`, toggle theme | Fill stays at `100%` with same state class; color swaps without JS involvement |
| TC-15 | Backend accepts a 1-character password | App running | `POST /signup` with `username=t1&email=t@t&password=a&csrf_token=<valid>` returns 302 to `/login` (proves backend gate did not change) |
| TC-16 | CSRF still enforced | App running | `POST /signup` without `csrf_token` still returns 403 |
| TC-17 | Rate limit still enforced | App running | The 6th `POST /signup` from one IP in 60 s still returns 429 |
| TC-18 | Bcrypt still in use | Repo checkout | `grep -n 'bcrypt' backend/app/core/security.py` matches |
| TC-19 | Parameterized SQL still in use | Repo checkout | `grep -n 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)' backend/app/services/auth_service.py` matches |
| TC-20 | Stored XSS escape still in place | Repo checkout | `grep -n 'html.escape(username, quote=True)' backend/app/api/routes/auth.py` matches |
| TC-21 | `/download/db` still 404 | App running | `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/download/db` prints `404` |
| TC-22 | Login and dashboard templates untouched | Repo checkout | `git diff --stat main..HEAD -- frontend/templates/login.html frontend/templates/dashboard.html` shows no entries |
| TC-23 | App boots | Fresh checkout | `uv run backend/app/main.py` starts with no traceback |
| TC-24 | README updated | Repo checkout | `grep -n 'Password Strength Meter' README.md` shows the row moved out of "Planned" into a "Done" row |
| TC-25 | CLAUDE.md updated | Repo checkout | `grep -n 'Password Strength Meter' CLAUDE.md` shows a new bullet under Frontend-Backend Integration |

---

## 10. Verification Steps

Run from the repository root.

### 10.1 Confirm Meter DOM Present (AC-01, TC-01, TC-02)

```bash
uv run backend/app/main.py &  # if not already running
sleep 1
curl -s http://localhost:3001/signup | grep -o 'data-criterion="[a-z]*"'
```

Expected: five lines printing `data-criterion="length"`, `data-criterion="lowercase"`, `data-criterion="uppercase"`, `data-criterion="digit"`, `data-criterion="special"` in this order.

### 10.2 Confirm CSRF Hidden Input Still First Child (AC-03, TC-03)

```bash
awk '/<form id="signup-form"/{flag=1; next} flag && /<input/{print; exit}' frontend/templates/signup.html
```

Expected: the printed line is the `csrf_token` hidden input.

### 10.3 Confirm Submit Handler Unchanged (AC-04, TC-04)

```bash
grep -c 'e.preventDefault()' frontend/templates/signup.html
grep -n "form.addEventListener('submit'" frontend/templates/signup.html
```

Expected: `1` from the first command (the existing password-mismatch handler); the second command points at the unchanged listener block.

### 10.4 Confirm No Backend Change (AC-05, AC-12, TC-05)

```bash
git diff --stat main..HEAD -- backend/
```

Expected: empty output.

### 10.5 Confirm No Dependency Change (AC-06, TC-06)

```bash
git diff --stat main..HEAD -- pyproject.toml backend/pyproject.toml uv.lock
```

Expected: empty output.

### 10.6 Confirm No New Network or Persistence Calls (AC-07, AC-08, TC-07, TC-08)

```bash
grep -nE 'fetch\(|XMLHttpRequest|sendBeacon' frontend/templates/signup.html \
  || echo '(no network calls — preserved)'
grep -nE 'localStorage\.|sessionStorage\.|document\.cookie' frontend/templates/signup.html
```

Expected: the network-calls grep prints its fallback; the persistence grep prints only the two pre-existing theme-toggle lines.

### 10.7 Confirm Single `input` Listener (AC-09, TC-09)

```bash
grep -c "addEventListener('input'" frontend/templates/signup.html
grep -cE "addEventListener\('(keyup|keydown|change|paste)'" frontend/templates/signup.html
```

Expected: `1` and `0`.

### 10.8 Manual Browser Verification of Strength Mapping (AC-11, TC-10, TC-11, TC-12)

1. Open `http://localhost:3001/signup` in a browser.
2. Confirm the meter is in the empty state (no fill, no label, five `✗`).
3. Type `a` → confirm `Very Weak` label, 20% fill, `lowercase` row shows `✓` and others `✗`.
4. Append until `Aa1!aaaa` → confirm `Strong` label, 100% fill, all five `✓`.
5. Delete back to empty → confirm meter returns to the empty state cleanly.

### 10.9 Weak Password Still Submits (TC-13, TC-15)

```bash
TOKEN=$(curl -s -c jar.txt http://localhost:3001/signup | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -b jar.txt -c jar.txt -X POST http://localhost:3001/signup \
  --data-urlencode 'username=weakpw_user' \
  --data-urlencode 'email=w@t.com' \
  --data-urlencode 'password=a' \
  --data-urlencode "csrf_token=$TOKEN"
```

Expected: `HTTP=302`. The 1-character password is accepted — backend gate did not change.

### 10.10 Theme Toggle Recolors Without JS Re-Run (TC-14)

1. With the meter on `Strong`, click the theme-toggle button.
2. Confirm the fill recolors to its dark-mode green hue with no visible flicker, and the state class on the fill `<div>` (visible in DevTools) is still `strength-strong`.

### 10.11 CSRF and Rate Limit Still Enforced (AC-17, TC-16, TC-17)

```bash
# CSRF: POST without token
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -X POST http://localhost:3001/signup \
  --data-urlencode 'username=ghost' --data-urlencode 'email=g@x' --data-urlencode 'password=p'
```

Expected: `HTTP=403`.

```bash
# Rate limit: 6th POST in 60 s (each carrying a fresh token)
for i in 1 2 3 4 5 6; do
  TOKEN=$(curl -s -c jar$i.txt http://localhost:3001/signup | grep -Eo 'value="[A-Za-z0-9_-]{43}"' | sed -E 's/value="([^"]+)"/\1/')
  curl -s -o /dev/null -w "POST$i: %{http_code}\n" -b jar$i.txt -X POST http://localhost:3001/signup \
    --data-urlencode "username=u$i" --data-urlencode "email=u$i@t" --data-urlencode 'password=a' \
    --data-urlencode "csrf_token=$TOKEN"
done
```

Expected: POSTs 1–5 print `302`; POST 6 prints `429`.

### 10.12 Other Closed Vulnerabilities Preserved (AC-17, TC-18 – TC-22)

```bash
grep -n 'bcrypt' backend/app/core/security.py
grep -n 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)' backend/app/services/auth_service.py
grep -n 'html.escape(username, quote=True)' backend/app/api/routes/auth.py
grep -c 'html.escape(' backend/app/api/routes/auth.py     # expect >= 7 (5 pre-existing + 2 CSRF splices)
curl -s -o /dev/null -w 'download/db=%{http_code}\n' http://localhost:3001/download/db
git diff --stat main..HEAD -- frontend/templates/login.html frontend/templates/dashboard.html
```

Expected: each grep matches; the count is ≥ 7; `download/db=404`; the diff is empty.

### 10.13 App Boots Cleanly (AC-16, TC-23)

```bash
rm -f vulnerable_app.db
uv run backend/app/main.py
```

Expected: server listens on `http://localhost:3001` with no traceback. `GET /signup` renders the page with the meter visible.

---
