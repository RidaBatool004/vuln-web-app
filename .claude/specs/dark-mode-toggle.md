# Software Specification Document — Dark Mode Toggle

**Version:** 1.0.0
**Last Updated:** June 11, 2026
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)

---

## 1. Overview / Purpose

This document specifies a **light/dark theme toggle** feature for the Vulnerable Web Application's three rendered pages: login, signup, and dashboard. The feature is **purely presentational** — it adds a visual mode switch driven by CSS custom properties and a `data-theme` attribute on `<html>`, with the user's choice persisted to `localStorage` under the key `"theme"`. The toggle restores the saved theme **before render** to avoid a flash of the wrong theme (FOUC), falls back to the user agent's `prefers-color-scheme` media query when no value is saved, is fully keyboard accessible, and exposes an `aria-label` that reflects the current toggle action. The feature is **additive** and must not remove, weaken, or otherwise alter any of the eight intentional lab vulnerabilities.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- A visible toggle control on the login, signup, and dashboard pages (placed inside the shared header).
- CSS custom property–based theming covering existing global, auth, and dashboard styles.
- `data-theme="light"` / `data-theme="dark"` attribute on the root `<html>` element as the single source of truth at render time.
- Persistence of the selected theme in `localStorage` under the key `"theme"` (allowed values: `"light"`, `"dark"`).
- Inline `<head>` script that synchronously applies the saved or system-preferred theme **before** the body renders.
- Fallback to `window.matchMedia('(prefers-color-scheme: dark)')` when no value is saved in `localStorage`.
- Keyboard accessibility: the toggle is reachable via `Tab`, activated by `Enter` and `Space`, and exposes a dynamic `aria-label`.

### 2.2 Out of Scope

- Server-side theme storage, user-account-bound preferences, or any database/schema changes.
- Per-component theme overrides, multi-theme palettes beyond light/dark, accent-color pickers.
- Animated/transition effects beyond the smooth color transition already permitted by CSS.
- Any change to backend code (`backend/app/**`).
- Any change to template structure that affects the existing `{{username}}` substitution mechanism.

### 2.3 Lab Vulnerabilities — In/Out of Scope

This feature is **strictly additive**. The following 8 OWASP-aligned vulnerabilities documented in [app-foundation.md](./app-foundation.md) and `CLAUDE.md` remain **intentionally unfixed**:

| # | Vulnerability | Status under this feature |
|---|---------------|---------------------------|
| 1 | SQL Injection (`auth_service.py`) | Intentionally unchanged |
| 2 | Stored XSS (dashboard `{{username}}`) | Intentionally unchanged |
| 3 | Reflected XSS (`/search`) | Intentionally unchanged |
| 4 | Session Hijacking (hardcoded secret) | Intentionally unchanged |
| 5 | Weak Password Hashing (MD5, no salt) | Intentionally unchanged |
| 6 | Exposed Database (`/download/db`) | Intentionally unchanged |
| 7 | No Rate Limiting | Intentionally unchanged |
| 8 | CSRF (no tokens) | Intentionally unchanged |

**No vulnerability is in scope to be fixed.** AC-06 and TC-09 explicitly assert that the Stored XSS sink in the dashboard remains exploitable after this feature ships.

---

## 3. Affected Files

The implementation MUST touch only the following four files. No other file in the repository may be created or modified.

| Path | Change Type |
|------|-------------|
| `frontend/static/css/styles.css` | Modified — add CSS custom properties, `[data-theme="dark"]` overrides, toggle button styles |
| `frontend/templates/login.html` | Modified — add pre-render theme script in `<head>`, theme toggle button in header |
| `frontend/templates/signup.html` | Modified — add pre-render theme script in `<head>`, theme toggle button in header |
| `frontend/templates/dashboard.html` | Modified — add pre-render theme script in `<head>`, theme toggle button in header |

The dashboard template MUST retain the literal `{{username}}` placeholder verbatim so that the server-side `str.replace('{{username}}', ...)` substitution in `backend/app/api/routes/auth.py` continues to operate unchanged.

---

## 4. Functional Requirements

### FR-01: Theme Attribute

- The root `<html>` element MUST carry a `data-theme` attribute whose value is either `"light"` or `"dark"`.
- All themed styles MUST be expressed as CSS custom properties scoped to `:root` (light defaults) and `:root[data-theme="dark"]` (dark overrides).

### FR-02: Persistence

- The selected theme MUST be persisted in `localStorage` under the key `"theme"`.
- Only the literal strings `"light"` and `"dark"` are written. Any other value found on read MUST be treated as absent.

### FR-03: Pre-Render Restoration (No FOUC)

- Each of the three templates MUST include an inline `<script>` in the document `<head>`, **before** the `<link rel="stylesheet">` is parsed by the body, that:
  1. Reads `localStorage.getItem('theme')`.
  2. If the value is `"light"` or `"dark"`, sets `document.documentElement.setAttribute('data-theme', value)`.
  3. Otherwise consults `window.matchMedia('(prefers-color-scheme: dark)').matches` and sets `data-theme` to `"dark"` or `"light"` accordingly.
- The script MUST be synchronous and inline (no `src=`, no `defer`, no `async`) so the attribute is set before first paint.

### FR-04: Toggle Control

- A button with `id="theme-toggle"` MUST appear inside the shared `<header class="header">` element on all three pages, on the right side near the existing logos.
- The button is a native `<button type="button">` so it is focusable and keyboard-activatable by default.
- The button MUST carry an `aria-label` whose value reflects the **action the user will perform** on the next click:
  - When the current theme is light → `aria-label="Switch to dark mode"`.
  - When the current theme is dark → `aria-label="Switch to light mode"`.
- The button MUST display a visible icon (text glyph `☀` for light, `🌙` for dark — the icon shown is the icon of the **target** theme, matching the action described in the aria-label).

### FR-05: Toggle Behavior

- Clicking the toggle, or activating it via `Enter` or `Space` while focused, MUST:
  1. Read the current `data-theme` attribute on `<html>`.
  2. Compute the opposite value.
  3. Set `document.documentElement.setAttribute('data-theme', next)`.
  4. Write the new value to `localStorage.setItem('theme', next)`.
  5. Update the button's `aria-label` and icon to reflect the new state.

### FR-06: System Preference Fallback

- When no value is saved in `localStorage`, the pre-render script MUST default to the user agent's `prefers-color-scheme` setting.
- Once the user clicks the toggle and a value is persisted, the saved value takes precedence over the system preference on all subsequent loads.

### FR-07: Themed Surfaces

The dark theme MUST provide overrides for at least these visual regions used by existing styles in `styles.css`:

- Body background and primary text color.
- Shared header background, border, and title color.
- Auth pages: right-panel (form) background, form title and subtitle colors, input background and border, focus glow, error message colors.
- Auth pages: the left-panel gradient and decorative circles MAY remain unchanged (brand panel) OR be darkened — implementation choice, but must remain readable.
- Dashboard: body background (`.dashboard-body`), mission card, vulnerability cards, card borders, card-title and description colors, vulnerability-tag color pairs (background tints must remain distinguishable in dark mode), process-step cards.

### FR-08: No Backend Coupling

- No server route, session value, request, or response is created or modified by this feature.
- The theme is never transmitted to the server in any form.

---

## 5. Non-Functional Requirements

### NFR-01: No Flash of Unstyled / Wrong Theme

- On a hard refresh of any of the three pages with `"dark"` saved in `localStorage`, the first painted frame MUST already be in dark mode. There MUST NOT be a perceptible flash of the light theme.

### NFR-02: No External Dependencies

- The feature MUST be implemented with vanilla HTML, CSS, and JavaScript only. No framework, no build step, no new package, no third-party script, no remote font or icon library.

### NFR-03: Accessibility

- The toggle MUST be reachable via the `Tab` key in document order.
- The toggle MUST be activatable by `Enter` and `Space` (native `<button>` behavior).
- The toggle MUST have a visible focus indicator consistent with the existing focus styling vocabulary (e.g., a box-shadow ring akin to `0 0 0 3px rgba(57, 73, 171, 0.12)`).
- The `aria-label` MUST always describe the **next** action (FR-04).

### NFR-04: Performance

- The pre-render script MUST execute in O(1) time and perform at most one `localStorage` read and one `matchMedia` query.
- CSS theme overrides MUST be authored as CSS custom property reassignments under `:root[data-theme="dark"]` — no duplicated selector trees.

### NFR-05: Vulnerability Preservation

- The implementation MUST NOT introduce any HTML escaping, sanitization, CSRF token, rate limiter, parameterized query, or session-secret change, even incidentally. See Section 2.3.

### NFR-06: Style Consistency

- The toggle button styling MUST inherit the application's existing visual language: 8px border-radius, system font stack, neutral background, hover/focus transitions matching the existing 0.2s timing.

---

## 6. Success Paths

### SP-01: First Visit (No Saved Preference, Light System)

1. User visits `/login` for the first time on a system where `prefers-color-scheme: dark` is false.
2. Pre-render script finds no `"theme"` key in `localStorage`.
3. Script consults `matchMedia` → light.
4. `<html data-theme="light">` is set before first paint.
5. Page renders in light theme. Toggle icon is `🌙`, `aria-label="Switch to dark mode"`.

### SP-02: First Visit (No Saved Preference, Dark System)

1. User visits `/signup` for the first time on a system where `prefers-color-scheme: dark` is true.
2. Pre-render script finds no `"theme"` key in `localStorage`.
3. Script consults `matchMedia` → dark.
4. `<html data-theme="dark">` is set before first paint.
5. Page renders in dark theme. Toggle icon is `☀`, `aria-label="Switch to light mode"`.

### SP-03: Toggle Click

1. User on `/login` with light theme active clicks the toggle.
2. Handler sets `data-theme="dark"` on `<html>`.
3. Handler writes `"dark"` to `localStorage["theme"]`.
4. Button icon updates to `☀`, `aria-label="Switch to light mode"`.
5. The full page recolors to dark via CSS custom properties.

### SP-04: Cross-Page Persistence

1. User toggles dark mode on `/login`.
2. User submits valid credentials and is redirected to `/welcome`.
3. The dashboard's pre-render script reads `"dark"` from `localStorage` and applies it before first paint.
4. The dashboard renders in dark mode without flash.

### SP-05: Keyboard Activation

1. User loads `/dashboard` (`/welcome`).
2. User presses `Tab` until focus lands on the theme toggle.
3. User presses `Space` (or `Enter`).
4. Theme switches as in SP-03, focus remains on the toggle, focus ring remains visible.

---

## 7. Edge Cases

### EC-01: Corrupted `localStorage` Value

- If `localStorage.getItem('theme')` returns a value that is not `"light"` or `"dark"` (e.g., `"system"`, `""`, `"DARK"`), the pre-render script MUST treat it as absent and fall back to the system preference.

### EC-02: `localStorage` Unavailable

- If `localStorage` access throws (private browsing modes in some engines, disabled storage), the pre-render script MUST catch the error and fall back to the system preference. Subsequent toggle clicks MUST also wrap `setItem` in a try/catch — the in-page theme still updates even if persistence fails.

### EC-03: `matchMedia` Unsupported

- If `window.matchMedia` is undefined or the dark-scheme query returns `null`, the script MUST default to `"light"`.

### EC-04: System Preference Changes Mid-Session

- If the user changes their OS theme while the page is open and no value is saved in `localStorage`, the in-page theme is NOT required to update live. (This is a deliberate non-goal — the system preference is consulted only at page load.)

### EC-05: Multiple Tabs Open

- If the user has two tabs open and toggles in one tab, the other tab is NOT required to update live. The new value is read on next navigation/refresh.

### EC-06: Username Containing `<script>` (Stored XSS)

- The dashboard MUST still render an unescaped `{{username}}`. A user registered with username `<script>alert(1)</script>` MUST still trigger script execution on the dashboard after this feature ships, regardless of which theme is active. See AC-06 and TC-09.

### EC-07: Disabled JavaScript

- With JavaScript disabled, the pre-render script does not run. The page renders with the default `:root` (light) palette. The toggle button is present but inert. This is acceptable — themed rendering is a JavaScript-driven enhancement.

---

## 8. Acceptance Criteria

### AC-01: Toggle Presence

- On `/login`, `/signup`, and `/welcome`, the shared header contains a `<button id="theme-toggle">` element to the right of the logos.

### AC-02: Theme Attribute Driven

- Setting `data-theme="dark"` on `<html>` via DevTools recolors the page without any JavaScript reload, proving the theme is a pure CSS custom-property switch.

### AC-03: Persistence

- After clicking the toggle, the value of `localStorage.getItem('theme')` matches the active theme. Refreshing the page preserves the theme.

### AC-04: No FOUC

- Loading any of the three pages with `"dark"` saved in `localStorage` shows the dark theme on first paint. There is no observable light-theme flash.

### AC-05: Keyboard & ARIA

- The toggle is reachable by `Tab`, activatable by `Enter` and `Space`, has a visible focus ring, and exposes an `aria-label` that toggles between `"Switch to dark mode"` and `"Switch to light mode"` matching the next action.

### AC-06: Vulnerabilities Intact

- All eight vulnerabilities listed in Section 2.3 remain exploitable. In particular, registering a user with username `<script>alert('xss')</script>` and then logging in still causes the script to execute on the dashboard in **both** themes.

### AC-07: Affected Files Only

- A `git diff` of the implementation touches only the four files listed in Section 3. No backend file, no new file under `backend/`, no new file under `frontend/static/js/`, and no change to `pyproject.toml`, `CLAUDE.md`, or any spec is introduced by the implementation.

### AC-08: System Preference Fallback

- With `localStorage` cleared, the initial theme matches the user agent's `prefers-color-scheme`.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | First visit, light system | `localStorage` cleared; OS in light mode | Page renders light; `<html data-theme="light">`; toggle aria-label is "Switch to dark mode" |
| TC-02 | First visit, dark system | `localStorage` cleared; OS reports `prefers-color-scheme: dark` | Page renders dark on first paint; `<html data-theme="dark">`; toggle aria-label is "Switch to light mode" |
| TC-03 | Click toggle (light → dark) | Page in light mode | `<html>` gains `data-theme="dark"`; `localStorage["theme"]` becomes `"dark"`; icon updates to `☀`; aria-label updates to "Switch to light mode" |
| TC-04 | Click toggle (dark → light) | Page in dark mode | `<html>` gains `data-theme="light"`; `localStorage["theme"]` becomes `"light"`; icon updates to `🌙`; aria-label updates to "Switch to dark mode" |
| TC-05 | Persistence across reload | Toggle to dark, then hard-reload the page | Page renders dark on first paint; no FOUC observed |
| TC-06 | Persistence across pages | Toggle to dark on `/login`, then navigate to `/signup` | `/signup` renders dark immediately |
| TC-07 | Keyboard activation | Focus toggle via `Tab`, press `Space` | Theme switches; focus remains on toggle; focus ring visible |
| TC-08 | Corrupted localStorage value | Manually set `localStorage["theme"] = "purple"`, reload | Script treats value as absent; falls back to `prefers-color-scheme` |
| TC-09 | Stored XSS still fires (vulnerability preservation) | Register user `<script>alert('xss')</script>`, log in, view `/welcome` in **both** light and dark themes | Browser executes the script (alert appears) in both themes — dashboard renders the username unescaped, confirming the Stored XSS vulnerability is untouched |
| TC-10 | Reflected XSS still fires | Visit `/search?q=<script>alert(1)</script>` while in dark mode | Script executes — Reflected XSS untouched |
| TC-11 | Hardcoded session secret unchanged | Grep `backend/app/main.py` for `"super-secret-key-12345"` | String is still present |
| TC-12 | No CSRF token added | Inspect login and signup form HTML | No CSRF token field is present |
| TC-13 | `localStorage` unavailable | Stub `localStorage.setItem` to throw, click toggle | Theme still flips in the DOM; no uncaught error in the console |
| TC-14 | Affected-files audit | `git status` after implementation | Only `frontend/static/css/styles.css`, `frontend/templates/login.html`, `frontend/templates/signup.html`, `frontend/templates/dashboard.html` appear as modified |
| TC-15 | `{{username}}` placeholder preserved | `grep '{{username}}' frontend/templates/dashboard.html` | The literal placeholder is still present so the server-side `str.replace` continues to work |

---

## 10. Verification Steps

Run the application from the project root:

```bash
uv run backend/app/main.py
```

Then exercise the feature against the following URLs:

1. **Login page** — `http://localhost:3001/login`
   - Verify the toggle appears in the header (AC-01).
   - Click the toggle and confirm the page recolors (TC-03/TC-04).
   - Open DevTools → Application → Local Storage → `http://localhost:3001` and confirm the `"theme"` key has the expected value (AC-03).
   - Hard-reload (Cmd+Shift+R) with dark saved and confirm no light flash (AC-04, TC-05).

2. **Signup page** — `http://localhost:3001/signup`
   - Repeat the toggle + reload checks. Confirm the theme set on `/login` is honored here (TC-06).

3. **Dashboard** — `http://localhost:3001/welcome`
   - Register a normal user via `/signup`, log in via `/login`, and navigate to `/welcome`.
   - Confirm the toggle works on the dashboard and the username strong-tag, mission card, vulnerability cards, tag pills, and process-step cards all recolor cleanly in dark mode.

4. **Vulnerability preservation (critical, AC-06 / TC-09)**
   - Register a user with username `<script>alert('xss')</script>` via `/signup`.
   - Log in via `/login`.
   - Visit `/welcome` in light mode → confirm alert fires.
   - Toggle to dark mode and reload `/welcome` → confirm alert fires again.

5. **Reflected XSS preservation (TC-10)**
   - With dark mode active, visit `http://localhost:3001/search?q=<script>alert(1)</script>` and confirm the script executes.

6. **Session secret preservation (TC-11)**
   - From the project root, run `grep -n 'super-secret-key-12345' backend/app/main.py` and confirm the line is still present and unchanged.

7. **Affected-files audit (AC-07 / TC-14)**
   - From the project root, run `git status` and confirm only the four files in Section 3 are listed as modified.

8. **Keyboard accessibility (AC-05 / TC-07)**
   - From any of the three pages, press `Tab` until focus reaches the toggle. Confirm a visible focus ring, then press `Space` to flip the theme.

9. **System preference fallback (AC-08 / TC-02)**
   - In DevTools, open the Rendering panel and emulate `prefers-color-scheme: dark`. Clear `localStorage` and reload `/login`. Confirm the dark theme is applied on first paint.
