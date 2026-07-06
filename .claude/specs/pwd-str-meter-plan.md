# Implementation Plan — Password Strength Meter (Signup, Frontend-Only, Advisory)

**Version:** 1.0.0
**Last Updated:** 2026-06-16
**Parent Spec:** [pwd-str-meter.md](./pwd-str-meter.md)
**Foundation Spec:** [app-foundation.md](./app-foundation.md)
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)
**Tracking Issue:** [Password Strength Meter — README "Feature Enhancements" #3](https://github.com/arifpucit/issues)

---

## 0. Plan Overview

This plan implements the enhancement specified in [pwd-str-meter.md](./pwd-str-meter.md). It adds a **real-time, frontend-only, advisory** password strength meter to the signup form (`frontend/templates/signup.html`) plus the matching CSS in `frontend/static/css/styles.css`, and updates two documentation files. **No backend file is touched.** **No closed vulnerability is touched.** The strength level is a transparent function of how many of the five acceptance criteria are met; the meter never gates submission and never sends or stores the password.

The work is split into **five phases** so the change is small, individually verifiable, and easy to revert.

**Two implementation realities baked into this plan:**

1. **CSS custom properties carry the theme split.** The meter must look correct under both `data-theme="light"` and `data-theme="dark"` without re-running JS on toggle. The plan therefore defines new color custom properties under `:root` and `[data-theme="dark"]`, and references them by `var(--strength-color-...)` from a single rule set per state class. This mirrors how the rest of `styles.css` handles light/dark today.
2. **The script is one inline `<script>` block, not a separate file.** The signup template already follows this pattern (one inline block for the password-match check, one inline block for the theme toggle). A separate `static/js/...` file would require a new `app.mount` line in `backend/app/main.py`, which would breach the "no backend change" rule.

The eight already-closed fixes (bcrypt password hashing, parameterized SQL, removed `/download/db`, env-sourced session secret, escaped dashboard `{{username}}`, escaped `/search` reflection sinks, per-IP POST rate-limit middleware, session-bound synchronizer-token CSRF middleware) MUST remain closed after every phase. Each phase ends with an explicit "MUST NOT" callout.

### Phase Summary

| # | Phase | Files Touched | Goal |
|---|-------|--------------|------|
| 1 | Add meter DOM to the signup template | `frontend/templates/signup.html` | Insert the `<div class="password-strength-meter">` block between the `password` and `confirm_password` form groups; keep CSRF hidden input first; keep existing submit handler unchanged |
| 2 | Add the live-update inline `<script>` block | `frontend/templates/signup.html` | One `input` listener on `#password`, five regex checks per keystroke, idempotent DOM mutations, fail-open `try/catch` |
| 3 | Append CSS rules + theme custom properties | `frontend/static/css/styles.css` | New rules for `.password-strength-meter`, bar, fill, label, criteria list/items; five strength-color custom properties under `:root` and `[data-theme="dark"]`; met/unmet criterion text colors |
| 4 | Update `README.md` and `CLAUDE.md` | `README.md`, `CLAUDE.md` | Move the feature row to "Done" in README's Feature Enhancements; add a meter bullet under Frontend-Backend Integration in CLAUDE.md; add an Important Rules entry; append the spec/plan pair to the Specification Hierarchy |
| 5 | End-to-end verification + vulnerability preservation audit | None (read-only) | Walk every Verification Step in spec §10 |

### Files Modified / Created (Authored)

Exactly the four files declared in spec §3:

- **Modified** — `frontend/templates/signup.html`
- **Modified** — `frontend/static/css/styles.css`
- **Modified** — `README.md`
- **Modified** — `CLAUDE.md`

No new file is created. No dependency change (`pyproject.toml`, `backend/pyproject.toml`, `uv.lock` untouched).

### Files That MUST NOT Be Modified

- `backend/app/main.py` — middleware wiring + env-sourced `SECRET_KEY` (VULN-4, VULN-7, VULN-8).
- `backend/app/services/auth_service.py` — parameterized queries + bcrypt verify (VULN-1, VULN-5).
- `backend/app/core/security.py` — bcrypt (VULN-5).
- `backend/app/core/csrf.py` — synchronizer-token middleware (VULN-8).
- `backend/app/core/rate_limit.py` — per-IP rate-limit middleware (VULN-7).
- `backend/app/db/session.py` — schema and connection layer (no schema column for strength state).
- `backend/app/api/routes/auth.py` — all handlers including `signup_page`, `signup_post`.
- `frontend/templates/login.html` — login is not where a new password is chosen.
- `frontend/templates/dashboard.html` — no password field on the dashboard.
- `frontend/static/images/*` — no image change.
- `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, and every prior spec/plan pair.
- `pyproject.toml`, `backend/pyproject.toml`, `uv.lock`.

### Vulnerability Preservation Checklist (Carry Through Every Phase)

After every phase, re-confirm:

1. **SQL Injection (VULN-1).** `auth_service.py` and `/search` use parameterized `?` queries. Not touched by this plan; stays closed.
2. **Stored XSS (VULN-2).** `welcome_page` escapes `{{username}}` with `html.escape(..., quote=True)`. `dashboard.html` is not touched; stays closed.
3. **Reflected XSS (VULN-3).** `/search` escapes `q`, both row columns, exception text. Not touched; stays closed.
4. **Session Hijacking (VULN-4).** `main.py` sources `SECRET_KEY` from env. Not touched; stays closed.
5. **Weak Password Storage (VULN-5).** `core/security.py` uses bcrypt at rounds ≥ 12 with the defensive `try/except` in `verify_password`. Not touched; stays closed. **The frontend meter is advisory — it does not replace, supplement, or pre-empt the server-side hashing.**
6. **Exposed Database (VULN-6).** No `/download/db` route. Not touched; stays closed.
7. **No Rate Limiting (VULN-7).** `RateLimitMiddleware` is registered. Not touched; stays closed.
8. **CSRF (VULN-8).** The hidden `<input name="csrf_token">` stays the **first** child of `<form id="signup-form">`. The meter DOM is inserted later in the form, between the password and confirm-password form groups; it does not touch the hidden field, the form's `action`, or the form's `method`.

---

## Phase 1 — Add Meter DOM to `frontend/templates/signup.html`

### 1.1 Goal

Insert a new `<div class="password-strength-meter">` block as a sibling of the existing form-group `<div>`s, positioned strictly between the password form group and the confirm-password form group. The block contains a strength bar, a strength label, and a five-item criteria list. The CSRF hidden input stays first; the existing form structure stays otherwise byte-for-byte unchanged; the existing submit handler stays byte-for-byte unchanged.

### 1.2 File to Modify

- `frontend/templates/signup.html`

### 1.3 Edit — Insert Meter Block Between Password and Confirm-Password Form Groups

**Before** (region around L78–L86):

```html
                    <div class="form-group">
                        <label class="form-label" for="password">Password</label>
                        <input type="password" id="password" name="password" class="form-input" placeholder="Create a password" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="confirm_password">Confirm Password</label>
                        <input type="password" id="confirm_password" class="form-input" placeholder="Confirm your password" required>
                        <span id="password-error" class="password-error" style="display: none;">Passwords do not match</span>
                    </div>
```

**After**:

```html
                    <div class="form-group">
                        <label class="form-label" for="password">Password</label>
                        <input type="password" id="password" name="password" class="form-input" placeholder="Create a password" required>
                    </div>
                    <div class="password-strength-meter strength-empty" id="password-strength-meter">
                        <div class="password-strength-bar">
                            <div class="password-strength-bar-fill strength-empty" id="password-strength-bar-fill" style="width: 0%;"></div>
                        </div>
                        <div class="password-strength-label" id="password-strength-label" aria-live="polite"></div>
                        <ul class="password-criteria-list" id="password-criteria-list" aria-label="Password requirements">
                            <li class="password-criteria-item is-unmet" data-criterion="length">
                                <span class="password-criteria-marker" aria-hidden="true">✗</span>
                                At least 8 characters
                            </li>
                            <li class="password-criteria-item is-unmet" data-criterion="lowercase">
                                <span class="password-criteria-marker" aria-hidden="true">✗</span>
                                At least one lowercase letter (a–z)
                            </li>
                            <li class="password-criteria-item is-unmet" data-criterion="uppercase">
                                <span class="password-criteria-marker" aria-hidden="true">✗</span>
                                At least one uppercase letter (A–Z)
                            </li>
                            <li class="password-criteria-item is-unmet" data-criterion="digit">
                                <span class="password-criteria-marker" aria-hidden="true">✗</span>
                                At least one digit (0–9)
                            </li>
                            <li class="password-criteria-item is-unmet" data-criterion="special">
                                <span class="password-criteria-marker" aria-hidden="true">✗</span>
                                At least one special character
                            </li>
                        </ul>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="confirm_password">Confirm Password</label>
                        <input type="password" id="confirm_password" class="form-input" placeholder="Confirm your password" required>
                        <span id="password-error" class="password-error" style="display: none;">Passwords do not match</span>
                    </div>
```

The insertion is a single contiguous block. Nothing above the password form group is touched (the hidden CSRF input stays the first child of the form); nothing below the confirm-password form group is touched (the submit button stays the last child).

### 1.4 Line-by-Line Justification

| Block / attribute | Decision | Spec ref |
|---|---|---|
| Insertion point: between password and confirm-password form groups | Keeps the CSRF hidden input as the first child of the form (preserves VULN-8 closure) and places the meter where the user looks immediately after typing the password | FR-01, AC-02, AC-03 |
| Outer `<div class="password-strength-meter strength-empty" id="password-strength-meter">` | Outer container; the state class is mirrored here (in addition to on the fill) so any future label-color tweak can read it without re-querying state | FR-02, FR-06 |
| Inner `<div class="password-strength-bar">` wrapping `<div class="password-strength-bar-fill ...">` | Two-element structure: bar is the track, fill is the colored progress; allows the bar to keep its full width while the fill grows | FR-02 |
| Initial inline `style="width: 0%;"` on the fill | Sets the empty initial state directly in HTML so a no-JS render still shows a visually consistent (empty) bar | FR-10, EC-08 |
| Initial `strength-empty` state class on both the meter and the fill | Drives the CSS to the "empty" color custom property; JS will swap this class as the level changes | FR-06, FR-10 |
| Label `<div ... aria-live="polite">` (initially empty) | `polite` is the correct ARIA level for advisory updates (does not interrupt in-flight speech) | FR-07 |
| `<ul class="password-criteria-list" aria-label="Password requirements">` | Semantic list markup; `aria-label` gives screen readers a heading for the group | FR-07 |
| Five `<li class="password-criteria-item is-unmet" data-criterion="...">` in fixed order: length, lowercase, uppercase, digit, special | Stable `data-criterion` attributes give the JS a single lookup key and let TC-02 grep verify order; initial `is-unmet` matches the empty initial state | FR-02, FR-10, AC-01, AC-02 |
| Marker `<span ... aria-hidden="true">✗</span>` | The glyph is decorative; the criterion text already conveys the requirement, and `is-met` / `is-unmet` styling conveys state visually | FR-07 |
| Criterion text matches the human-readable strings in §FR-02 | Identical wording avoids drift between spec and template; en-dashes (`a–z`, `A–Z`, `0–9`) are intentional for typographic polish | FR-02 |
| No `<style>` inside the meter block | All styling lives in `styles.css` (Phase 3); inline styles would breach the existing project style | FR-13 |

### 1.5 What NOT to Change in Phase 1

- **DO NOT** move, modify, or remove the `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` line. VULN-8 closure depends on it being the first child of the form.
- **DO NOT** change the `<form id="signup-form" action="/signup" method="POST">` opening tag's attributes.
- **DO NOT** modify the existing submit handler at the bottom of the file (the password-match check). It stays byte-for-byte (AC-04).
- **DO NOT** add `required`, `pattern`, `minlength`, or `maxlength` attributes to `#password`. The meter is advisory; HTML-native gating would block submission and violate the "no submit gate" rule (FR-08).
- **DO NOT** insert any meter DOM into `login.html` or `dashboard.html`.
- **DO NOT** introduce a `<script src=...>` tag pointing at a static file. The implementation is inline JS (Phase 2).
- **DO NOT** rename the existing `#password-error` span or its `password-error` class. The new `.password-strength-*` and `.password-criteria-*` classes are deliberately namespaced to avoid collision (FR-13).
- **DO NOT** add any `<link rel="stylesheet" ...>` tag for a new stylesheet. The new CSS rules are appended to the existing `styles.css` (Phase 3).
- **DO NOT** modify the theme-toggle script block below the form. It stays byte-for-byte.

### 1.6 Phase 1 Verification (Pre-Server)

```bash
# Meter block present, with the right outer class
grep -n 'class="password-strength-meter' frontend/templates/signup.html

# All five data-criterion attributes present in the correct order
grep -n 'data-criterion=' frontend/templates/signup.html
# Expected output, in this source order:
#   data-criterion="length"
#   data-criterion="lowercase"
#   data-criterion="uppercase"
#   data-criterion="digit"
#   data-criterion="special"

# CSRF hidden input still the FIRST child of the form
awk '/<form id="signup-form"/{flag=1; next} flag && /<input/{print; exit}' frontend/templates/signup.html
# Expected: the printed line is the csrf_token hidden input

# Existing submit handler unchanged (one preventDefault, no new ones)
grep -c 'e.preventDefault()' frontend/templates/signup.html
# Expected: 1

# Login and dashboard templates untouched
git diff --stat frontend/templates/login.html frontend/templates/dashboard.html
# Expected: empty
```

Expected: the outer-class grep matches once; the `data-criterion` grep prints exactly five lines in the correct order; the awk line prints the CSRF hidden input; the `preventDefault` count is `1`; the diff is empty.

---

## Phase 2 — Add the Live-Update Inline `<script>` Block

### 2.1 Goal

Append a new inline `<script>` block to `signup.html` that wires up the meter. The block defines a self-invoking function that:

1. Looks up `#password`, the meter DOM, the fill `<div>`, the label `<div>`, and the five `<li>`s by `data-criterion`. Exits cleanly if any lookup fails.
2. Defines the level-name + width + state-class mapping table from §FR-04.
3. Registers a single `input` listener on `#password`. On each event, recomputes the five criterion booleans, updates each `<li>`'s class and marker, updates the fill's class and width, updates the meter's class, and sets the label text.
4. Runs the update path once at script start (covers back-button restore and any pre-filled value).
5. Wraps the update body in `try/catch` so any unexpected error degrades silently — typing is never blocked.

The block goes **after** the existing password-match `<script>` block and **before** the existing theme-toggle `<script>` block, so the order of inline scripts on the page is: password-match (unchanged), strength-meter (new), theme-toggle (unchanged). Order does not matter functionally (each script is self-contained), but consistency makes future edits easier.

### 2.2 File to Modify

- `frontend/templates/signup.html`

### 2.3 Edit — Insert New `<script>` Block

**Before** (region between the password-match script and the theme-toggle script — currently L110–L112):

```html
        });
    </script>

    <script>
        (function () {
            var toggle = document.getElementById('theme-toggle');
```

**After**:

```html
        });
    </script>

    <script>
        (function () {
            var password = document.getElementById('password');
            var meter = document.getElementById('password-strength-meter');
            var fill = document.getElementById('password-strength-bar-fill');
            var label = document.getElementById('password-strength-label');
            var list = document.getElementById('password-criteria-list');
            if (!password || !meter || !fill || !label || !list) return;

            var items = {};
            var nodes = list.querySelectorAll('.password-criteria-item');
            for (var i = 0; i < nodes.length; i++) {
                var key = nodes[i].getAttribute('data-criterion');
                if (key) items[key] = nodes[i];
            }
            if (!items.length || !items.lowercase || !items.uppercase || !items.digit || !items.special) return;

            var LEVELS = [
                { name: '',          width: 0,   cls: 'strength-empty' },
                { name: 'Very Weak', width: 20,  cls: 'strength-very-weak' },
                { name: 'Weak',      width: 40,  cls: 'strength-weak' },
                { name: 'Fair',      width: 60,  cls: 'strength-fair' },
                { name: 'Good',      width: 80,  cls: 'strength-good' },
                { name: 'Strong',    width: 100, cls: 'strength-strong' }
            ];
            var ALL_CLASSES = ['strength-empty','strength-very-weak','strength-weak','strength-fair','strength-good','strength-strong'];

            function setItem(node, met) {
                node.classList.toggle('is-met', met);
                node.classList.toggle('is-unmet', !met);
                var marker = node.querySelector('.password-criteria-marker');
                if (marker) marker.textContent = met ? '✓' : '✗';
            }

            function swapClass(el, next) {
                for (var i = 0; i < ALL_CLASSES.length; i++) el.classList.remove(ALL_CLASSES[i]);
                el.classList.add(next);
            }

            function update() {
                try {
                    var v = password.value || '';
                    var checks = {
                        length:    v.length >= 8,
                        lowercase: /[a-z]/.test(v),
                        uppercase: /[A-Z]/.test(v),
                        digit:     /[0-9]/.test(v),
                        special:   /[^A-Za-z0-9]/.test(v)
                    };
                    var met = 0;
                    for (var k in checks) if (checks[k]) met++;

                    setItem(items.length,    checks.length);
                    setItem(items.lowercase, checks.lowercase);
                    setItem(items.uppercase, checks.uppercase);
                    setItem(items.digit,     checks.digit);
                    setItem(items.special,   checks.special);

                    var level = LEVELS[met];
                    fill.style.width = level.width + '%';
                    swapClass(fill, level.cls);
                    swapClass(meter, level.cls);
                    label.textContent = level.name;
                } catch (e) {
                    /* advisory UX — never block typing on a meter error */
                }
            }

            password.addEventListener('input', update);
            update();
        })();
    </script>

    <script>
        (function () {
            var toggle = document.getElementById('theme-toggle');
```

The insertion is a single self-invoking function inside a new `<script>` block. No other line on the page changes.

### 2.4 Line-by-Line Justification

| Block | Decision | Spec ref |
|---|---|---|
| `var password = document.getElementById('password'); ... if (!password || !meter || !fill || !label || !list) return;` | Resilience to missing DOM (e.g., future refactor removes `#password`); fail-open exit, no error | NFR-06 |
| Build `items` map by iterating `data-criterion` attributes | Decouples DOM order from JS lookup; if a future edit reorders the `<li>`s, the JS still works as long as the data attributes are correct | FR-02 |
| `LEVELS` table mirrors §FR-04 row-for-row | One source-of-truth mapping — easy to compare against the spec table during review | FR-04 |
| `ALL_CLASSES` list for `swapClass` | Removes all six possible state classes before adding the new one; cleaner than tracking which one was last applied | FR-06 |
| `setItem(node, met)` toggles `is-met` / `is-unmet` and writes the marker `textContent` | `textContent`, never `innerHTML` — defense-in-depth against any future change to the level-name source (FR-04 already mandates `textContent` for the label; same standard applied to the markers) | FR-04, FR-07 |
| Five regex checks built as a plain object | Five constant-time tests; total cost well under a millisecond per keystroke | NFR-04 |
| `met` accumulator from a plain `for...in` loop over `checks` | Five iterations, no allocation overhead | NFR-04 |
| Update order: `<li>`s first, then fill, then label | Reads first (`checks`), writes second; no layout-thrash interleaving | NFR-04 |
| `fill.style.width = level.width + '%'` | Single inline style mutation — width only, not color (color comes from the state class via CSS custom properties) | FR-06 |
| `swapClass(fill, level.cls); swapClass(meter, level.cls);` | State class on both elements so the label color can pick up the same custom property if a future CSS tweak wants it | FR-06 |
| `label.textContent = level.name` | `textContent` so any future source change cannot become an XSS vector (the strings here are literal constants today, but the rule keeps the code review-able) | FR-04, FR-07 |
| Whole body wrapped in `try { ... } catch (e) { /* swallow */ }` | Fail-OPEN: advisory UX must never block typing | NFR-07, EC-04 |
| `password.addEventListener('input', update)` — single `input` listener | Covers typing, paste, drag-drop, autofill, IME composition in one event; no debounce | FR-05, AC-09 |
| `update()` called once at script start | Covers back-button restore and pre-filled values; matches initial-state requirements | FR-10, SP-07 |
| `(function () { ... })()` IIFE | Mirrors the existing inline scripts' style; `var` (not `let`/`const`) keeps style consistent with the other inline blocks in the same template | FR-13 |
| No `console.log`, no `alert`, no `confirm` | Production code; only the `catch` comment is permitted | NFR-05, EC-04 |
| No `fetch`, no `XMLHttpRequest`, no `sendBeacon`, no `localStorage`, no `document.cookie` | Strict no-network, no-persistence rule | FR-09, NFR-05 |

### 2.5 What NOT to Change in Phase 2

- **DO NOT** modify the password-match script above the new block. Its `e.preventDefault()` on mismatch stays exactly as it is (AC-04).
- **DO NOT** modify the theme-toggle script below the new block.
- **DO NOT** attach a `submit` listener, `keyup`/`keydown`/`change`/`paste` listener, or any handler other than the single `input` listener on `#password`.
- **DO NOT** call `password.setCustomValidity`, `form.checkValidity`, or any HTML-validation API. The meter is advisory.
- **DO NOT** call `preventDefault`, `stopPropagation`, or `stopImmediatePropagation` anywhere in the new block.
- **DO NOT** toggle the `disabled` attribute on the submit button.
- **DO NOT** mutate `#password`'s `required`, `pattern`, `minlength`, or `maxlength` attributes.
- **DO NOT** read from or write to `localStorage`, `sessionStorage`, or `document.cookie`.
- **DO NOT** read from or write to any `<input>` other than `#password` (and don't even *read* `#password.value` outside the listener body — the IIFE captures the element, the listener does the read).
- **DO NOT** import any external JS file or NPM module.
- **DO NOT** add `setInterval` or `setTimeout` debouncing. The five regex tests are cheap; debouncing only adds perceived latency.
- **DO NOT** log the password (or its length, or any derivative) anywhere.
- **DO NOT** re-introduce a closed vulnerability — the rules at the top of `CLAUDE.md` apply.

### 2.6 Phase 2 Verification (Pre-Server)

```bash
# Exactly one input listener on the password field
grep -c "addEventListener('input'" frontend/templates/signup.html
# Expected: 1

# No other keystroke / change / paste listeners
grep -cE "addEventListener\('(keyup|keydown|change|paste|submit)'" frontend/templates/signup.html
# Expected: 1   (the unchanged submit listener from the password-match script; no others)

# No preventDefault outside the existing password-match handler
grep -c 'e.preventDefault()' frontend/templates/signup.html
# Expected: 1

# No network calls in signup.html
grep -nE 'fetch\(|XMLHttpRequest|sendBeacon' frontend/templates/signup.html \
  || echo '(no network calls — preserved)'

# No new persistence calls (only the two existing theme-toggle lines)
grep -cE 'localStorage\.|sessionStorage\.|document\.cookie' frontend/templates/signup.html
# Expected: 2  (one localStorage.getItem, one localStorage.setItem in theme toggle)

# The five regex checks are present
grep -nE "/\[a-z\]/|/\[A-Z\]/|/\[0-9\]/|/\[\^A-Za-z0-9\]/" frontend/templates/signup.html
# Expected: four matching lines (lowercase, uppercase, digit, special); length is a numeric compare

# The length check is present
grep -n 'v.length >= 8' frontend/templates/signup.html
# Expected: one matching line

# textContent used for label and markers (never innerHTML)
grep -n 'innerHTML' frontend/templates/signup.html \
  || echo '(no innerHTML — preserved)'

# try/catch around the update body
grep -nE 'try\s*\{|catch\s*\(' frontend/templates/signup.html
# Expected: at least one matching try and one matching catch in the new block
```

Expected: the input-listener count is `1`; the other-listener count is `1` (the unchanged submit listener); `preventDefault` count is `1`; the network grep prints its fallback; the persistence count is `2`; all four regex literals and the `>= 8` check appear; the `innerHTML` grep prints its fallback; the try/catch greps each match.

---

## Phase 3 — Append CSS Rules + Theme Custom Properties to `styles.css`

### 3.1 Goal

Append a new CSS section at the **end** of `frontend/static/css/styles.css` containing:

- Five new strength-color custom properties on `:root` (light theme).
- The same five custom properties on `[data-theme="dark"]` with dark-theme values.
- Two new criterion text-color custom properties (`--criterion-met-color`, `--criterion-unmet-color`) on both theme blocks.
- One rule set for `.password-strength-meter` (spacing + the meter's own state-class hooks for the label color, if used).
- One rule set for `.password-strength-bar` (the track) + one for `.password-strength-bar-fill` (the colored progress) including the `transition` for smooth width / color animation.
- Six rule sets for the six state classes on the fill: `strength-empty`, `strength-very-weak`, `strength-weak`, `strength-fair`, `strength-good`, `strength-strong`, each setting `background-color: var(--strength-color-<state>)`.
- One rule set for `.password-strength-label` (font, spacing).
- One rule set for `.password-criteria-list` (reset list styling: no bullets, no padding).
- One rule set for `.password-criteria-item` (flex layout for marker + text, base font).
- Two rule sets for `.password-criteria-item.is-met` and `.password-criteria-item.is-unmet` using `--criterion-met-color` / `--criterion-unmet-color`.
- One rule set for `.password-criteria-marker` (fixed width so the text doesn't jiggle when the marker swaps between `✓` and `✗`).

Appending to the **end** of the file keeps the diff minimal and avoids interleaving with any of the existing rules — easy to revert by deleting the appended block.

### 3.2 File to Modify

- `frontend/static/css/styles.css`

### 3.3 Edit — Append the New Section

Add the following block at the **very end** of `styles.css`:

```css
/* ============================================================
 * Password Strength Meter (signup form, advisory UX).
 * Frontend-only — no server-side policy change.
 * Theming via CSS custom properties so toggling data-theme
 * recolors the bar with zero JS involvement.
 * ============================================================ */

:root {
    --strength-color-empty:      #e0e3eb;
    --strength-color-very-weak:  #d32f2f;
    --strength-color-weak:       #f57c00;
    --strength-color-fair:       #fbc02d;
    --strength-color-good:       #689f38;
    --strength-color-strong:     #2e7d32;
    --criterion-met-color:       #2e7d32;
    --criterion-unmet-color:     #64748b;
}

[data-theme="dark"] {
    --strength-color-empty:      #2a2f3a;
    --strength-color-very-weak:  #ef5350;
    --strength-color-weak:       #ffa726;
    --strength-color-fair:       #ffd54f;
    --strength-color-good:       #9ccc65;
    --strength-color-strong:     #66bb6a;
    --criterion-met-color:       #9ccc65;
    --criterion-unmet-color:     #a0aec0;
}

.password-strength-meter {
    margin-top: 0.5rem;
    margin-bottom: 1rem;
}

.password-strength-bar {
    width: 100%;
    height: 6px;
    background-color: var(--strength-color-empty);
    border-radius: 6px;
    overflow: hidden;
}

.password-strength-bar-fill {
    height: 100%;
    width: 0%;
    background-color: var(--strength-color-empty);
    transition: width 0.18s ease, background-color 0.18s ease;
}

.password-strength-bar-fill.strength-empty      { background-color: var(--strength-color-empty); }
.password-strength-bar-fill.strength-very-weak  { background-color: var(--strength-color-very-weak); }
.password-strength-bar-fill.strength-weak       { background-color: var(--strength-color-weak); }
.password-strength-bar-fill.strength-fair       { background-color: var(--strength-color-fair); }
.password-strength-bar-fill.strength-good       { background-color: var(--strength-color-good); }
.password-strength-bar-fill.strength-strong     { background-color: var(--strength-color-strong); }

.password-strength-label {
    margin-top: 0.35rem;
    font-size: 0.82rem;
    font-weight: 600;
    min-height: 1em;
    color: var(--criterion-unmet-color);
}

.password-strength-meter.strength-very-weak .password-strength-label  { color: var(--strength-color-very-weak); }
.password-strength-meter.strength-weak      .password-strength-label  { color: var(--strength-color-weak); }
.password-strength-meter.strength-fair      .password-strength-label  { color: var(--strength-color-fair); }
.password-strength-meter.strength-good      .password-strength-label  { color: var(--strength-color-good); }
.password-strength-meter.strength-strong    .password-strength-label  { color: var(--strength-color-strong); }

.password-criteria-list {
    list-style: none;
    padding: 0;
    margin: 0.5rem 0 0 0;
}

.password-criteria-item {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.78rem;
    line-height: 1.5;
}

.password-criteria-item.is-met    { color: var(--criterion-met-color); }
.password-criteria-item.is-unmet  { color: var(--criterion-unmet-color); }

.password-criteria-marker {
    display: inline-block;
    width: 1em;
    text-align: center;
    font-weight: 700;
}
```

No other line of `styles.css` is touched.

### 3.4 Line-by-Line Justification

| Block | Decision | Spec ref |
|---|---|---|
| Section banner comment | Documents the advisory-UX posture and the theming approach inline so a future maintainer doesn't refactor it into JS | NFR-01 |
| Five `--strength-color-*` custom properties under `:root` and `[data-theme="dark"]` | Theme switching with zero JS involvement (NFR-10); the colors map intuitively (empty=grey, very-weak=red, weak=orange, fair=yellow, good=light-green, strong=green); dark-theme values are lighter so they stay readable on a dark background | FR-12, NFR-10 |
| `--criterion-met-color` / `--criterion-unmet-color` | Same theming pattern for the criteria list text | FR-12 |
| `.password-strength-meter { margin-top, margin-bottom }` | Spacing — sits between two form groups; mirrors the existing form-group margins | (style consistency) |
| `.password-strength-bar { height: 6px; border-radius: 6px; overflow: hidden }` | Thin bar (does not crowd the form); rounded corners match the existing `.form-input` 8px radius family; `overflow: hidden` keeps the fill's color from bleeding outside the rounded track | (style consistency) |
| `.password-strength-bar-fill { transition: width 0.18s ease, background-color 0.18s ease }` | 180 ms is fast enough to feel responsive, slow enough to be visible; matches the "smooth but not laggy" feel of the existing focus-glow transitions | (UX) |
| Six `.password-strength-bar-fill.strength-*` rules | One per state class, each referencing the custom property — JS only needs to swap the class, CSS handles the color | FR-06, NFR-10 |
| `.password-strength-label { min-height: 1em }` | Prevents layout shift when the label transitions between empty and non-empty | (UX) |
| `.password-strength-meter.strength-*` `.password-strength-label` color rules | Optional label colorization that matches the bar; mirrors the strength-color customs without re-defining them | FR-06 |
| `.password-criteria-list { list-style: none; padding: 0; margin: 0.5rem 0 0 0 }` | Strips default `<ul>` styling so the list reads as a clean checklist, not a bulleted list | FR-13 |
| `.password-criteria-item { display: flex; gap: 0.4rem }` | Marker + text on one row; gap avoids manual margin tuning | (UX) |
| `.password-criteria-item.is-met` / `.is-unmet` rules scoped via the parent class | Avoids matching bare `.is-met` / `.is-unmet` elsewhere (FR-13 namespace guarantee) | FR-13 |
| `.password-criteria-marker { width: 1em; text-align: center }` | Fixed-width marker so the text doesn't jiggle horizontally when `✓` swaps with `✗` (✓ and ✗ have different glyph widths) | (UX polish) |

### 3.5 What NOT to Change in Phase 3

- **DO NOT** modify any existing CSS rule. The new section is appended at the end; no existing selector, value, or media-query is touched.
- **DO NOT** add `!important` to any new rule. The existing stylesheet doesn't use it; the new rules don't need it.
- **DO NOT** add a `@media (prefers-color-scheme: dark)` block. The project uses `[data-theme="dark"]` (driven by the theme-toggle script's `localStorage` value, with a `prefers-color-scheme` fallback already applied at the HTML level). Adding a separate `@media` block would create a second source of truth.
- **DO NOT** introduce a new font-family or import a web font.
- **DO NOT** add `:focus`, `:hover`, or `:active` rules on the meter elements. The meter is non-interactive (the user types into the password field, not into the meter).
- **DO NOT** add CSS animations beyond the two `transition` properties on the fill. No keyframes, no pulses, no flashes.
- **DO NOT** add CSS to `login.html` or `dashboard.html` styling.
- **DO NOT** introduce a CSS framework (Tailwind, Bootstrap, etc.).
- **DO NOT** add a CSS preprocessor (Sass, Less, etc.). Plain CSS only.

### 3.6 Phase 3 Verification (Pre-Server)

```bash
# Custom properties present under both theme blocks
grep -n -- '--strength-color-empty' frontend/static/css/styles.css
# Expected: at least two matching lines (one in :root, one in [data-theme="dark"])

grep -c -- '--strength-color-' frontend/static/css/styles.css
# Expected: at least 12  (5 strength colors x 2 themes + 2 references in transitions/usage; conservative lower bound)

# Five state-class fill rules present
grep -c '.password-strength-bar-fill.strength-' frontend/static/css/styles.css
# Expected: at least 6  (one per state class)

# Criteria list rules present
grep -n '.password-criteria-list' frontend/static/css/styles.css
grep -n '.password-criteria-item' frontend/static/css/styles.css
grep -n '.password-criteria-marker' frontend/static/css/styles.css

# No !important
grep -c '!important' frontend/static/css/styles.css
# Expected: same count as before the change (presumably 0, but the rule is "no NEW !important")

# No @media (prefers-color-scheme) added
grep -n '@media (prefers-color-scheme' frontend/static/css/styles.css \
  || echo '(no prefers-color-scheme media block — preserved)'

# Existing rules untouched (sample: header, form-input, btn)
grep -n '.header\|.form-input\|.btn-primary' frontend/static/css/styles.css | head -10
# Eyeball: these match the same lines they always did
```

Expected: the custom-property greps match in both theme blocks; the state-class count is ≥ 6; the criteria selectors match; `!important` count is unchanged from baseline; the media-query grep prints its fallback; the existing selectors still match.

---

## Phase 4 — Update `README.md` and `CLAUDE.md`

### 4.1 Goal

Reflect the new feature in two documentation files:

- `README.md`'s "Feature Enhancements" table: move "Password Strength Meter" out of the "Planned" rows into a "Done" row, mirroring the existing "Dark Mode Toggle" entry.
- `CLAUDE.md`:
  - Add a one-line bullet under "Frontend-Backend Integration" describing the meter's advisory-UX posture.
  - Add an "Important Rules" entry: the meter is frontend-only and advisory; do not push strength state into the backend, the session, or the database, and do not block submission on a weak password.
  - Append the new spec/plan pair to the Specification Hierarchy list.

### 4.2 Files to Modify

- `README.md`
- `CLAUDE.md`

### 4.3 Edit A — `README.md` Feature Enhancements Table

**Before** (relevant region):

```
| 0 | Dark Mode Toggle | Light/dark theme toggle on login, signup, and dashboard pages; preference saved in `localStorage`, restored before first paint to avoid FOUC, with `prefers-color-scheme` fallback. | **Done (v0.1.1)** |
| 1 | User Profile Page | ... | Planned |
| 2 | Email Verification on Signup | ... | Planned |
| 3 | Password Strength Meter | A real-time indicator on the signup form that displays password strength and the acceptance criteria (length, complexity, character classes) as the user types. | Planned |
| 4 | Change Password | ... | Planned |
```

**After**:

```
| 0 | Dark Mode Toggle | Light/dark theme toggle on login, signup, and dashboard pages; preference saved in `localStorage`, restored before first paint to avoid FOUC, with `prefers-color-scheme` fallback. | **Done (v0.1.1)** |
| 1 | Password Strength Meter | A real-time, frontend-only indicator on the signup form: a colored bar (Very Weak → Strong), a live checklist of five acceptance criteria (min length 8, lowercase, uppercase, digit, special character), and a `data-theme`-aware color palette. Advisory only — the backend still accepts any non-empty password. | **Done** |
| 2 | User Profile Page | ... | Planned |
| 3 | Email Verification on Signup | ... | Planned |
| 4 | Change Password | ... | Planned |
```

Renumbering: "Password Strength Meter" moves to row #1 (immediately after the done "Dark Mode Toggle"). The previous rows #1 (User Profile Page) and #2 (Email Verification on Signup) renumber down by one. Rows #4–#11 are unchanged in content but renumber up if they appeared between the moved row's old and new positions — in this case, none of #4–#11 sits between old-#3 and new-#1, so they stay at their original numbers (the only renumbering is User Profile #1 → #2 and Email Verification #2 → #3, with old-#3 → new-#1).

### 4.4 Edit B — `CLAUDE.md` Frontend-Backend Integration

**Before** (the "Frontend-Backend Integration" section):

```
## Frontend-Backend Integration

- **Login**: `fetch()` POST → JSON response → client-side redirect
- **Signup**: Standard form POST → server redirect
- **Dashboard**: Server-side `str.replace('{{username}}', ...)` — no template engine; the value is HTML-escaped with `html.escape(..., quote=True)` before substitution (VULN-2 closed)
- **Theme**: Pure client-side. Each template's `<head>` runs a synchronous IIFE that reads `localStorage["theme"]` (or `prefers-color-scheme` as fallback) and sets `<html data-theme="light|dark">` before first paint. A `#theme-toggle` button in the shared header flips the attribute and persists the new value. No server round-trip, no session field, no backend coupling.
```

**After** — append a new bullet after the Theme bullet:

```
## Frontend-Backend Integration

- **Login**: `fetch()` POST → JSON response → client-side redirect
- **Signup**: Standard form POST → server redirect
- **Dashboard**: Server-side `str.replace('{{username}}', ...)` — no template engine; the value is HTML-escaped with `html.escape(..., quote=True)` before substitution (VULN-2 closed)
- **Theme**: Pure client-side. Each template's `<head>` runs a synchronous IIFE that reads `localStorage["theme"]` (or `prefers-color-scheme` as fallback) and sets `<html data-theme="light|dark">` before first paint. A `#theme-toggle` button in the shared header flips the attribute and persists the new value. No server round-trip, no session field, no backend coupling.
- **Password strength meter**: Pure client-side. An inline `<script>` in `signup.html` listens to `input` on `#password`, scores the password against five criteria (length ≥ 8, lowercase, uppercase, digit, special) in JS, and updates a colored bar + live checklist beneath the password field. Advisory UX only — the backend's signup handler still accepts any non-empty password; nothing about the strength is sent to the server, stored in the session, or written to the database. The bar's colors are CSS custom properties shared between `:root` and `[data-theme="dark"]`, so toggling theme recolors the bar without re-running JS.
```

### 4.5 Edit C — `CLAUDE.md` Important Rules

**Before** (last existing rule in "Important Rules"):

```
- The dark-mode feature is purely frontend (CSS + 4 files: `styles.css`, `login.html`, `signup.html`, `dashboard.html`). Don't push theme state into the backend, the session, or the database.
```

**After** — add a new bullet immediately after the dark-mode rule:

```
- The dark-mode feature is purely frontend (CSS + 4 files: `styles.css`, `login.html`, `signup.html`, `dashboard.html`). Don't push theme state into the backend, the session, or the database.
- The password strength meter on the signup form is purely frontend and advisory (CSS + `signup.html` only). Don't push strength state into the backend, the session, or the database, and don't block form submission on a weak password — the bcrypt-hashing server-side gate (VULN-5 closure) is what authenticates; the meter only informs the user.
```

### 4.6 Edit D — `CLAUDE.md` Specification Hierarchy

**Before** (last item in the list):

```
11. `.claude/specs/csrf-fix.md` + `.claude/specs/csrf-fix-plan.md` — VULN-8 fix
```

**After** — append a new item:

```
11. `.claude/specs/csrf-fix.md` + `.claude/specs/csrf-fix-plan.md` — VULN-8 fix
12. `.claude/specs/pwd-str-meter.md` + `.claude/specs/pwd-str-meter-plan.md` — Password strength meter (signup, frontend-only, advisory)
```

### 4.7 Line-by-Line Justification

| Edit | Decision | Spec ref |
|---|---|---|
| README row moves to row #1 (just after dark-mode "Done") | Visually groups Done features at the top of the table; matches the existing convention | AC-15 |
| README row text emphasizes "Advisory only — the backend still accepts any non-empty password" | Makes the security posture explicit so a reader cannot mistake the meter for a hardening change | NFR-01 |
| CLAUDE.md bullet under Frontend-Backend Integration mirrors the "Theme" bullet's style | One-line summary + the key invariant ("no server round-trip, no session field, no backend coupling") | NFR-01 |
| CLAUDE.md bullet calls out CSS custom properties for theme recoloring | Documents the FR-12 / NFR-10 invariant in human language for future maintainers | FR-12, NFR-10 |
| Important Rule bullet next to the dark-mode rule | Same shape, same posture; reads as a paired guarantee | AC-15 |
| Important Rule cites VULN-5 closure | Reminds the maintainer that the bcrypt gate is what authenticates — replacing it with the meter would re-open VULN-5 | NFR-01 |
| Spec Hierarchy item #12 | Appends to the existing numbered list | AC-15 |

### 4.8 What NOT to Change in Phase 4

- **DO NOT** rewrite, shorten, or restructure any other row of the README's Feature Enhancements table.
- **DO NOT** edit the README's Bug Fixes table, Tech Stack, Project Structure, Vulnerabilities table, Learning Path, Useful Commands, or Troubleshooting sections.
- **DO NOT** change CLAUDE.md's opening paragraph, Vulnerability Map, "Login Flow After the Bcrypt Fix", "Session Secret After the Fix", "Rate Limiting After the Fix", or "CSRF Protection After the Fix" sections.
- **DO NOT** add a "Password Strength Meter After the Fix" subsection. The meter is a feature, not a vulnerability fix — the existing "After the Fix" subsections are reserved for vulnerability closures.
- **DO NOT** edit `docs/PRD.md` or `docs/TDD.md`. Those documents predate this enhancement; updating them is out of scope (the spec hierarchy treats them as the foundational pair, with later docs additive).

### 4.9 Phase 4 Verification (Pre-Server)

```bash
# README row moved to "Done"
grep -nE 'Password Strength Meter.*Done' README.md
# Expected: one matching line

grep -n 'Password Strength Meter' README.md
# Expected: a single row, no longer marked "Planned"

# CLAUDE.md bullet present
grep -n 'Password strength meter' CLAUDE.md
# Expected: at least one match under Frontend-Backend Integration

# CLAUDE.md Important Rule entry present
grep -n 'password strength meter on the signup form is purely frontend' CLAUDE.md
# Expected: one matching line

# Spec Hierarchy includes the new pair
grep -n 'pwd-str-meter' CLAUDE.md
# Expected: at least one matching line in the numbered spec list
```

Expected: all four greps match as described.

---

## Phase 5 — End-to-End Verification + Vulnerability Preservation Audit

### 5.1 Goal

Walk every Verification Step in spec §10, plus a final "nothing in `backend/` changed" diff, to confirm the feature works end-to-end and all eight closed vulnerabilities remain closed.

### 5.2 Steps

1. **Boot the app.**

   ```bash
   rm -f vulnerable_app.db
   uv run backend/app/main.py
   ```

   Expected: server listens on `http://localhost:3001` with no traceback. The signup page renders with the meter visible.

2. **Meter DOM rendered (AC-01, AC-02, TC-01, TC-02).** Run spec §10.1.

3. **CSRF hidden input still first child of form (AC-03, TC-03).** Run spec §10.2.

4. **Submit handler unchanged (AC-04, TC-04).** Run spec §10.3.

5. **No backend file changed (AC-05, AC-12, TC-05).** Run spec §10.4.

6. **No dependency change (AC-06, TC-06).** Run spec §10.5.

7. **No new network or persistence calls (AC-07, AC-08, TC-07, TC-08).** Run spec §10.6.

8. **Single `input` listener (AC-09, TC-09).** Run spec §10.7.

9. **Strength mapping correctness (AC-11, TC-10, TC-11, TC-12).** Run spec §10.8 in a browser.

10. **Weak password still submits (TC-13, TC-15).** Run spec §10.9.

11. **Theme toggle recolors instantly (TC-14).** Run spec §10.10 in a browser.

12. **CSRF and rate limit still enforced (AC-17, TC-16, TC-17).** Run spec §10.11.

13. **Other closed vulnerabilities preserved (AC-17, TC-18 – TC-22).** Run spec §10.12.

14. **App boots cleanly (AC-16, TC-23).** Already done in step 1 of this phase.

### 5.3 Vulnerability Preservation Final Audit

A focused diff that catches accidental backend or template-other-than-signup changes:

```bash
# Backend untouched
git diff --stat main..HEAD -- backend/

# Login and dashboard templates untouched
git diff --stat main..HEAD -- frontend/templates/login.html frontend/templates/dashboard.html

# No new dependency
git diff --stat main..HEAD -- pyproject.toml backend/pyproject.toml uv.lock

# No image change
git diff --stat main..HEAD -- frontend/static/images/

# Whitelist: only the four allowed files should appear
git diff --name-only main..HEAD | sort
# Expected output (sorted):
#   .claude/specs/pwd-str-meter-plan.md
#   .claude/specs/pwd-str-meter.md
#   CLAUDE.md
#   README.md
#   frontend/static/css/styles.css
#   frontend/templates/signup.html
```

Expected: each of the first four `git diff --stat` lines prints empty; the final `git diff --name-only` lists exactly six files (the two new spec docs plus the four modified files).

### 5.4 What NOT to Change in Phase 5

- Phase 5 is **read-only**. If a verification step fails, return to the appropriate earlier phase and fix the root cause. Do not "tweak around" failures by editing additional files.
- **DO NOT** add tests that hit `localhost` from CI here — the spec doesn't introduce a test framework. The verification steps are manual and curl-based, matching the pattern of the prior vulnerability-fix specs.

---

## Appendix A — Quick Diff Summary

After all phases, `git diff --stat main..HEAD` should look approximately like:

```
 .claude/specs/pwd-str-meter-plan.md            | <N> ++++++++++++++
 .claude/specs/pwd-str-meter.md                 | <N> ++++++++++++++
 CLAUDE.md                                      |   ~5 +++--
 README.md                                      |   ~2 +-
 frontend/static/css/styles.css                 |  ~75 ++++++++++++++++++++++
 frontend/templates/signup.html                 |  ~90 ++++++++++++++++++++++++
 6 files changed, ~XXX insertions(+), ~Y deletions(-)
```

Six files total: two new spec docs (this file and the parent spec) and four modified files. Zero backend changes, zero dependency changes, zero closed-vulnerability changes.

---

## Appendix B — Rollback

To remove this feature cleanly:

1. Delete the appended CSS section at the end of `frontend/static/css/styles.css` (everything from the `/* Password Strength Meter ... */` banner to end-of-file).
2. In `frontend/templates/signup.html`, delete the `<div class="password-strength-meter ...">...</div>` block and the new `<script>` block.
3. In `README.md`, move the "Password Strength Meter" row back to "Planned".
4. In `CLAUDE.md`, remove the new bullet under Frontend-Backend Integration, the new Important Rules entry, and item #12 from the Specification Hierarchy.
5. Optionally delete `.claude/specs/pwd-str-meter.md` and `.claude/specs/pwd-str-meter-plan.md`.

No database migration, no dependency removal, no middleware deregistration — the rollback is purely file-level.

---
