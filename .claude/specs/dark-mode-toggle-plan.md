# Implementation Plan — Dark Mode Toggle

**Version:** 1.0.0
**Last Updated:** June 11, 2026
**Parent Spec:** [dark-mode-toggle.md](./dark-mode-toggle.md)
**Foundation Spec:** [app-foundation.md](./app-foundation.md)
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)

---

## 0. Plan Overview

This plan implements the dark-mode toggle feature defined in [dark-mode-toggle.md](./dark-mode-toggle.md). The work is divided into **six phases** to keep each step small, individually verifiable, and reversible. The plan is **additive only** — no backend code is modified, no template structure that drives the existing vulnerabilities (`{{username}}` placeholder, unescaped search reflection, raw form posts) is changed, and no security control (CSRF tokens, parameterized queries, rate limiters, escaped output, session-secret change) is introduced — even incidentally.

### Phase Summary

| # | Phase | Files Touched | Goal |
|---|-------|--------------|------|
| 1 | CSS Theming Foundation | `frontend/static/css/styles.css` | Introduce `:root` custom properties (light defaults) and refactor existing rules to consume them. No visual change yet. |
| 2 | Dark Theme Overrides | `frontend/static/css/styles.css` | Add `[data-theme="dark"]` overrides for the same custom properties. |
| 3 | Toggle Button Styling | `frontend/static/css/styles.css` | Add `.theme-toggle` button styles + focus ring. |
| 4 | Pre-Render Init Script + Toggle Button in Templates | `frontend/templates/login.html`, `signup.html`, `dashboard.html` | Add the synchronous `<head>` script and place the toggle button inside the shared header. |
| 5 | Toggle Click/Keyboard Handler | `frontend/templates/login.html`, `signup.html`, `dashboard.html` | Add the runtime handler (vanilla JS, inline). |
| 6 | End-to-End Verification | None (read-only) | Walk through every Verification Step in the spec. |

### Files Modified (Total)

Exactly the four files declared in spec §3:

- `frontend/static/css/styles.css`
- `frontend/templates/login.html`
- `frontend/templates/signup.html`
- `frontend/templates/dashboard.html`

No other file may be created or edited. AC-07 / TC-14 enforce this with a `git status` check at the end.

### Files That MUST NOT Be Modified

- Any file under `backend/app/**` — the backend defines all eight intentional vulnerabilities. Touching it risks accidentally fixing one.
- `CLAUDE.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, `.claude/specs/app-foundation-plan.md`, `.claude/specs/dark-mode-toggle.md`.
- `pyproject.toml`, `uv.lock`, `requirements.txt`.
- The existing inline `<script>` blocks on `login.html` (fetch-based login submission) and `signup.html` (client-side password confirmation). These drive the asymmetric login behavior and the client-only confirm-password validation documented in app-foundation.md §3.1, §3.2 — they must stay byte-identical.

### Vulnerability Preservation Checklist (Carry Through Every Phase)

When making any edit, re-confirm each of these is **untouched**:

1. ✅ SQL injection in `auth_service.py` — not in scope, not modified.
2. ✅ Stored XSS via `{{username}}` — dashboard template must still contain the literal `{{username}}` placeholder inside `<strong>...</strong>`. NEVER replace it with a template-engine variable, NEVER add escaping, NEVER add a Content-Security-Policy meta tag.
3. ✅ Reflected XSS at `/search` — not in scope.
4. ✅ Session secret `"super-secret-key-12345"` — not in scope.
5. ✅ MD5 password hashing — not in scope.
6. ✅ `/download/db` open endpoint — not in scope.
7. ✅ No rate limiting — must NOT add any throttling, even on the new client-side toggle.
8. ✅ No CSRF tokens — must NOT add a CSRF token to the login or signup form, even as part of a "template cleanup" touch.

---

## Phase 1 — CSS Theming Foundation (Refactor Without Visual Change)

### 1.1 Goal

Introduce a CSS custom-property layer in `:root` containing the **current light palette** and refactor existing color/background declarations in `styles.css` to consume those variables. After this phase, the light theme must look pixel-identical to today's release — this is a pure refactor.

### 1.2 File to Modify

- `frontend/static/css/styles.css`

### 1.3 Custom Property Inventory

The following variables MUST be defined under `:root`. Names use the existing color vocabulary from app-foundation.md §5.1.

```css
:root {
    color-scheme: light dark;

    /* Surfaces */
    --color-bg-body:           #ffffff;          /* default body */
    --color-bg-dashboard:      #eef1f8;          /* .dashboard-body override */
    --color-bg-surface:        #ffffff;          /* white cards, form panel */
    --color-bg-input:          #f8f9ff;          /* form inputs */
    --color-bg-header:         #ffffff;          /* shared header */

    /* Text */
    --color-text-primary:      #1e293b;
    --color-text-secondary:    #475569;
    --color-text-muted:        #64748b;
    --color-text-accent:       #1a237e;          /* link / brand */
    --color-text-on-brand:     #ffffff;

    /* Borders & dividers */
    --color-border-soft:       #e2e8f0;          /* card borders, header bottom */
    --color-border-input:      #c5cae9;
    --color-border-input-focus:#3949ab;

    /* Brand gradients & accents */
    --color-brand-primary:     #1a237e;
    --color-brand-secondary:   #3949ab;
    --color-brand-tertiary:    #283593;
    --color-brand-deep:        #0d1b5e;

    /* Focus glow */
    --shadow-focus:            0 0 0 3px rgba(57, 73, 171, 0.12);
    --shadow-header:           0 2px 10px rgba(26, 35, 126, 0.08);
    --shadow-card-hover:       0 4px 16px rgba(26, 35, 126, 0.10);

    /* Error palette */
    --color-error-bg:          #fef2f2;
    --color-error-border:      #fecaca;
    --color-error-text:        #991b1b;
    --color-error-inline:      #dc2626;

    /* Vulnerability tag pairs (background, text) */
    --tag-sqli-bg:    #fef9c3;  --tag-sqli-fg:    #854d0e;
    --tag-xss-bg:     #fee2e2;  --tag-xss-fg:     #991b1b;
    --tag-session-bg: #f3e8ff;  --tag-session-fg: #6b21a8;
    --tag-brute-bg:   #ffedd5;  --tag-brute-fg:   #9a3412;
    --tag-crypto-bg:  #dcfce7;  --tag-crypto-fg:  #166534;
    --tag-exposed-bg: #dbeafe;  --tag-exposed-fg: #1e40af;
    --tag-csrf-bg:    #fce7f3;  --tag-csrf-fg:    #9d174d;

    /* Step cards (dashboard) */
    --color-step-bg:      #1a237e;
    --color-step-text:    #ffffff;
    --color-step-muted:   rgba(255, 255, 255, 0.85);
    --color-step-badge:   rgba(255, 255, 255, 0.2);
}
```

Place this `:root` block **at the very top** of `styles.css`, immediately after the existing reset block (`*, *::before, *::after { ... }`). The existing reset stays exactly as-is.

### 1.4 Refactor — Before/After Snippets

For each colored rule in the file, replace literal hex values with `var(--...)`. The following table lists the precise replacements; line numbers refer to the current file.

| Rule | Property | Before | After |
|------|----------|--------|-------|
| `body` (L10–16) | `color` | `#1e293b` | `var(--color-text-primary)` |
| `body` | `background` | *(none — add)* | `var(--color-bg-body)` |
| `a` (L18–21) | `color` | `#1a237e` | `var(--color-text-accent)` |
| `.header` (L30–44) | `background` | `#ffffff` | `var(--color-bg-header)` |
| `.header` | `border-bottom` | `1px solid #e2e8f0` | `1px solid var(--color-border-soft)` |
| `.header` | `box-shadow` | `0 2px 10px rgba(...)` | `var(--shadow-header)` |
| `.header-title` (L46–50) | `color` | `#1a237e` | `var(--color-text-accent)` |
| `.auth-left` (L74–82) | `background` | linear-gradient literal | linear-gradient using `var(--color-brand-deep)`, `var(--color-brand-primary)`, `var(--color-brand-tertiary)` |
| `.auth-badge` (L118–129) | `color` | `#c5cae9` | `var(--color-border-input)` *(reuses light-indigo)* |
| `.auth-right` (L168–174) | `background` | `#ffffff` | `var(--color-bg-surface)` |
| `.form-title` (L181–186) | `color` | `#1e293b` | `var(--color-text-primary)` |
| `.form-subtitle` (L188–192) | `color` | `#64748b` | `var(--color-text-muted)` |
| `.form-label` (L199–205) | `color` | `#475569` | `var(--color-text-secondary)` |
| `.form-input` (L207–217) | `background` | `#f8f9ff` | `var(--color-bg-input)` |
| `.form-input` | `border` | `1.5px solid #c5cae9` | `1.5px solid var(--color-border-input)` |
| `.form-input` | `color` | `#1e293b` | `var(--color-text-primary)` |
| `.form-input::placeholder` (L219–221) | `color` | `#64748b` | `var(--color-text-muted)` |
| `.form-input:focus` (L223–227) | `border-color` | `#3949ab` | `var(--color-border-input-focus)` |
| `.form-input:focus` | `box-shadow` | literal | `var(--shadow-focus)` |
| `.btn-primary` (L247–253) | `background` | `#1a237e` | `var(--color-brand-primary)` |
| `.btn-primary` | `color` | `#ffffff` | `var(--color-text-on-brand)` |
| `.btn-primary:hover` (L255–257) | `background` | `#283593` | `var(--color-brand-tertiary)` |
| `.error-message` (L260–268) | `background` | `#fef2f2` | `var(--color-error-bg)` |
| `.error-message` | `border` | `1px solid #fecaca` | `1px solid var(--color-error-border)` |
| `.error-message` | `color` | `#991b1b` | `var(--color-error-text)` |
| `.password-error` (L270–274) | `color` | `#dc2626` | `var(--color-error-inline)` |
| `.form-link` (L277–282) | `color` | `#64748b` | `var(--color-text-muted)` |
| `.form-link a` (L284–287) | `color` | `#1a237e` | `var(--color-text-accent)` |
| `.dashboard-body` (L292–294) | `background` | `#eef1f8` | `var(--color-bg-dashboard)` |
| `.hero-banner` (L297–305) | `background` | linear-gradient literal | linear-gradient using `var(--color-brand-primary)`, `var(--color-brand-secondary)` |
| `.mission-card` (L358–364) | `background` | `#ffffff` | `var(--color-bg-surface)` |
| `.mission-card` | `border` | `1px solid #e2e8f0` | `1px solid var(--color-border-soft)` |
| `.section-title` (L366–371) | `color` | `#1e293b` | `var(--color-text-primary)` |
| `.mission-description` (L373–377) | `color` | `#475569` | `var(--color-text-secondary)` |
| `.vuln-header` (L384–391) | `color` | `#64748b` | `var(--color-text-muted)` |
| `.vuln-card` (L399–405) | `background` | `#ffffff` | `var(--color-bg-surface)` |
| `.vuln-card` | `border` | `1px solid #e2e8f0` | `1px solid var(--color-border-soft)` |
| `.vuln-card:hover` (L407–409) | `box-shadow` | literal | `var(--shadow-card-hover)` |
| `.card-title` (L411–416) | `color` | `#1e293b` | `var(--color-text-primary)` |
| `.card-description` (L418–422) | `color` | `#475569` | `var(--color-text-secondary)` |
| `.tag-sqli`..`.tag-csrf` (L433–466) | `background` / `color` | each literal pair | matching `var(--tag-*-bg)` / `var(--tag-*-fg)` |
| `.step-card` (L478–485) | `background` | `#1a237e` | `var(--color-step-bg)` |
| `.step-card` | `color` | `#ffffff` | `var(--color-step-text)` |
| `.step-description` (L506–510) | `color` | `rgba(255,255,255,0.85)` | `var(--color-step-muted)` |
| `.step-badge` (L487–498) | `background` | `rgba(255,255,255,0.2)` | `var(--color-step-badge)` |

Example before/after of one rule:

**Before** (`styles.css` L207–217):
```css
.form-input {
    width: 100%;
    padding: 12px 16px;
    font-size: 0.9rem;
    font-family: inherit;
    background: #f8f9ff;
    border: 1.5px solid #c5cae9;
    border-radius: 8px;
    color: #1e293b;
    transition: border-color 0.2s, box-shadow 0.2s;
}
```

**After**:
```css
.form-input {
    width: 100%;
    padding: 12px 16px;
    font-size: 0.9rem;
    font-family: inherit;
    background: var(--color-bg-input);
    border: 1.5px solid var(--color-border-input);
    border-radius: 8px;
    color: var(--color-text-primary);
    transition: border-color 0.2s, box-shadow 0.2s;
}
```

### 1.5 What NOT to Change in Phase 1

- **DO NOT** change the `.auth-left` gradient literals to dark-only colors. We're keeping the gradient brand-consistent across both themes (NFR-07 spec note: the left panel is the brand panel; only its text contrast may need tweaking in Phase 2).
- **DO NOT** touch the `@media (max-width: 768px)` responsive block — it has no themed colors.
- **DO NOT** add any new selectors yet (toggle styles come in Phase 3).
- **DO NOT** remove or reorder any existing comment headers (`/* ============ ... */`).

### 1.6 Phase 1 Verification

1. Run `uv run backend/app/main.py`.
2. Visit `http://localhost:3001/login`, `/signup`, and `/welcome` (after logging in as a normal user).
3. Compare to the v0.1.0 baseline screenshots. Pages MUST look identical — same colors, same fonts, same spacing.
4. Open DevTools → Elements → Computed and confirm `body { background: rgb(255, 255, 255); color: rgb(30, 41, 59); }`.
5. `grep '{{username}}' frontend/templates/dashboard.html` — placeholder still present (TC-15).
6. Stop the server.

---

## Phase 2 — Dark Theme Overrides

### 2.1 Goal

Add a `:root[data-theme="dark"]` block that reassigns the custom properties from Phase 1 to a dark palette. After this phase, manually setting `<html data-theme="dark">` via DevTools must recolor the page completely (AC-02).

### 2.2 File to Modify

- `frontend/static/css/styles.css`

### 2.3 Insert Location

Immediately **after** the `:root { ... }` block added in Phase 1, before the `body` rule.

### 2.4 Dark Palette Block

```css
:root[data-theme="dark"] {
    /* Surfaces */
    --color-bg-body:           #0f172a;
    --color-bg-dashboard:      #0b1220;
    --color-bg-surface:        #1e293b;
    --color-bg-input:          #111827;
    --color-bg-header:         #0b1220;

    /* Text */
    --color-text-primary:      #e2e8f0;
    --color-text-secondary:    #cbd5e1;
    --color-text-muted:        #94a3b8;
    --color-text-accent:       #a5b4fc;   /* indigo-300 — readable on dark */
    --color-text-on-brand:     #ffffff;

    /* Borders & dividers */
    --color-border-soft:       #1f2937;
    --color-border-input:      #334155;
    --color-border-input-focus:#a5b4fc;

    /* Brand gradients & accents stay close to brand for hero/auth-left */
    --color-brand-primary:     #3949ab;
    --color-brand-secondary:   #5c6bc0;
    --color-brand-tertiary:    #283593;
    --color-brand-deep:        #1a237e;

    /* Focus glow */
    --shadow-focus:            0 0 0 3px rgba(165, 180, 252, 0.25);
    --shadow-header:           0 2px 10px rgba(0, 0, 0, 0.45);
    --shadow-card-hover:       0 4px 16px rgba(0, 0, 0, 0.50);

    /* Error palette — slightly darker bg, lighter text */
    --color-error-bg:          #3f1d1d;
    --color-error-border:      #7f1d1d;
    --color-error-text:        #fecaca;
    --color-error-inline:      #fca5a5;

    /* Vulnerability tag pairs — keep hues identifiable, darken backgrounds */
    --tag-sqli-bg:    #3a2e0a;  --tag-sqli-fg:    #facc15;
    --tag-xss-bg:     #3a1414;  --tag-xss-fg:     #fca5a5;
    --tag-session-bg: #2e1a4d;  --tag-session-fg: #d8b4fe;
    --tag-brute-bg:   #3a2210;  --tag-brute-fg:   #fdba74;
    --tag-crypto-bg:  #102a18;  --tag-crypto-fg:  #86efac;
    --tag-exposed-bg: #102036;  --tag-exposed-fg: #93c5fd;
    --tag-csrf-bg:    #3a1432;  --tag-csrf-fg:    #f9a8d4;

    /* Step cards */
    --color-step-bg:      #1a237e;
    --color-step-text:    #ffffff;
    --color-step-muted:   rgba(255, 255, 255, 0.78);
    --color-step-badge:   rgba(255, 255, 255, 0.18);
}
```

### 2.5 What NOT to Change in Phase 2

- **DO NOT** rewrite any of the rules touched in Phase 1. The dark theme is delivered purely by reassigning the same variables.
- **DO NOT** add `prefers-color-scheme` media queries inside CSS. Spec FR-06 mandates that the **JavaScript** init script consults `matchMedia` and writes `data-theme`; CSS does not need a media query path.
- **DO NOT** modify the literal `#ffffff` in `.welcome-heading` (auth-left) or `.hero-title` (dashboard hero) — these sit on top of the brand gradient and must stay white in both themes for contrast. They are out-of-scope for theming.

### 2.6 Phase 2 Verification

1. Re-run `uv run backend/app/main.py`.
2. In DevTools Elements panel, edit the `<html>` element and add `data-theme="dark"`.
3. Confirm `/login`, `/signup`, `/welcome` all recolor — dark body, dark form panel, light text, dark cards.
4. Remove the attribute → page reverts to light cleanly.
5. Confirm the auth-left brand panel still reads cleanly (white heading on indigo gradient).
6. Confirm vulnerability tag pills remain visually distinct from each other in dark mode (TC visual check supporting AC-06 grouping).

---

## Phase 3 — Toggle Button Styling

### 3.1 Goal

Add the visual styles for the toggle button itself. The button still doesn't exist in the templates after this phase — only its styles are present.

### 3.2 File to Modify

- `frontend/static/css/styles.css`

### 3.3 Insert Location

Inside the `/* ============ Shared Header ============ */` section, **after** the `.header-logo` rule (current L58–62), so it lives logically next to the other header-children.

### 3.4 Rules to Add

```css
.theme-toggle {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    margin-right: 12px;
    background: transparent;
    border: 1px solid var(--color-border-soft);
    border-radius: 8px;
    font-family: inherit;
    font-size: 1.1rem;
    line-height: 1;
    color: var(--color-text-accent);
    cursor: pointer;
    transition: background-color 0.2s, border-color 0.2s, box-shadow 0.2s;
}

.theme-toggle:hover {
    background: var(--color-bg-input);
    border-color: var(--color-border-input);
}

.theme-toggle:focus-visible {
    outline: none;
    border-color: var(--color-border-input-focus);
    box-shadow: var(--shadow-focus);
}

.theme-toggle .theme-toggle-icon {
    pointer-events: none;
}
```

Then extend the `.header-logos` flex container to keep the toggle visually adjacent to the logos. **No change required** to `.header-logos` itself — the toggle is a sibling of `.header-logos` inside the same `<header>`, positioned to its left by document order.

### 3.5 Responsive Touch-Up

Inside the existing `@media (max-width: 768px)` block (current L515–551), append:

```css
    .theme-toggle {
        width: 36px;
        height: 36px;
        font-size: 1rem;
        margin-right: 8px;
    }
```

### 3.6 What NOT to Change in Phase 3

- **DO NOT** modify `.header`, `.header-title`, `.header-logos`, or `.header-logo` declarations.
- **DO NOT** add any global `button { ... }` reset — it would affect the existing `.btn`, `.btn-primary`, `.btn-logout` styling.

### 3.7 Phase 3 Verification

- Static-only phase: no visible change yet (button isn't in any template).
- Open `styles.css` in browser DevTools "Sources" tab and confirm the new rules parse without errors (no red squiggles).

---

## Phase 4 — Pre-Render Init Script + Toggle Button in Templates

### 4.1 Goal

Add to each of the three templates:
1. A synchronous inline `<script>` in `<head>` that sets `<html data-theme="...">` **before** the stylesheet is applied (FR-03, NFR-01).
2. A `<button id="theme-toggle" class="theme-toggle" type="button">` inside the shared header.

### 4.2 Files to Modify

- `frontend/templates/login.html`
- `frontend/templates/signup.html`
- `frontend/templates/dashboard.html`

### 4.3 Pre-Render Init Script

Insert **immediately after** `<meta name="viewport" ...>` and **before** `<title>`. Placing it before the stylesheet `<link>` ensures the `data-theme` attribute is in place when the CSS is applied, eliminating FOUC.

```html
    <script>
        (function () {
            try {
                var saved = localStorage.getItem('theme');
                if (saved !== 'light' && saved !== 'dark') {
                    saved = null;
                }
                var theme = saved;
                if (!theme && window.matchMedia) {
                    theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
                }
                if (!theme) {
                    theme = 'light';
                }
                document.documentElement.setAttribute('data-theme', theme);
            } catch (e) {
                document.documentElement.setAttribute('data-theme', 'light');
            }
        })();
    </script>
```

Notes:
- The IIFE is wrapped in `try/catch` to satisfy EC-02 (localStorage unavailable).
- Only the literal strings `"light"` and `"dark"` are accepted (FR-02, EC-01).
- No `defer`, no `async`, no `src=` — must be synchronous (FR-03).

### 4.4 Toggle Button Markup

Inside `<header class="header">`, insert the button **before** the existing `<div class="header-logos">` so the toggle sits to the left of the three logos (matches header spacing rules established in Phase 3).

```html
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to dark mode">
            <span class="theme-toggle-icon" aria-hidden="true">🌙</span>
        </button>
```

The initial `aria-label="Switch to dark mode"` and icon `🌙` are placeholders — they will be reconciled with the actual current theme by the runtime handler (Phase 5) on `DOMContentLoaded`.

### 4.5 Per-Template Diffs

#### 4.5.1 `frontend/templates/login.html`

**Before** (`<head>` block, L1–8):
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Security Vulnerability Lab</title>
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
```

**After**:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script>
        (function () {
            try {
                var saved = localStorage.getItem('theme');
                if (saved !== 'light' && saved !== 'dark') {
                    saved = null;
                }
                var theme = saved;
                if (!theme && window.matchMedia) {
                    theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
                }
                if (!theme) {
                    theme = 'light';
                }
                document.documentElement.setAttribute('data-theme', theme);
            } catch (e) {
                document.documentElement.setAttribute('data-theme', 'light');
            }
        })();
    </script>
    <title>Login - Security Vulnerability Lab</title>
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
```

**Header before** (L11–18):
```html
    <header class="header">
        <div class="header-title">Security Vulnerability Lab</div>
        <div class="header-logos">
            <img src="/static/images/PUCIT_Logo.png" alt="PUCIT" class="header-logo">
            <img src="/static/images/excaliat-logo.png" alt="Excaliat" class="header-logo">
            <img src="/static/images/blue-logo-scl2.png" alt="FCCU" class="header-logo">
        </div>
    </header>
```

**After**:
```html
    <header class="header">
        <div class="header-title">Security Vulnerability Lab</div>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to dark mode">
            <span class="theme-toggle-icon" aria-hidden="true">🌙</span>
        </button>
        <div class="header-logos">
            <img src="/static/images/PUCIT_Logo.png" alt="PUCIT" class="header-logo">
            <img src="/static/images/excaliat-logo.png" alt="Excaliat" class="header-logo">
            <img src="/static/images/blue-logo-scl2.png" alt="FCCU" class="header-logo">
        </div>
    </header>
```

**MUST NOT MODIFY** in `login.html`:
- The existing `<form id="login-form">` markup.
- The existing inline `<script>` block at L64–86 (the fetch-based login submission).

#### 4.5.2 `frontend/templates/signup.html`

Apply the identical two edits:
1. Add the same `<script>` block immediately after `<meta name="viewport">` and before `<title>`.
2. Insert the same `<button id="theme-toggle">` between `.header-title` and `.header-logos`.

**MUST NOT MODIFY** in `signup.html`:
- The existing `<form id="signup-form" action="/signup" method="POST">`. Specifically, do NOT add any `<input type="hidden" name="csrf_token" ...>` or any token-bearing element.
- The existing inline `<script>` block at L71–86 (client-side password confirmation validation).

#### 4.5.3 `frontend/templates/dashboard.html`

Apply the identical two edits:
1. Add the same `<script>` block immediately after `<meta name="viewport">` and before `<title>`.
2. Insert the same `<button id="theme-toggle">` between `.header-title` and `.header-logos`.

**MUST NOT MODIFY** in `dashboard.html`:
- The literal `{{username}}` placeholder at L27 inside `<strong>{{username}}</strong>`. Do **not** wrap it, escape it, replace it with a Jinja-style block, or add `|e` filter syntax. The backend performs `html.replace('{{username}}', username)` (app-foundation.md §2.4 / FR-02); any alteration breaks Stored XSS (TC-09).
- The vulnerability cards, mission card, step cards, or hero markup.

### 4.6 Phase 4 Verification

1. Restart `uv run backend/app/main.py`.
2. Clear DevTools → Application → Local Storage for `http://localhost:3001`.
3. Hard-reload `/login`. Confirm:
   - The toggle button appears in the header between the title and the logos.
   - The aria-label initially reads "Switch to dark mode".
   - Page renders in light (assuming light OS).
4. In Application → Local Storage, set `theme = "dark"`. Hard-reload. The page renders dark on first paint — **no flash of light** (NFR-01 / AC-04).
5. Repeat for `/signup` and (after login) `/welcome`.
6. `grep -n '{{username}}' frontend/templates/dashboard.html` → still present (TC-15).
7. `grep -n 'csrf' frontend/templates/login.html frontend/templates/signup.html` → no matches (TC-12 partial).

---

## Phase 5 — Toggle Click/Keyboard Handler

### 5.1 Goal

Wire up the runtime behavior on the toggle button: click + keyboard activation flip the theme, persist to `localStorage`, and update the `aria-label` and icon (FR-04, FR-05, NFR-03, EC-02).

### 5.2 Files to Modify

- `frontend/templates/login.html`
- `frontend/templates/signup.html`
- `frontend/templates/dashboard.html`

### 5.3 Handler Script

Append the following to **each** template's existing body-level `<script>` block (or, for `dashboard.html` which has no existing body script, add a new `<script>` block at the end of `<body>`, immediately before `</body>`):

```html
    <script>
        (function () {
            var toggle = document.getElementById('theme-toggle');
            if (!toggle) return;

            function reflect(theme) {
                var nextAction = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
                var icon = theme === 'dark' ? '☀' : '🌙';
                toggle.setAttribute('aria-label', nextAction);
                var iconEl = toggle.querySelector('.theme-toggle-icon');
                if (iconEl) iconEl.textContent = icon;
            }

            reflect(document.documentElement.getAttribute('data-theme') || 'light');

            toggle.addEventListener('click', function () {
                var current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
                var next = current === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', next);
                try {
                    localStorage.setItem('theme', next);
                } catch (e) {
                    /* persistence unavailable — in-page state still flips (EC-02) */
                }
                reflect(next);
            });
        })();
    </script>
```

Notes:
- Using a native `<button type="button">` means `Enter` and `Space` keypresses fire `click` automatically — no separate keydown handler needed (FR-05, NFR-03).
- The handler reconciles the initial aria-label/icon with the actual theme set by the pre-render script (covers SP-02 where the system pref forced dark).
- `localStorage.setItem` is wrapped in `try/catch` for EC-02.
- The IIFE pattern avoids leaking variables into the global scope where the existing login/signup scripts already define `form`, `errorDiv`, `passwordError`, etc.

### 5.4 Per-Template Notes

#### 5.4.1 `login.html`

Place the new toggle handler `<script>` block **after** the existing fetch-based login script (currently at L64–86). Do NOT merge into it — keep concerns separated for diff clarity.

#### 5.4.2 `signup.html`

Place the new toggle handler `<script>` block **after** the existing password-confirmation script (currently at L71–86).

#### 5.4.3 `dashboard.html`

Add a new `<script>` block at the very end of `<body>`, immediately before `</body>`. This file currently has no script blocks at all, so this is the first one.

### 5.5 What NOT to Change in Phase 5

- **DO NOT** modify the existing login fetch script. Its behavior (fetch POST, JSON response handling, `window.location.href = data.redirect`) is part of app-foundation.md §3.2 and is intentionally distinct from the signup form.
- **DO NOT** modify the existing signup password-confirm script. Confirm-password validation is intentionally client-only (app-foundation.md §6.1).
- **DO NOT** add any `fetch()` call, no server round-trip, no cookie write. The theme lives entirely in localStorage and the DOM.

### 5.6 Phase 5 Verification

Run the full spec § 10 verification, but specifically:

1. Restart `uv run backend/app/main.py`.
2. Visit `/login`. Click the toggle → page flips to dark; localStorage `theme === "dark"`; icon shows `☀`; aria-label reads "Switch to light mode". (TC-03)
3. Click again → flips back; localStorage `theme === "light"`; icon `🌙`; aria-label "Switch to dark mode". (TC-04)
4. Toggle to dark, hard-reload → no flash, renders dark immediately. (TC-05)
5. Toggle to dark on `/login`, navigate to `/signup` → renders dark immediately. (TC-06)
6. Tab to the toggle, press Space → theme flips, focus ring stays visible on the toggle. (TC-07)
7. In DevTools console: `localStorage.setItem('theme', 'purple'); location.reload();` → page renders per `prefers-color-scheme`. (TC-08)
8. In DevTools console:
   ```js
   var orig = localStorage.setItem;
   localStorage.setItem = function(){ throw new Error('blocked'); };
   document.getElementById('theme-toggle').click();
   ```
   → theme still flips in the DOM; no uncaught error reaches the console (the `try/catch` swallows it). Restore: `localStorage.setItem = orig;`. (TC-13)

---

## Phase 6 — End-to-End Verification

This phase is read-only. Walk every Verification Step from spec §10 in order and tick each box. **Do not** edit anything during this phase; if any step fails, document the failure and return to the failing phase to repair.

### 6.1 Run the Application

```bash
uv run backend/app/main.py
```

Confirm the server starts on port 3001 with no new errors or warnings vs. v0.1.0.

### 6.2 Functional Walkthrough

| Step | URL / Action | Pass Criteria |
|------|-------------|---------------|
| 6.2.1 | `http://localhost:3001/login` | AC-01 — toggle visible; AC-04 — no FOUC with `theme="dark"` saved |
| 6.2.2 | Click toggle on `/login` | TC-03 — flips dark, localStorage updates, aria-label and icon update |
| 6.2.3 | Click toggle again | TC-04 — flips light |
| 6.2.4 | Tab to toggle + Space | TC-07 — keyboard activation works, focus ring visible |
| 6.2.5 | `http://localhost:3001/signup` | Theme persisted from `/login` (TC-06) |
| 6.2.6 | Register normal user `alice` / `alice@test.com` / `pass123` | App-foundation SP-01 still works — redirect to `/login` |
| 6.2.7 | Log in as `alice` | SP-02 still works — redirect to `/welcome` |
| 6.2.8 | `http://localhost:3001/welcome` | Dashboard renders, toggle visible and functional, username "alice" displayed |

### 6.3 Vulnerability Preservation Walkthrough (Critical — AC-06)

| # | Vulnerability | Test | Pass Criteria |
|---|--------------|------|---------------|
| 1 | SQL Injection | On `/login`, submit `username=admin' OR '1'='1' --`, any password | Auth bypass still works (logs in despite no matching record) |
| 2 | Stored XSS | Register user `<script>alert('xss')</script>` / any email / any password, log in, visit `/welcome` in **light** mode | Alert fires |
| 2b | Stored XSS in dark | Toggle to dark, hard-reload `/welcome` | Alert fires again (TC-09) |
| 3 | Reflected XSS | Visit `/search?q=<script>alert(1)</script>` in dark mode | Alert fires (TC-10) |
| 4 | Session Secret | `grep -n 'super-secret-key-12345' backend/app/main.py` | Line still present (TC-11) |
| 5 | Weak Crypto | `grep -n 'md5' backend/app/core/security.py` | MD5 usage still present |
| 6 | Exposed DB | `curl -O http://localhost:3001/download/db` without session cookie | File downloads successfully |
| 7 | No Rate Limit | Loop login POST 100× | No 429s, all reach server |
| 8 | No CSRF | Inspect `<form id="login-form">` and `<form id="signup-form">` markup | No CSRF token field anywhere (TC-12) |

### 6.4 Affected-Files Audit (AC-07 / TC-14)

```bash
git status
```

Expected output (modified file list):

```
modified:   frontend/static/css/styles.css
modified:   frontend/templates/dashboard.html
modified:   frontend/templates/login.html
modified:   frontend/templates/signup.html
```

No other file may appear in the modified or untracked list. If `vulnerable_app.db` appears as a runtime artifact, that's pre-existing behavior (db is created at startup) — confirm it's gitignored or was already present.

```bash
git diff --stat
```

Confirm only the four expected files appear.

### 6.5 Spec Acceptance Criteria Roll-Up

Tick every AC from spec §8:

- [ ] AC-01 Toggle Presence (6.2.1, 6.2.5, 6.2.8)
- [ ] AC-02 Theme Attribute Driven (Phase 2.6 manual DevTools test)
- [ ] AC-03 Persistence (6.2.2)
- [ ] AC-04 No FOUC (6.2.1)
- [ ] AC-05 Keyboard & ARIA (6.2.4)
- [ ] AC-06 Vulnerabilities Intact (6.3 — all 8 rows)
- [ ] AC-07 Affected Files Only (6.4)
- [ ] AC-08 System Preference Fallback (Phase 5.6 step 7 / DevTools "Emulate CSS prefers-color-scheme")

### 6.6 Stop the Server

`Ctrl+C` to stop. Phase complete.

---

## Risk Log & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Accidentally adding `|e` escape filter to `{{username}}` while "modernizing" the template | Low | High — silently fixes Stored XSS | Phase 4 explicit "MUST NOT" callouts; TC-09 verifies in 6.3 |
| Adding a `<meta http-equiv="Content-Security-Policy">` "for safety" | Low | High — blocks the inline init script AND breaks XSS demos | Phase 4 forbids CSP; verifier in 6.3 row 2/3 catches it |
| Adding `<input type="hidden" name="csrf_token">` because it "felt incomplete" | Low | High — fixes CSRF, breaks TC-12 | Phase 4 explicit "MUST NOT" callout for signup form |
| FOUC because the script is placed after the stylesheet | Medium | Medium — visible flash | Phase 4 specifies script BEFORE `<link rel="stylesheet">` |
| FOUC because the script is loaded with `defer`/`async` | Medium | Medium — same as above | Phase 4.3 specifies synchronous inline only |
| `localStorage` access throws in private mode and crashes init | Medium | Medium — page renders unstyled | EC-02 try/catch in both init and click handler |
| Touching backend files (e.g., `auth.py` to inject a CSP header) | Low | Critical — fixes vulnerabilities | Phase 0 "Files That MUST NOT Be Modified" list; 6.4 `git status` audit |
| Unicode emoji icon doesn't render on Linux dev environment | Low | Cosmetic | Icons are decorative; aria-label carries the semantic meaning |

---

## Rollback Procedure

If any phase fails verification and cannot be repaired quickly:

```bash
git restore frontend/static/css/styles.css
git restore frontend/templates/login.html
git restore frontend/templates/signup.html
git restore frontend/templates/dashboard.html
```

Because the entire feature is contained in four files with no backend coupling, rollback is a single restore command. No database migration, no config change, no dependency change is involved.

---

## Out-of-Band: What This Plan Deliberately Does NOT Do

To make the negative space explicit:

- **No new file** is created. The spec says four affected files; this plan honors that. No new JS file under `frontend/static/js/`, no new CSS partial.
- **No backend change.** Zero edits under `backend/`. The theme never reaches the server.
- **No template engine introduction.** The dashboard's runtime `str.replace('{{username}}', ...)` substitution stays unchanged — Jinja2/Mako etc. are NOT introduced as part of this feature.
- **No CSRF token, no rate limiter, no escaping, no salt, no session-secret rotation, no auth on `/download/db`.** The eight vulnerabilities are the lab's curriculum; this plan is a UX enhancement only.
- **No animation easing on the theme transition.** Implicit CSS `transition` declarations already in the file (e.g., on `.form-input`, `.btn`) are sufficient. We are not adding a global `* { transition: ... }`.
- **No new dependency** in `pyproject.toml`. No npm, no font CDN, no icon library.
