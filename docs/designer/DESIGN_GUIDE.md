# SSL Manager — Designer Guide

This guide gets a designer up and running with a fully-populated local instance of SSL Manager — no Python, no database setup required.

---

## Prerequisites

| Tool | Install |
|---|---|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | [docker.com](https://www.docker.com/products/docker-desktop/) |
| [Git](https://git-scm.com/downloads) | Included on macOS; [git-scm.com](https://git-scm.com/downloads) on Windows |

---

## First-time setup

```bash
# Clone the repository
git clone https://github.com/your-org/ssl-manager.git
cd ssl-manager

# Start the app and seed it with example data
docker compose -f docker-compose.yml -f docker-compose.design.yml up --build
```

The first build takes a minute or two. Once running, open [http://localhost:5001](http://localhost:5001) in your browser.

Log in with any of the seeded accounts:

| Username | Password | Role |
|---|---|---|
| `designer` | `design123` | Superadmin |
| `alice` | `design123` | User |
| `bob` | `design123` | Inactive |

Use the `designer` account to see all pages and features.

---

## What's in the seed data

The database is pre-populated to exercise every visual state in the UI:

- **Certificates** — active (green / yellow / red / critical), expired, wildcard, pending signing, CSR import (with and without a private key)
- **Certificate Authorities** — four CAs covering all expiry badge colours (green / blue / yellow / red)
- **Certificate chains** — DigiCert, Let's Encrypt, and an internal chain
- **Audit log** — every action type, including failures and system backup entries
- **Users** — superadmin, standard user, and inactive account

---

## Refreshing the data

To wipe the database and re-seed with fresh example data:

```bash
docker compose -f docker-compose.yml -f docker-compose.design.yml run --rm seed-design
```

This re-runs the seeder against the running stack. Page refresh in the browser is all that's needed afterwards.

---

## Stopping and restarting

```bash
# Stop (preserves the database volume)
docker compose -f docker-compose.yml -f docker-compose.design.yml down

# Start again — data is still there from the last seed
docker compose -f docker-compose.yml -f docker-compose.design.yml up
```

To stop and delete all data (full reset):

```bash
docker compose -f docker-compose.yml -f docker-compose.design.yml down -v
```

Then run the full `up --build` command again to start fresh.

---

## Where to find the templates

All HTML templates are in `app/templates/` as a flat directory. They use [Jinja2](https://jinja.palletsprojects.com/) with [Bootstrap 5.3](https://getbootstrap.com/) and [Bootstrap Icons](https://icons.getbootstrap.com/).

```
app/templates/
├── base.html               # Shared layout: topbar, sidebar, flash messages, footer
├── login.html              # Login form
├── setup.html              # First-run admin account creation
├── certificates.html       # Certificate list (search, sort, paginate)
├── cert_new.html           # New certificate / renew form
├── cert_detail.html        # Certificate detail, downloads, signing
├── cert_detail_modal.html  # Modal variant of cert_detail loaded via fetch
├── cert_import_csr.html    # Import external CSR
├── chains.html             # Chain list
├── chain_form.html         # New chain form
├── chain_detail.html       # Chain detail — manage intermediate certificates
├── chain_import.html       # Import a PEM bundle into a chain
├── cas.html                # Certificate Authority list
├── ca_form.html            # New CA form
├── ca_detail.html          # CA detail — pending certificates, sign, download
├── profiles.html           # Certificate profile list and edit modal
├── users.html              # User list and edit/add modals
├── audit.html              # Audit log (paginated, searchable, sortable)
├── db_check.html           # Database integrity check (superadmin)
├── intermediate_form.html  # Add/edit intermediate certificate form
├── intermediates.html      # (legacy) intermediate certificate list
├── 403.html                # Access denied error page
├── 404.html                # Not found error page
└── settings.html           # (redirects to profiles)
```

Static assets (custom CSS, JS, images) are in `app/static/`.

---

## CSS system

All custom styles live in `app/static/server-manager.css`. The file is organised in three layers:

### 1. Bootstrap CSS variable overrides

The top of the file (inside a `[data-bs-theme="dark"], :root { }` block) redefines Bootstrap's CSS custom properties to implement the dark theme. Key tokens:

| Variable | Value | Used for |
|---|---|---|
| `--bs-body-bg` | `#1e2b30` | Page canvas (darkest surface) |
| `--bs-card-bg` | `#2f3e46` | Cards, table row base color |
| `--bs-card-cap-bg` | `#253238` | Card headers, table `thead` |
| `--bs-primary` | `#52796f` | Buttons, active states, links |
| `--bs-secondary` | `#84a98c` | Secondary buttons, icons |
| `--bs-body-font-family` | `'DM Sans', system-ui` | All body text |
| `--bs-font-monospace` | `'DM Mono', monospace` | Code values, timestamps, IPs |
| `--bs-body-font-size` | `1.025rem` | Base font size (inherited by table cells) |

> **Bootstrap specificity note:** Bootstrap 5.3's `[data-bs-theme="dark"]` component-level declarations can override `:root` tokens. Where this occurs (e.g. table row backgrounds, pagination active color) the fix is a direct property rule placed after Bootstrap in source order, rather than a variable override.

### 2. Component overrides

Below the variable block, `server-manager.css` contains direct property rules that fix specificity conflicts or add behaviour not covered by variables alone. Notable rules:

| Selector | Purpose |
|---|---|
| `.table > tbody > tr > td` | Sets `background-color: var(--bs-card-bg)` explicitly — overrides Bootstrap dark-mode table bg |
| `.table > tbody > tr > td.font-monospace` | Forces DM Mono at `0.9em` / weight 300 — prevents the DM Sans `td` reset from bleeding through |
| `.table > tbody > tr:nth-of-type(odd) > *` | Applies `#2a383f` stripe color (slightly darker than card bg) |
| `.page-item.active .page-link` | Sets pagination active color to `--bs-primary` — bypasses Bootstrap's component-level variable re-declaration |
| `.card` | Re-declares card tokens at component scope to guarantee they apply |

### 3. Custom badge system

Status pills use a two-class pattern instead of Bootstrap's `badge bg-*` utilities. This keeps colours consistent regardless of Bootstrap's contextual colour mapping.

```html
<span class="badge-status badge-valid">active</span>
<span class="badge-status badge-expiring">expiring</span>
<span class="badge-status badge-expired">expired</span>
<span class="badge-status badge-pending">pending</span>
```

| Modifier | Colour | Typical use |
|---|---|---|
| `badge-valid` | Green (`#52796f` / `#354f52`) | Active, success, superadmin, default |
| `badge-expiring` | Amber | Expiring soon |
| `badge-expired` | Red-tone | Expired, failure, inactive |
| `badge-pending` | Muted teal | Pending signing, user role, "you" indicator |

Each badge renders as a pill with a `::before` dot indicator. Base styles are in `.badge-status`; colour is applied by the modifier class.