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

All HTML templates are in `app/templates/`. They use [Jinja2](https://jinja.palletsprojects.com/) with [Bootstrap 5](https://getbootstrap.com/) and [Bootstrap Icons](https://icons.getbootstrap.com/).

```
app/templates/
├── base.html          # Shared layout, nav, and footer
├── dashboard.html     # Main dashboard / certificate list
├── certificates/      # Certificate detail, add, download pages
├── ca/                # Certificate Authority pages
├── chains/            # Chain pages
├── users/             # User management pages
├── audit/             # Audit log
└── ...
```

Static assets (custom CSS, JS, images) are in `app/static/`.