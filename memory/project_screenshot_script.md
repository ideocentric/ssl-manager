---
name: project-screenshot-script
description: Screenshot regeneration script at docs/take_screenshots.py — viewport-expansion strategy to fix fixed-footer overlap
metadata:
  type: project
---

A Playwright-based screenshot script lives at `docs/take_screenshots.py`. It regenerates all 34 documentation screenshots in `docs/user/screenshots/`.

**Why:** The app footer (`position: fixed; bottom: 0; height: 40px`) was covering the bottom of content in screenshots taken at a standard viewport height. Expanding the viewport to `document.documentElement.scrollHeight` before each capture puts the fixed footer at the true image bottom, using the existing `margin-bottom: 40px` on `.app-body` to keep all content clear.

**How to apply:** When the user needs to retake any documentation screenshots, direct them to run:
```
python docs/take_screenshots.py [--url http://localhost:5001]
```
The app must be running with seed_design.py data (`docker compose -f docker-compose.yml -f docker-compose.design.yml up`).

Requirements: `pip install playwright && playwright install chromium`

Credentials used: designer / design123 (from seed_design.py).

Interactive screenshots handled: import dropdown (click), Bootstrap modal (waits for shown.bs.modal event), upload previews (sets file inputs via Playwright, waits for spinner to clear), client-side sort (click column header), client-side search (fill input).