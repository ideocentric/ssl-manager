#!/usr/bin/env python3
"""
take_screenshots.py  —  Regenerate docs/user/screenshots/ for SSL Manager.

─── Viewport-sizing procedure ───────────────────────────────────────────────
Every screenshot follows this three-step sequence so the fixed footer
(position:fixed; bottom:0; height:40px) never overlaps page content:

  1. nav() resets the viewport to 800 px tall before each page load.
     This prevents the min-height:calc(100vh-…) rule on .main-content
     from inflating the document after a previous tall capture, which
     would cascade into an oversized scrollHeight measurement.

  2. After the page settles, capture() reads the true document height:
         scrollHeight = document.documentElement.scrollHeight
     At the 800 px baseline this reflects the actual content, not an
     artificially expanded layout.

  3. The viewport is then expanded to scrollHeight + 40 px (the footer
     height) and the screenshot is taken.  The footer lands at the very
     bottom of the image with a clear gap above it.

─── Adding a new screenshot ─────────────────────────────────────────────────
  1. Navigate to the target page with nav(page, base_url, "/your/path").
  2. Perform any JS interactions (open modal, fill search, etc.).
  3. Call capture(page, "section/filename.png").
  4. Add the corresponding ![alt](screenshots/section/filename.png) line
     to docs/user/USER_GUIDE.md in the appropriate section.

─── Prerequisites ───────────────────────────────────────────────────────────
    pip install playwright cryptography
    playwright install chromium

    The app must be running with seed_design.py data loaded.
    Easiest: docker exec <container> python /app/seed_design.py --force
    Or:      docker compose -f docker-compose.yml -f docker-compose.design.yml up

Usage:
    python docs/take_screenshots.py [--url http://localhost:5001]
"""

import argparse
import asyncio
import datetime
import sys
import tempfile
from pathlib import Path

DOCS_DIR  = Path(__file__).parent
SHOTS_DIR = DOCS_DIR / "user" / "screenshots"

USERNAME = "designer"
PASSWORD = "design123"
WIDTH    = 1280


# ══════════════════════════════════════════════════════════════════════════════
#  Crypto helpers  —  generate throwaway files for upload-preview screenshots
# ══════════════════════════════════════════════════════════════════════════════

def _make_key_and_cert():
    """Return (key_pem: bytes, cert_pem: bytes) for a minimal self-signed cert."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,         "preview.example.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,   "Screenshot Corp"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,        "US"),
    ])
    now  = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem  = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


def _make_p12(key_pem: bytes, cert_pem: bytes, password: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    key  = serialization.load_pem_private_key(key_pem, password=None)
    cert = x509.load_pem_x509_certificate(cert_pem)
    return pkcs12.serialize_key_and_certificates(
        name=b"preview",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )


# ══════════════════════════════════════════════════════════════════════════════
#  Playwright helpers
# ══════════════════════════════════════════════════════════════════════════════

async def login(page, base_url: str) -> None:
    await page.goto(f"{base_url}/login")
    await page.wait_for_load_state("networkidle")
    await page.fill('input[name="username"]', USERNAME)
    await page.fill('input[name="password"]', PASSWORD)
    await page.click('button[type="submit"]')
    await page.wait_for_load_state("networkidle")


async def nav(page, base_url: str, path: str) -> None:
    # Reset to a compact baseline so min-height:calc(100vh-…) doesn't inflate
    # the scrollHeight measurement in capture() after a tall previous page.
    await page.set_viewport_size({"width": WIDTH, "height": 800})
    await page.goto(f"{base_url}{path}")
    await page.wait_for_load_state("networkidle")
    # Auto-recover if the session was dropped (redirected to login)
    if "/login" in page.url and path != "/login":
        print(f"  [warn] session lost navigating to {path}, re-logging in…")
        await login(page, base_url)
        await page.goto(f"{base_url}{path}")
        await page.wait_for_load_state("networkidle")


async def capture(page, rel_path: str) -> None:
    """
    Resize viewport height to the full document scrollHeight, then screenshot.
    The fixed footer (position:fixed; bottom:0) therefore lands at the absolute
    bottom of the image, and the existing app-body margin-bottom keeps it clear
    of all content.
    """
    out = SHOTS_DIR / rel_path
    out.parent.mkdir(parents=True, exist_ok=True)
    scroll_h = await page.evaluate("document.documentElement.scrollHeight")
    # Add footer height (40 px) as a buffer: scrollHeight doesn't include the
    # fixed footer, so without this the footer overlaps the last content row.
    await page.set_viewport_size({"width": WIDTH, "height": max(scroll_h + 40, 640)})
    await page.screenshot(path=str(out))
    print(f"  ✓  {rel_path}")


async def wait_for_modal(page, modal_id: str) -> None:
    """Wait for a Bootstrap modal to finish its opening animation."""
    await page.evaluate(
        f"""new Promise(resolve => {{
            const el = document.getElementById('{modal_id}');
            if (el.classList.contains('show')) {{ resolve(); return; }}
            el.addEventListener('shown.bs.modal', resolve, {{once: true}});
        }})"""
    )


async def wait_for_preview(page, selector: str, timeout: int = 10_000) -> None:
    """Wait for a preview panel to appear and its spinner to clear."""
    await page.wait_for_selector(selector, state="visible", timeout=timeout)
    # Wait until the loading spinner disappears (replaced by fetched content)
    spinner = page.locator(f"{selector} .spinner-border")
    if await spinner.count() > 0:
        await spinner.first.wait_for(state="detached", timeout=timeout)


# ══════════════════════════════════════════════════════════════════════════════
#  Entity ID discovery  —  parse list pages so IDs don't need to be hardcoded
# ══════════════════════════════════════════════════════════════════════════════

def _first_id_from_hrefs(hrefs: list, segment: str) -> int | None:
    """Extract the integer ID from the first href containing /segment/N."""
    for href in hrefs:
        parts = [p for p in href.split("/") if p]
        if segment in parts:
            idx = parts.index(segment)
            if idx + 1 < len(parts) and parts[idx + 1].isdigit():
                return int(parts[idx + 1])
    return None


async def _hrefs(page, selector: str) -> list[str]:
    """Return all href values matching selector without waiting (no timeout)."""
    links = await page.locator(selector).all()
    result = []
    for link in links:
        href = await link.get_attribute("href")
        if href:
            result.append(href)
    return result


async def discover_ids(page, base_url: str) -> dict:
    ids: dict = {}

    # ── Certificates: first active, first pending ─────────────────────────────
    await nav(page, base_url, "/certificates")
    rows = await page.locator("table tbody tr").all()
    active_cert = pending_cert = None
    for row in rows:
        links = await row.locator("a[href*='/certificates/']").all()
        if not links:
            continue
        href = await links[0].get_attribute("href")
        if not href:
            continue
        last_part = href.rstrip("/").split("/")[-1]
        if not last_part.isdigit():
            continue
        cid = int(last_part)
        badges = await row.locator(".badge").all()
        if not badges:
            continue
        badge_text = (await badges[0].inner_text()).strip().lower()
        if active_cert is None and badge_text == "active":
            active_cert = cid
        if pending_cert is None and "pending" in badge_text:
            pending_cert = cid
        if active_cert and pending_cert:
            break
    ids["active_cert"]  = active_cert  or 1
    ids["pending_cert"] = pending_cert or 11

    # ── CAs: first CA detail link ─────────────────────────────────────────────
    await nav(page, base_url, "/cas")
    ca_hrefs = await _hrefs(page, "a[href*='/cas/']")
    ids["ca"] = _first_id_from_hrefs(ca_hrefs, "cas") or 1

    # ── Chains: first chain detail link ──────────────────────────────────────
    await nav(page, base_url, "/chains")
    chain_hrefs = await _hrefs(page, "a[href*='/chains/']")
    ids["chain"] = _first_id_from_hrefs(chain_hrefs, "chains") or 1

    # ── Users: all edit-link IDs; alice is the second user ───────────────────
    await nav(page, base_url, "/users")
    user_hrefs = await _hrefs(page, "a[href*='/users/'][href*='/edit']")
    user_ids: list[int] = []
    for href in user_hrefs:
        uid = _first_id_from_hrefs([href], "users")
        if uid and uid not in user_ids:
            user_ids.append(uid)
    ids["alice"] = user_ids[1] if len(user_ids) > 1 else (user_ids[0] if user_ids else 2)

    return ids


# ══════════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════════

async def main(base_url: str) -> None:
    from playwright.async_api import async_playwright

    # Generate throwaway crypto assets for upload-preview screenshots.
    print("Generating test crypto files for upload-preview screenshots…")
    key_pem, cert_pem = _make_key_and_cert()
    p12_pass  = "test1234"
    p12_bytes = _make_p12(key_pem, cert_pem, p12_pass)

    with tempfile.TemporaryDirectory() as _tmp:
        tmp       = Path(_tmp)
        cert_file = tmp / "preview.crt"
        key_file  = tmp / "preview.key"
        p12_file  = tmp / "preview.p12"
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)
        p12_file.write_bytes(p12_bytes)

        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            ctx     = await browser.new_context(viewport={"width": WIDTH, "height": 900})
            page    = await ctx.new_page()

            # ── Auth ──────────────────────────────────────────────────────────
            print(f"Logging in at {base_url}…")
            await login(page, base_url)

            # ── Discover entity IDs ───────────────────────────────────────────
            print("Discovering entity IDs from list pages…")
            ids = await discover_ids(page, base_url)
            ac  = ids["active_cert"]   # active cert  (full downloads available)
            pc  = ids["pending_cert"]  # pending cert (upload section present)
            ca  = ids["ca"]            # first CA
            chn = ids["chain"]         # first chain
            ali = ids["alice"]         # alice user (role=user, for edit form)
            print(f"  active_cert={ac}  pending_cert={pc}  ca={ca}  chain={chn}  alice={ali}")

            print("\nCapturing screenshots…")

            # ── 02  Login — use a throwaway context so the main session is untouched
            login_ctx  = await browser.new_context(viewport={"width": WIDTH, "height": 900})
            login_page = await login_ctx.new_page()
            await login_page.goto(f"{base_url}/login")
            await login_page.wait_for_load_state("networkidle")
            await capture(login_page, "02-login/login_page.png")
            await login_ctx.close()

            # ── 03  Dashboard / certificates list ─────────────────────────────
            await nav(page, base_url, "/certificates")
            await capture(page, "03-dashboard/certificates_list.png")

            # ── 04  Profiles ──────────────────────────────────────────────────
            await nav(page, base_url, "/profiles")
            await capture(page, "04-profiles/profiles_list.png")

            await nav(page, base_url, "/profiles/new")
            await capture(page, "04-profiles/profile_new_form.png")

            # ── 05  Chains ────────────────────────────────────────────────────
            await nav(page, base_url, "/chains")
            await capture(page, "05-chains/chains_list.png")

            await nav(page, base_url, "/chains/new")
            await capture(page, "05-chains/chain_new_form.png")

            # Open Add Certificate modal first (fresh nav, default viewport, easy click)
            await nav(page, base_url, f"/chains/{chn}")
            await page.get_by_role("button", name="Add Certificate").first.click()
            await wait_for_modal(page, "addCertModal")
            await capture(page, "05-chains/chain_add_cert_form.png")

            # Plain chain detail (re-navigate; modal state is gone)
            await nav(page, base_url, f"/chains/{chn}")
            await capture(page, "05-chains/chain_detail.png")

            await nav(page, base_url, f"/chains/{chn}/import")
            await capture(page, "05-chains/chain_import_bundle.png")

            # ── 06  Certificate Authorities ───────────────────────────────────
            await nav(page, base_url, "/cas")
            await capture(page, "06-ca/ca_list.png")

            await nav(page, base_url, "/cas/new")
            await capture(page, "06-ca/ca_new_form.png")

            await nav(page, base_url, f"/cas/{ca}")
            await capture(page, "06-ca/ca_detail.png")

            # ── 07  Certificate lifecycle ─────────────────────────────────────

            # Import dropdown — navigate to certs page then open the dropdown
            await nav(page, base_url, "/certificates")
            await page.get_by_role("button", name="Import").click()
            await page.wait_for_selector(".dropdown-menu.show", state="visible")
            await capture(page, "07-lifecycle/07-0_import_dropdown.png")

            await nav(page, base_url, "/certificates/new")
            await capture(page, "07-lifecycle/07-1_cert_new_form.png")

            await nav(page, base_url, f"/certificates/{pc}")
            await capture(page, "07-lifecycle/07-2_cert_detail_pending.png")

            # Upload preview: set the file input, then wait for the preview panel
            await nav(page, base_url, f"/certificates/{pc}")
            await page.locator("#certFileInput").set_input_files(str(cert_file))
            await wait_for_preview(page, "#bundlePreview")
            await capture(page, "07-lifecycle/07-3_cert_upload_with_preview.png")

            # Active cert detail — top-of-page view (same page, no scroll needed)
            await nav(page, base_url, f"/certificates/{ac}")
            await capture(page, "07-lifecycle/07-3_cert_detail_active_top.png")

            await nav(page, base_url, f"/certificates/{ac}")
            await capture(page, "07-lifecycle/07-4_cert_detail_active_full.png")

            await nav(page, base_url, "/certificates/import-csr")
            await capture(page, "07-lifecycle/07-4_import_csr_form.png")

            # P12 import — plain form (no file loaded)
            await nav(page, base_url, "/certificates/import-p12")
            await capture(page, "07-lifecycle/07-5_import_p12_form.png")

            # P12 import preview: upload file → shows "enter password" message,
            # then fill password → debounced fetch populates full preview.
            await nav(page, base_url, "/certificates/import-p12")
            await page.locator("#p12FileInput").set_input_files(str(p12_file))
            await page.wait_for_selector("#p12Preview", state="visible")
            await page.locator("#p12Password").fill(p12_pass)
            await page.locator("#p12Password").dispatch_event("input")
            await wait_for_preview(page, "#p12Preview")
            await capture(page, "07-lifecycle/07-5_import_p12_with_preview.png")

            # Keypair import — plain form (no files loaded)
            await nav(page, base_url, "/certificates/import-keypair")
            await capture(page, "07-lifecycle/07-6_import_keypair_form.png")

            # Keypair import preview: upload both files simultaneously,
            # the JS triggers once both are present.
            await nav(page, base_url, "/certificates/import-keypair")
            await page.locator("#keyFileInput").set_input_files(str(key_file))
            await page.locator("#certFileInput").set_input_files(str(cert_file))
            await wait_for_preview(page, "#keypairPreview")
            await capture(page, "07-lifecycle/07-6_import_keypair_with_preview.png")

            # ── 08  Browsing and finding certificates ─────────────────────────
            await nav(page, base_url, "/certificates")
            await capture(page, "08-browsing/cert_list_default.png")

            # Sorted by expiry (ascending = oldest first) — JS client-side sort
            await nav(page, base_url, "/certificates")
            await page.click('th.sortable[data-col="2"]')
            await page.wait_for_timeout(300)
            await capture(page, "08-browsing/cert_list_sorted_expiry.png")

            # Filtered by search term "active"
            await nav(page, base_url, "/certificates")
            await page.fill("#certSearch", "active")
            await page.wait_for_timeout(300)
            await capture(page, "08-browsing/cert_list_search_active.png")

            # Filtered by search term "expired"
            await nav(page, base_url, "/certificates")
            await page.fill("#certSearch", "expired")
            await page.wait_for_timeout(300)
            await capture(page, "08-browsing/cert_list_search_expired.png")

            # ── 09  Downloads ─────────────────────────────────────────────────
            await nav(page, base_url, f"/certificates/{ac}")
            await capture(page, "09-downloads/cert_detail_downloads.png")

            # ── 10  Renew ─────────────────────────────────────────────────────
            await nav(page, base_url, f"/certificates/{ac}/renew")
            await capture(page, "10-renew/renew_form.png")

            # ── 11  User management ───────────────────────────────────────────
            await nav(page, base_url, "/users")
            await capture(page, "11-users/users_list.png")

            await nav(page, base_url, "/users/new")
            await capture(page, "11-users/user_add_form.png")

            await nav(page, base_url, f"/users/{ali}/edit")
            await capture(page, "11-users/user_edit_form.png")

            # ── 12  Audit log ─────────────────────────────────────────────────
            await nav(page, base_url, "/audit")
            await capture(page, "12-audit/audit_log.png")

            # Filtered audit log — use URL parameter (server-side search)
            await nav(page, base_url, "/audit?q=login")
            await capture(page, "12-audit/audit_log_search.png")

            await browser.close()

    print(f"\nDone — {len(list(SHOTS_DIR.rglob('*.png')))} screenshots in {SHOTS_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Capture SSL Manager documentation screenshots.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--url",
        default="http://localhost:5001",
        metavar="BASE_URL",
        help="Base URL of the running SSL Manager app (default: http://localhost:5001)",
    )
    args = parser.parse_args()

    try:
        asyncio.run(main(args.url))
    except KeyboardInterrupt:
        sys.exit(0)