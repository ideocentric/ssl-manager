#!/usr/bin/env python3
"""
generate_pdf.py — Build PDF artifacts from SSL Manager documentation.

─── Tool chain ──────────────────────────────────────────────────────────────
  1. pandoc   converts Markdown → standalone HTML (handles tables, code
              blocks, images, and generates a linked table of contents).
  2. WeasyPrint  renders the HTML + docs/pdf/<guide>.css → PDF.

No browser is involved, so no system file paths appear in headers or footers.
Page headers and footers are defined entirely in the CSS @page rules.

─── Usage ───────────────────────────────────────────────────────────────────
  python docs/generate_pdf.py              # build all guides
  python docs/generate_pdf.py --guide user # build one guide

─── Adding a new guide ──────────────────────────────────────────────────────
  1. Write docs/<audience>/YOUR_GUIDE.md  (use relative paths for images).
  2. Create docs/pdf/<audience>-guide.css  (copy user-guide.css as a start;
     update the @top-center title string).
  3. Add a Guide(...) entry to GUIDES list below.
  4. Run:  python docs/generate_pdf.py --guide <key>

─── Prerequisites ───────────────────────────────────────────────────────────
  pandoc     on PATH     (brew install pandoc)
  weasyprint in .venv    (pip install -r requirements-docs.txt  — dev tooling,
                          NOT in the server's requirements.txt; needs Python 3.10+)
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


def _ensure_homebrew_libs() -> None:
    """macOS: add /opt/homebrew/lib to DYLD_LIBRARY_PATH and re-exec if needed.

    WeasyPrint's cffi bindings call dlopen() for Pango/GLib at import time.
    On Apple Silicon Macs, Homebrew installs these under /opt/homebrew/lib
    which is not in the default dyld search path.  Setting DYLD_LIBRARY_PATH
    and re-exec-ing the interpreter before the first import is the reliable fix.
    """
    if sys.platform != "darwin":
        return
    homebrew_lib = "/opt/homebrew/lib"
    if not Path(homebrew_lib).exists():
        return
    current = os.environ.get("DYLD_LIBRARY_PATH", "")
    if homebrew_lib in current.split(":"):
        return  # already set — avoid infinite re-exec
    new_path = f"{homebrew_lib}:{current}" if current else homebrew_lib
    os.environ["DYLD_LIBRARY_PATH"] = new_path
    os.execv(sys.executable, [sys.executable] + sys.argv)


_ensure_homebrew_libs()  # must run before any weasyprint import

REPO_ROOT = Path(__file__).parent.parent
DOCS_DIR  = Path(__file__).parent


# ── Guide registry ────────────────────────────────────────────────────────────

@dataclass
class Guide:
    key:        str                  # --guide <key>
    source_md:  "Path | list[Path]"  # one Markdown file, or a list to concatenate
    css:        Path                 # WeasyPrint stylesheet  (docs/pdf/<name>.css)
    output_pdf: Path                 # where the PDF lands
    title:      str                  # pandoc document title (used in HTML <title>)
    toc_depth:  int = 2              # table-of-contents depth


GUIDES: list[Guide] = [
    Guide(
        key        = "user",
        source_md  = DOCS_DIR / "user" / "USER_GUIDE.md",
        css        = DOCS_DIR / "pdf"  / "user-guide.css",
        output_pdf = DOCS_DIR / "user" / "SSL_Manager_User_Guide.pdf",
        title      = "SSL Manager — User Guide",
        toc_depth  = 2,
    ),
    Guide(
        key        = "admin",
        source_md  = [
            DOCS_DIR / "admin" / "REQUIREMENTS.md",
            DOCS_DIR / "admin" / "INSTALL.md",
            DOCS_DIR / "admin" / "DEPLOY-AWS.md",
            DOCS_DIR / "admin" / "DEPLOY-AZURE.md",
        ],
        css        = DOCS_DIR / "pdf"  / "admin-guide.css",
        output_pdf = DOCS_DIR / "admin" / "SSL_Manager_Admin_Guide.pdf",
        title      = "SSL Manager — Administrator Guide",
        toc_depth  = 2,
    ),
]


# ── Core build logic ──────────────────────────────────────────────────────────

def check_pandoc() -> None:
    if not shutil.which("pandoc"):
        sys.exit("Error: pandoc not found. Install with:  brew install pandoc")


def check_weasyprint():
    try:
        import weasyprint
        return weasyprint
    except ImportError:
        sys.exit(
            "Error: weasyprint not installed.\n"
            "Run:  pip install weasyprint   (or add to .venv)"
        )


def build(guide: Guide, weasyprint) -> None:
    """Convert one Markdown guide to PDF via pandoc + WeasyPrint."""
    # Normalise source_md to a list so the rest of the function is uniform.
    sources: list[Path] = (
        guide.source_md if isinstance(guide.source_md, list) else [guide.source_md]
    )
    # pandoc is run from the directory of the first source file so that
    # relative image paths in that file resolve correctly.  For multi-file
    # admin guides there are no images, so this is fine.
    source_dir = sources[0].parent

    label = ", ".join(p.name for p in sources)
    print(f"[{guide.key}] {label} → HTML…")

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as tmp:
        tmp_path = Path(tmp.name)

    try:
        # ── Step 1: Markdown → standalone HTML ──────────────────────────────
        # Run pandoc from the first source file's directory so that relative
        # image paths (e.g. screenshots/02-login/login_page.png) are preserved
        # as-is in the HTML src attributes.  WeasyPrint then resolves them
        # against base_url=source_dir, which is set in Step 2.
        # Multiple input files are concatenated by pandoc with an implicit
        # horizontal rule between each, which maps to a section break in CSS.
        subprocess.run(
            [
                "pandoc",
                *[str(s) for s in sources],
                "--from",     "markdown",
                "--to",       "html5",
                "--standalone",
                "--toc",
                "--toc-depth", str(guide.toc_depth),
                "--metadata", f"title={guide.title}",
                "--syntax-highlighting", "tango",
                "-o", str(tmp_path),
            ],
            check=True,
            cwd=source_dir,
        )

        # ── Step 2: HTML + CSS → PDF ─────────────────────────────────────────
        print(f"[{guide.key}] HTML → {guide.output_pdf.name}…")
        html_doc = weasyprint.HTML(
            filename=str(tmp_path),
            base_url=str(source_dir) + "/",   # resolve relative image paths
        )
        css_doc = weasyprint.CSS(filename=str(guide.css))
        html_doc.write_pdf(str(guide.output_pdf), stylesheets=[css_doc])

    finally:
        tmp_path.unlink(missing_ok=True)

    size_kb = guide.output_pdf.stat().st_size // 1024
    print(f"[{guide.key}] ✓  {guide.output_pdf}  ({size_kb} KB)")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build PDF documentation from Markdown sources.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--guide",
        metavar="KEY",
        help="Build only this guide (omit to build all). "
             f"Available: {', '.join(g.key for g in GUIDES)}",
    )
    args = parser.parse_args()

    check_pandoc()
    weasyprint = check_weasyprint()

    targets = (
        [g for g in GUIDES if g.key == args.guide]
        if args.guide else GUIDES
    )
    if not targets:
        sys.exit(f"Unknown guide key '{args.guide}'. "
                 f"Available: {', '.join(g.key for g in GUIDES)}")

    for guide in targets:
        build(guide, weasyprint)

    print("\nDone.")


if __name__ == "__main__":
    main()