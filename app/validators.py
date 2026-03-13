# ==============================================================================
# FILE:           validators.py
# DESCRIPTION:    Input validation helpers and string sanitizers used across
#                 route handlers and models.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import re

_DOMAIN_RE = re.compile(
    r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
_COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def _clean(value, max_len=256):
    """Strip whitespace and enforce a maximum length."""
    return (value or "").strip()[:max_len]


def normalize_alias(domain: str) -> str:
    """Convert a domain name to a safe alias string for filenames and keystores.

    Examples:
        *.ideocentric.com  → star.ideocentric.com
        www.example.com    → www.example.com
    """
    alias = domain.replace("*.", "star.").replace("*", "star")
    alias = re.sub(r"[^a-zA-Z0-9.\-]", "-", alias)
    alias = alias.strip("-")
    return alias or "certificate"


def _validate_domain(domain):
    """Return an error string, or None if the domain is valid."""
    if not domain:
        return "Domain is required."
    if len(domain) > 253:
        return "Domain name must be 253 characters or fewer."
    if not _DOMAIN_RE.match(domain):
        return "Invalid domain name. Use a valid hostname (e.g. example.com or *.example.com)."
    return None


def _validate_san_list(san_raw):
    """Validate newline-separated SAN domains. Returns (list, error_or_None)."""
    domains = [s.strip() for s in san_raw.splitlines() if s.strip()]
    for d in domains:
        err = _validate_domain(d)
        if err:
            return [], f"Invalid SAN '{d}': use a valid hostname."
    return domains, None


def _validate_email(email):
    """Return an error string, or None if email is valid (empty is allowed)."""
    if not email:
        return None
    if len(email) > 256:
        return "Email address must be 256 characters or fewer."
    if not _EMAIL_RE.match(email):
        return "Invalid email address format."
    return None


def _validate_country(country):
    """Return an error string, or None if country code is valid (empty is allowed)."""
    if not country:
        return None
    if not _COUNTRY_RE.match(country):
        return "Country must be exactly 2 letters (e.g. US)."
    return None


def _validate_username(username):
    """Return an error string, or None if the username is acceptable."""
    if not username:
        return "Username is required."
    if not _USERNAME_RE.match(username):
        return "Username may only contain letters, numbers, underscores, and hyphens (1–64 characters)."
    return None