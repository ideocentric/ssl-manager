# ==============================================================================
# FILE:           app.py
# DESCRIPTION:    Flask web application for SSL certificate lifecycle management.
#                 Handles RSA key and CSR generation, signed certificate storage,
#                 CA chain management, multi-format bundle downloads, user
#                 authentication, CSRF protection, input validation, and audit
#                 logging.
#
# USAGE:          python app.py                        # local dev server
#                 gunicorn --bind unix:/run/ssl-manager/ssl-manager.sock app:app
#
# DEPENDENCIES:   Flask, Flask-SQLAlchemy, Flask-Login, cryptography, pyjks,
#                 gunicorn, openssl (system binary, required for P7B export)
# REQUIREMENTS:   Python 3.10+
#
# AUTHOR:         Matt Comeione <matt@ideocentric.com>
# ORGANIZATION:   ideocentric
# GITHUB:         https://github.com/ideocentric/ssl-manager
# CREATED:        2026-03-12
# LAST MODIFIED:  2026-03-12
# VERSION:        1.0.0
#
# CHANGELOG:
#   1.0.0 - 2026-03-12 - Initial release
#
# NOTES:
#   In production, run behind nginx (loopback only) with SSH port forwarding
#   for remote access.  See README.md and install.sh for full deployment
#   instructions.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ==============================================================================


import io
import json
import logging
import logging.handlers
import os
import re
import secrets
import subprocess
import tempfile
from datetime import datetime, timezone
from functools import wraps
from io import BytesIO
from zipfile import ZipFile

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///ssl_manager.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "ssl-manager-secret-key-change-in-prod")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB upload limit

db = SQLAlchemy(app)

# ---------------------------------------------------------------------------
# SQLite connection hardening
# ---------------------------------------------------------------------------
# Listen on the SQLAlchemy Engine *class* (not an instance) so the handler
# fires for every SQLite connection regardless of when the engine is created.
# The isinstance guard ensures this is a no-op for any non-SQLite backend.

from sqlalchemy import event as _sa_event
from sqlalchemy.engine import Engine as _Engine
import sqlite3 as _sqlite3


@_sa_event.listens_for(_Engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Apply safety and performance PRAGMAs on every new SQLite connection.

    * ``journal_mode=WAL`` — Write-Ahead Log eliminates the brief window
      where a power-loss can corrupt the database under the default DELETE
      journal.  WAL also allows readers and writers to proceed concurrently,
      which is important when multiple gunicorn workers are active.

    * ``synchronous=NORMAL`` — Flushes to disk at the most critical moments
      (WAL checkpoints) without a full ``fsync`` on every commit.  Safe with
      WAL mode; provides a good balance between durability and performance.

    * ``foreign_keys=ON`` — Enforces referential integrity at the SQLite
      layer so that cascades and SET NULL actions always fire, even if a
      query bypasses the ORM.
    """
    if not isinstance(dbapi_connection, _sqlite3.Connection):
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

# ---------------------------------------------------------------------------
# Logging / audit setup
# ---------------------------------------------------------------------------

app.logger.setLevel(logging.INFO)
try:
    _syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
    _syslog_handler.setFormatter(logging.Formatter("ssl-manager: %(message)s"))
    app.logger.addHandler(_syslog_handler)
except (OSError, AttributeError):
    # /dev/log unavailable (macOS, minimal Docker, etc.) — console logging only
    pass


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(db.Model, UserMixin):
    """Application user with role-based access control."""

    __tablename__ = "user"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False)
    email         = db.Column(db.String(256), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(16), default="user", nullable=False)  # superadmin | user
    active        = db.Column(db.Boolean, default=True, nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    # Flask-Login requires is_active; route it to our column
    @property
    def is_active(self):
        """Return whether this user account is active."""
        return self.active

    def set_password(self, password: str) -> None:
        """Hash and store the given password.

        Args:
            password: Plain-text password to hash and persist.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify a plain-text password against the stored hash.

        Args:
            password: Plain-text password to check.

        Returns:
            True if the password matches, False otherwise.
        """
        return check_password_hash(self.password_hash, password)

    @property
    def is_superadmin(self) -> bool:
        """Return True if the user has the superadmin role."""
        return self.role == "superadmin"


@login_manager.user_loader
def load_user(user_id: str):
    """Load a user by ID for Flask-Login session management.

    Args:
        user_id: String representation of the user's primary key.

    Returns:
        The User instance, or None if not found.
    """
    return User.query.get(int(user_id))


def _superadmin_count() -> int:
    """Return the number of active superadmin users.

    Returns:
        Count of active users with the superadmin role.
    """
    return User.query.filter_by(role="superadmin", active=True).count()


class Settings(db.Model):
    """Named profile of certificate-subject defaults used when generating new CSRs.

    Multiple profiles can exist; exactly one is marked as the default.  When
    only one profile exists it is used automatically without requiring the user
    to choose.
    """

    __tablename__ = "settings"

    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(128), nullable=False, default="Default")
    is_default = db.Column(db.Boolean, nullable=False, default=False)
    key_size   = db.Column(db.Integer, default=2048)
    country    = db.Column(db.String(2), default="US")
    state      = db.Column(db.String(128), default="")
    city       = db.Column(db.String(128), default="")
    org_name   = db.Column(db.String(256), default="")
    org_unit   = db.Column(db.String(256), default="")
    email      = db.Column(db.String(256), default="")


class CertChain(db.Model):
    """Named collection of intermediate certificates forming a trust chain."""

    __tablename__ = "cert_chain"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(512), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    intermediates = db.relationship(
        "IntermediateCert", backref="chain", lazy=True,
        cascade="all, delete-orphan",
    )
    certificates = db.relationship("Certificate", backref="chain", lazy=True)


class IntermediateCert(db.Model):
    """A single intermediate (or root) CA certificate belonging to a chain."""

    __tablename__ = "intermediate_cert"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    pem_data = db.Column(db.Text, nullable=False)
    order = db.Column(db.Integer, default=0)
    chain_id = db.Column(db.Integer, db.ForeignKey("cert_chain.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def parsed_cert(self):
        """Return the parsed x509 certificate object, or None on failure."""
        try:
            return x509.load_pem_x509_certificate(self.pem_data.encode())
        except Exception:
            return None

    @property
    def expiry_date(self):
        """Return the certificate's expiry as a timezone-aware datetime, or None."""
        cert = self.parsed_cert
        if cert is None:
            return None
        try:
            exp = cert.not_valid_after_utc
        except AttributeError:
            exp = cert.not_valid_after
            if exp is not None and exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
        return exp

    @property
    def subject(self):
        """Return the certificate's Common Name, falling back to the full subject string."""
        cert = self.parsed_cert
        if cert is None:
            return "Unknown"
        try:
            return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            return str(cert.subject)

    @property
    def is_root(self):
        """Return True if the certificate is self-signed (subject equals issuer)."""
        cert = self.parsed_cert
        if cert is None:
            return False
        try:
            return cert.subject == cert.issuer
        except Exception:
            return False


class Certificate(db.Model):
    """SSL/TLS certificate record, including key, CSR, signed cert, and metadata."""

    __tablename__ = "certificate"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(256), nullable=False)
    san_domains = db.Column(db.Text, default="[]")  # JSON list
    key_size = db.Column(db.Integer, default=2048)
    private_key_pem = db.Column(db.Text)
    csr_pem = db.Column(db.Text)
    signed_cert_pem = db.Column(db.Text)
    status = db.Column(db.String(32), default="pending_signing")
    expiry_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    country = db.Column(db.String(2), default="US")
    state = db.Column(db.String(128), default="")
    city = db.Column(db.String(128), default="")
    org_name = db.Column(db.String(256), default="")
    org_unit = db.Column(db.String(256), default="")
    email = db.Column(db.String(256), default="")
    chain_id   = db.Column(db.Integer, db.ForeignKey("cert_chain.id"),    nullable=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("settings.id",
                           ondelete="SET NULL"), nullable=True)
    profile    = db.relationship("Settings", foreign_keys=[profile_id], lazy="select")

    @property
    def san_list(self):
        """Return the Subject Alternative Names as a list of strings."""
        try:
            return json.loads(self.san_domains or "[]")
        except (json.JSONDecodeError, TypeError):
            return []

    @property
    def days_until_expiry(self):
        """Return the number of days until the certificate expires, or None if not set."""
        if self.expiry_date is None:
            return None
        now = datetime.now(timezone.utc)
        exp = self.expiry_date
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        delta = exp - now
        return delta.days

    @property
    def status_label(self):
        """Return a display-ready status string, marking active-but-expired certs as 'expired'."""
        if self.status == "active":
            days = self.days_until_expiry
            if days is not None and days < 0:
                return "expired"
            return "active"
        return self.status

    @property
    def safe_domain(self) -> str:
        """Domain name safe for use in filenames and keystore aliases.

        Replaces wildcard prefix and any characters illegal in filenames:
            *.example.com  →  star.example.com
            www.example.com → www.example.com
        """
        return normalize_alias(self.domain)


class AuditLog(db.Model):
    """Immutable record of a security-relevant action performed in the application."""

    __tablename__ = "audit_log"

    id            = db.Column(db.Integer, primary_key=True)
    timestamp     = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    username      = db.Column(db.String(64))
    user_id       = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    ip_address    = db.Column(db.String(45))
    action        = db.Column(db.String(64), nullable=False)
    resource_type = db.Column(db.String(32))
    resource_id   = db.Column(db.Integer)
    result        = db.Column(db.String(16))   # "success" | "failure"
    detail        = db.Column(db.String(512))


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def get_default_profile():
    """Return the active default Settings profile, creating one if none exist.

    Resolution order:
      1. The profile with ``is_default=True``.
      2. The only existing profile (when exactly one exists).
      3. A newly-created "Default" profile (first run).

    Returns:
        The Settings ORM instance to use as the current default.
    """
    default = Settings.query.filter_by(is_default=True).first()
    if default:
        return default
    profiles = Settings.query.all()
    if len(profiles) == 1:
        # Auto-promote the sole profile so future queries are fast.
        profiles[0].is_default = True
        db.session.commit()
        return profiles[0]
    if not profiles:
        profile = Settings(name="Default", is_default=True, key_size=2048)
        db.session.add(profile)
        db.session.commit()
        return profile
    # Multiple profiles, none marked default — promote the first one.
    profiles[0].is_default = True
    db.session.commit()
    return profiles[0]


# Keep the old name as an alias so any call sites missed by this refactor
# still work correctly.
get_settings = get_default_profile


def generate_key_and_csr(domain, san_list, key_size, country, state, city, org_name, org_unit, email):
    """Generate RSA private key and CSR. Returns (private_key_pem, csr_pem) as strings."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    name_attrs = []
    if country:
        name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2]))
    if state:
        name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if city:
        name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, city))
    if org_name:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name))
    if org_unit:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit))
    if email:
        name_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, domain))

    subject = x509.Name(name_attrs)

    # Build SAN list
    san_names = [x509.DNSName(domain)]
    for san in san_list:
        san = san.strip()
        if san and san != domain:
            san_names.append(x509.DNSName(san))

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .sign(key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return private_key_pem, csr_pem


def parse_cert_expiry(cert_pem):
    """Parse x509 cert PEM and return expiry datetime (timezone-aware UTC)."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    try:
        exp = cert.not_valid_after_utc
    except AttributeError:
        exp = cert.not_valid_after
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
    return exp


def normalize_alias(domain: str) -> str:
    """Convert a domain name to a safe alias string.

    Examples:
        *.ideocentric.com  → star.ideocentric.com
        www.example.com    → www.example.com
    """
    alias = domain.replace("*.", "star.").replace("*", "star")
    alias = re.sub(r"[^a-zA-Z0-9.\-]", "-", alias)
    alias = alias.strip("-")
    return alias or "certificate"


def create_pkcs12(cert_pem, key_pem, intermediates_pem_list, password, name=None):
    """Create PKCS#12 bundle. Returns bytes."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)

    cas = []
    for pem in intermediates_pem_list:
        if pem and pem.strip():
            try:
                cas.append(x509.load_pem_x509_certificate(pem.encode()))
            except Exception:
                pass

    if isinstance(password, str):
        password = password.encode()

    if isinstance(name, str):
        name = name.encode()

    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=name,
        key=key,
        cert=cert,
        cas=cas if cas else None,
        encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption(),
    )
    return p12_bytes


def create_jks(cert_pem, key_pem, intermediates_pem_list, store_password, alias="certificate"):
    """Create JKS keystore. Returns bytes."""
    import jks

    # Convert private key to PKCS8 DER
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    key_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Convert certs to DER
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    cert_chain_der = [cert_der]
    for pem in intermediates_pem_list:
        if pem and pem.strip():
            try:
                ic = x509.load_pem_x509_certificate(pem.encode())
                cert_chain_der.append(ic.public_bytes(serialization.Encoding.DER))
            except Exception:
                pass

    entry = jks.PrivateKeyEntry.new(alias, cert_chain_der, key_der)

    if isinstance(store_password, bytes):
        store_password = store_password.decode()

    keystore = jks.KeyStore.new("jks", [entry])

    with tempfile.NamedTemporaryFile(suffix=".jks", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        keystore.save(tmp_path, store_password)
        with open(tmp_path, "rb") as f:
            jks_bytes = f.read()
    finally:
        os.unlink(tmp_path)

    return jks_bytes


def create_p7b(cert_pem_list):
    """Create PKCS#7 P7B bundle from list of PEM strings. Returns bytes or None."""
    try:
        # Write all certs to a temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as tmp_in:
            for pem in cert_pem_list:
                if pem and pem.strip():
                    tmp_in.write(pem)
                    if not pem.endswith("\n"):
                        tmp_in.write("\n")
            tmp_in_path = tmp_in.name

        with tempfile.NamedTemporaryFile(suffix=".p7b", delete=False) as tmp_out:
            tmp_out_path = tmp_out.name

        result = subprocess.run(
            ["openssl", "crl2pkcs7", "-nocrl", "-certfile", tmp_in_path, "-out", tmp_out_path, "-outform", "DER"],
            capture_output=True,
            timeout=15,
        )

        if result.returncode != 0:
            return None

        with open(tmp_out_path, "rb") as f:
            p7b_bytes = f.read()

        return p7b_bytes
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return None
    finally:
        try:
            os.unlink(tmp_in_path)
        except Exception:
            pass
        try:
            os.unlink(tmp_out_path)
        except Exception:
            pass


def create_components_zip(domain, cert_pem, key_pem, intermediates_pem_list, csr_pem=None):
    """Create a ZIP of component PEM files. Returns BytesIO.

    Contents:
      private_key.pem      — RSA private key only
      certificate.pem      — signed certificate only
      chain.pem            — intermediates concatenated (no cert, no key)
                             use as Apache SSLCACertificateFile
      fullchain.pem        — signed cert + intermediates (no private key)
                             use as nginx ssl_certificate or Apache SSLCertificateFile
      certificate.csr      — original CSR (if available)
    """
    active_intermediates = [p for p in intermediates_pem_list if p and p.strip()]

    buf = BytesIO()
    with ZipFile(buf, "w") as zf:
        zf.writestr("private_key.pem", key_pem)
        zf.writestr("certificate.pem", cert_pem)

        if active_intermediates:
            zf.writestr(
                "chain.pem",
                "\n".join(p.strip() for p in active_intermediates) + "\n",
            )

        fullchain_parts = [cert_pem] + active_intermediates
        zf.writestr("fullchain.pem", "\n".join(p.strip() for p in fullchain_parts) + "\n")

        if csr_pem:
            zf.writestr("certificate.csr", csr_pem)

    buf.seek(0)
    return buf


def get_intermediates_ordered():
    """Return all intermediate certs sorted by order ascending (legacy helper)."""
    return IntermediateCert.query.order_by(IntermediateCert.order.asc()).all()


def get_chain_intermediates(chain_id):
    """Return intermediate certs for a specific chain, sorted by order."""
    if chain_id is None:
        return []
    return IntermediateCert.query.filter_by(chain_id=chain_id).order_by(IntermediateCert.order.asc()).all()


def parse_pem_bundle(text):
    """Split a concatenated PEM bundle into a list of individual PEM strings.

    Returns a list of strings, each containing one PEM certificate block.
    Raises ValueError if no valid certificates are found.
    """
    pattern = re.compile(
        r"(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)",
        re.MULTILINE,
    )
    certs = pattern.findall(text)
    if not certs:
        raise ValueError("No PEM certificate blocks found in the provided text.")
    return [c.strip() for c in certs]


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------

def _get_csrf_token():
    """Return the session CSRF token, generating one if it doesn't exist."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = _get_csrf_token


def _static_url(filename):
    """Return a cache-busting URL for a static file using its mtime as a version.

    Appends ``?v=<mtime>`` so browsers fetch a fresh copy whenever the file
    changes on disk, without requiring users to clear their cache.

    Args:
        filename: Path relative to the static folder (e.g. ``'favicon.ico'``).

    Returns:
        A URL string with a ``v`` query parameter derived from the file's
        modification time, or ``0`` if the file cannot be found.
    """
    import os
    path = os.path.join(app.static_folder, filename)
    try:
        v = str(int(os.path.getmtime(path)))
    except OSError:
        v = "0"
    return url_for("static", filename=filename, v=v)


app.jinja_env.globals["static_url"] = _static_url


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
_COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def _clean(value, max_len=256):
    """Strip whitespace and enforce a maximum length."""
    return (value or "").strip()[:max_len]


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


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------

def _get_client_ip():
    """Return the client IP; trusts X-Real-IP set by the nginx proxy."""
    return request.headers.get("X-Real-IP") or request.remote_addr or "unknown"


def _audit(action, resource_type=None, resource_id=None, result="success", detail=None):
    """Persist an audit event to the database and emit it via the system logger."""
    username = None
    uid = None
    try:
        if current_user and current_user.is_authenticated:
            username = current_user.username
            uid = current_user.id
    except Exception:
        pass

    ip = _get_client_ip()

    entry = AuditLog(
        username=username,
        user_id=uid,
        ip_address=ip,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        detail=(detail or "")[:512],
    )
    try:
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

    log_parts = [f"action={action}", f"result={result}", f"user={username!r}", f"ip={ip}"]
    if resource_type:
        log_parts.append(f"resource={resource_type}:{resource_id}")
    if detail:
        log_parts.append(f"detail={detail!r}")
    msg = " ".join(log_parts)
    if result == "failure":
        app.logger.warning(msg)
    else:
        app.logger.info(msg)


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------

def superadmin_required(f):
    """Decorator that restricts a route to authenticated superadmin users.

    Args:
        f: The view function to protect.

    Returns:
        The wrapped view function that enforces superadmin access.
    """
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        """Enforce superadmin role before delegating to the wrapped view."""
        if not current_user.is_superadmin:
            flash("Superadmin access required.", "error")
            return redirect(url_for("certificates"))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated


# ---------------------------------------------------------------------------
# Before-request hook
# ---------------------------------------------------------------------------

@app.before_request
def _security_checks():
    """First-run redirect and CSRF enforcement."""
    if request.endpoint == "static":
        return

    # Redirect to setup when no users exist
    if request.endpoint not in (None, "setup", "login", "logout"):
        if User.query.count() == 0:
            return redirect(url_for("setup"))

    # CSRF enforcement on all state-changing requests (skipped in test mode)
    if not app.testing and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        session_token = session.get("csrf_token")
        submitted = (
            request.headers.get("X-CSRFToken", "")
            if request.is_json
            else request.form.get("csrf_token", "")
        )
        if not session_token or not submitted or not secrets.compare_digest(session_token, submitted):
            _audit("csrf_failure", result="failure", detail=f"endpoint={request.endpoint} method={request.method}")
            if request.is_json:
                abort(403)
            flash("Your request could not be verified. Please try again.", "error")
            return redirect(request.referrer or url_for("certificates"))


@app.after_request
def _set_security_headers(response):
    """Apply security-related HTTP response headers."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "font-src 'self' cdn.jsdelivr.net data:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    """GET / — Redirect the root URL to the certificates list."""
    return redirect(url_for("certificates"))


# ---- Auth routes ----

@app.route("/setup", methods=["GET", "POST"])
def setup():
    """First-run setup — only accessible when no users exist."""
    if User.query.count() > 0:
        return redirect(url_for("login"))
    if request.method == "POST":
        username = _clean(request.form.get("username", ""), 64)
        email    = _clean(request.form.get("email", ""), 256)
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        error = (
            _validate_username(username)
            or _validate_email(email) or (None if email else "Email is required.")
            or (None if len(password) >= 8 else "Password must be at least 8 characters.")
            or (None if password == confirm else "Passwords do not match.")
        )
        if error:
            _audit("setup_failed", result="failure", detail=error)
            flash(error, "error")
            return render_template("setup.html")
        user = User(username=username, email=email, role="superadmin")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        _audit("setup", "user", user.id, "success", f"superadmin created: {username}")
        flash(f"Welcome, {username}! Your admin account has been created.", "success")
        return redirect(url_for("certificates"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """GET/POST /login — Display the login form and authenticate the user."""
    if current_user.is_authenticated:
        return redirect(url_for("certificates"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            _audit("login_failed", "user", None, "failure", f"username={username!r}")
            flash("Invalid username or password.", "error")
            return render_template("login.html")
        if not user.active:
            _audit("login_failed", "user", user.id, "failure", "account deactivated")
            flash("This account has been deactivated.", "error")
            return render_template("login.html")
        login_user(user, remember=remember)
        _audit("login", "user", user.id, "success")
        next_page = request.args.get("next")
        return redirect(next_page or url_for("certificates"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """GET /logout — Log out the current user and redirect to the login page."""
    _audit("logout", "user", current_user.id, "success")
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ---- User management routes ----

@app.route("/users")
@superadmin_required
def users():
    """GET /users — List all users (superadmin only)."""
    all_users = User.query.order_by(User.created_at.asc()).all()
    return render_template("users.html", users=all_users)


@app.route("/users/new", methods=["GET", "POST"])
@superadmin_required
def user_new():
    """GET/POST /users/new — Display and process the new-user creation form (superadmin only)."""
    if request.method == "POST":
        username = _clean(request.form.get("username", ""), 64)
        email    = _clean(request.form.get("email", ""), 256)
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        role     = request.form.get("role", "user")
        if role not in ("superadmin", "user"):
            role = "user"
        error = (
            _validate_username(username)
            or _validate_email(email) or (None if email else "Email is required.")
            or (None if len(password) >= 8 else "Password must be at least 8 characters.")
            or (None if password == confirm else "Passwords do not match.")
            or (None if not User.query.filter_by(username=username).first() else f"Username '{username}' is already taken.")
            or (None if not User.query.filter_by(email=email).first() else f"Email '{email}' is already registered.")
        )
        if error:
            flash(error, "error")
            return render_template("user_form.html", user=None, roles=["superadmin", "user"])
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        _audit("user_created", "user", user.id, "success", f"username={username!r} role={role}")
        flash(f"User '{username}' created.", "success")
        return redirect(url_for("users"))
    return render_template("user_form.html", user=None, roles=["superadmin", "user"])


@app.route("/users/<int:user_id>/edit")
@superadmin_required
def user_edit(user_id):
    """GET /users/<user_id>/edit — Show the edit form for an existing user (superadmin only)."""
    user = User.query.get_or_404(user_id)
    return render_template("user_form.html", user=user, roles=["superadmin", "user"])


@app.route("/users/<int:user_id>/update", methods=["POST"])
@superadmin_required
def user_update(user_id):
    """POST /users/<user_id>/update — Save edits to an existing user (superadmin only)."""
    user = User.query.get_or_404(user_id)
    username = _clean(request.form.get("username", ""), 64)
    email    = _clean(request.form.get("email", ""), 256)
    role     = request.form.get("role", "user")
    active   = request.form.get("active") == "1"
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")
    if role not in ("superadmin", "user"):
        role = "user"
    dup_user  = User.query.filter(User.username == username, User.id != user_id).first()
    dup_email = User.query.filter(User.email == email, User.id != user_id).first()
    error = (
        _validate_username(username)
        or _validate_email(email) or (None if email else "Email is required.")
        or (None if not dup_user  else f"Username '{username}' is already taken.")
        or (None if not dup_email else f"Email '{email}' is already registered.")
    )
    # Prevent removing the last active superadmin
    if not error and (role != "superadmin" or not active):
        if user.role == "superadmin" and user.active:
            if _superadmin_count() <= 1:
                error = "Cannot demote or deactivate the last active superadmin."
    if error:
        flash(error, "error")
        return render_template("user_form.html", user=user, roles=["superadmin", "user"])
    if password:
        if len(password) < 8:
            flash("New password must be at least 8 characters.", "error")
            return render_template("user_form.html", user=user, roles=["superadmin", "user"])
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("user_form.html", user=user, roles=["superadmin", "user"])
        user.set_password(password)
    user.username = username
    user.email    = email
    user.role     = role
    user.active   = active
    db.session.commit()
    _audit("user_updated", "user", user_id, "success", f"username={username!r} role={role} active={active}")
    flash(f"User '{username}' updated.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@superadmin_required
def user_delete(user_id):
    """POST /users/<user_id>/delete — Delete a user account (superadmin only)."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("users"))
    if user.role == "superadmin" and _superadmin_count() <= 1:
        flash("Cannot delete the last superadmin.", "error")
        return redirect(url_for("users"))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    _audit("user_deleted", "user", user_id, "success", f"username={username!r}")
    flash(f"User '{username}' deleted.", "success")
    return redirect(url_for("users"))


# ---- Certificates ----

@app.route("/certificates")
@login_required
def certificates():
    """GET /certificates — List all certificates ordered by creation date descending."""
    certs = Certificate.query.order_by(Certificate.created_at.desc()).all()
    return render_template("certificates.html", certs=certs)


@app.route("/certificates/new", methods=["GET", "POST"])
@login_required
def certificate_new():
    """GET/POST /certificates/new — Display and process the new-certificate form, generating a key and CSR."""
    all_profiles = Settings.query.order_by(Settings.name.asc()).all()
    default_profile = get_default_profile()
    chains = CertChain.query.order_by(CertChain.name.asc()).all()
    if request.method == "POST":
        # Resolve which profile was chosen (falls back to default).
        try:
            chosen_profile_id = int(request.form.get("profile_id", ""))
            chosen_profile = Settings.query.get(chosen_profile_id) or default_profile
        except (ValueError, TypeError):
            chosen_profile = default_profile

        domain = _clean(request.form.get("domain", ""), 253)
        san_raw = request.form.get("san_domains", "")
        country = _clean(request.form.get("country", chosen_profile.country or ""), 2).upper()
        state    = _clean(request.form.get("state",    chosen_profile.state    or ""), 128)
        city     = _clean(request.form.get("city",     chosen_profile.city     or ""), 128)
        org_name = _clean(request.form.get("org_name", chosen_profile.org_name or ""), 256)
        org_unit = _clean(request.form.get("org_unit", chosen_profile.org_unit or ""), 256)
        email    = _clean(request.form.get("email",    chosen_profile.email    or ""), 256)

        san_list, san_err = _validate_san_list(san_raw)
        error = (
            _validate_domain(domain)
            or san_err
            or _validate_country(country)
            or _validate_email(email)
        )
        if error:
            flash(error, "error")
            return render_template("cert_new.html", profiles=all_profiles,
                                   default_profile=default_profile, chains=chains)

        try:
            key_size = int(request.form.get("key_size", chosen_profile.key_size))
        except (ValueError, TypeError):
            key_size = 2048
        if key_size not in (2048, 4096):
            key_size = 2048

        chain_id_raw = request.form.get("chain_id", "")
        try:
            chain_id = int(chain_id_raw) if chain_id_raw else None
        except ValueError:
            chain_id = None

        try:
            private_key_pem, csr_pem = generate_key_and_csr(
                domain, san_list, key_size, country, state, city, org_name, org_unit, email
            )
        except Exception as e:
            flash(f"Error generating key/CSR: {e}", "error")
            return render_template("cert_new.html", profiles=all_profiles,
                                   default_profile=default_profile, chains=chains)

        cert = Certificate(
            domain=domain,
            san_domains=json.dumps(san_list),
            key_size=key_size,
            private_key_pem=private_key_pem,
            csr_pem=csr_pem,
            status="pending_signing",
            country=country,
            state=state,
            city=city,
            org_name=org_name,
            org_unit=org_unit,
            email=email,
            chain_id=chain_id,
            profile_id=chosen_profile.id if chosen_profile else None,
        )
        db.session.add(cert)
        db.session.commit()
        _audit("certificate_created", "certificate", cert.id, "success", f"domain={domain!r}")
        flash(f"RSA key and CSR generated for {domain}.", "success")
        return redirect(url_for("certificate_detail", cert_id=cert.id))

    return render_template("cert_new.html", profiles=all_profiles,
                           default_profile=default_profile, chains=chains)


@app.route("/certificates/<int:cert_id>/renew")
@login_required
def certificate_renew(cert_id):
    """GET /certificates/<cert_id>/renew — Show the new-certificate form pre-populated for renewal."""
    cert = Certificate.query.get_or_404(cert_id)
    all_profiles = Settings.query.order_by(Settings.name.asc()).all()
    default_profile = get_default_profile()
    chains = CertChain.query.order_by(CertChain.name.asc()).all()
    return render_template("cert_new.html", profiles=all_profiles,
                           default_profile=default_profile, renew_from=cert, chains=chains)


@app.route("/certificates/<int:cert_id>")
@login_required
def certificate_detail(cert_id):
    """GET /certificates/<cert_id> — Show full details for a single certificate."""
    cert = Certificate.query.get_or_404(cert_id)
    intermediates = get_chain_intermediates(cert.chain_id)
    chains = CertChain.query.order_by(CertChain.name.asc()).all()
    return render_template("cert_detail.html", cert=cert, intermediates=intermediates, chains=chains)


@app.route("/certificates/<int:cert_id>/set-chain", methods=["POST"])
@login_required
def certificate_set_chain(cert_id):
    """POST /certificates/<cert_id>/set-chain — Assign or clear the certificate's trust chain."""
    cert = Certificate.query.get_or_404(cert_id)
    chain_id_raw = request.form.get("chain_id", "")
    try:
        cert.chain_id = int(chain_id_raw) if chain_id_raw else None
    except ValueError:
        cert.chain_id = None
    db.session.commit()
    chain_name = cert.chain.name if cert.chain else "None"
    flash(f"Certificate chain updated to: {chain_name}.", "success")
    return redirect(url_for("certificate_detail", cert_id=cert_id))


@app.route("/certificates/<int:cert_id>/upload", methods=["POST"])
@login_required
def certificate_upload(cert_id):
    """POST /certificates/<cert_id>/upload — Upload a signed certificate PEM (file or pasted text)."""
    cert = Certificate.query.get_or_404(cert_id)

    # Prefer file upload over pasted text
    uploaded = request.files.get("cert_file")
    if uploaded and uploaded.filename:
        try:
            signed_pem = uploaded.read().decode("utf-8", errors="replace").strip()
        except Exception as e:
            flash(f"Could not read uploaded file: {e}", "error")
            return redirect(url_for("certificate_detail", cert_id=cert_id))
    else:
        signed_pem = request.form.get("signed_cert_pem", "").strip()

    if not signed_pem:
        flash("No certificate PEM provided.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    try:
        expiry = parse_cert_expiry(signed_pem)
    except Exception as e:
        flash(f"Invalid certificate PEM: {e}", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    cert.signed_cert_pem = signed_pem
    cert.status = "active"
    # Store as naive UTC for SQLite compatibility
    if expiry.tzinfo is not None:
        expiry = expiry.replace(tzinfo=None)
    cert.expiry_date = expiry
    db.session.commit()
    _audit("certificate_signed", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    flash("Signed certificate uploaded successfully.", "success")
    return redirect(url_for("certificate_detail", cert_id=cert_id))


@app.route("/certificates/<int:cert_id>/delete", methods=["POST"])
@login_required
def certificate_delete(cert_id):
    """POST /certificates/<cert_id>/delete — Permanently delete a certificate record."""
    cert = Certificate.query.get_or_404(cert_id)
    domain = cert.domain
    db.session.delete(cert)
    db.session.commit()
    _audit("certificate_deleted", "certificate", cert_id, "success", f"domain={domain!r}")
    flash(f"Certificate for {domain} deleted.", "success")
    return redirect(url_for("certificates"))


# ---- Certificate Downloads ----

@app.route("/certificates/<int:cert_id>/download/csr")
@login_required
def download_csr(cert_id):
    """GET /certificates/<cert_id>/download/csr — Download the certificate's CSR as a PEM file."""
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.csr_pem:
        flash("No CSR available.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))
    buf = BytesIO(cert.csr_pem.encode())
    _audit("download_csr", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(
        buf,
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name=f"{cert.safe_domain}.csr",
    )


@app.route("/certificates/<int:cert_id>/download/fullchain")
@login_required
def download_fullchain(cert_id):
    """GET /certificates/<cert_id>/download/fullchain — Download private key + signed cert + intermediates as a PEM bundle."""
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    intermediates = get_chain_intermediates(cert.chain_id)
    parts = [cert.private_key_pem, cert.signed_cert_pem]
    for ic in intermediates:
        parts.append(ic.pem_data)

    fullchain = "\n".join(p.strip() for p in parts if p and p.strip()) + "\n"
    buf = BytesIO(fullchain.encode())
    _audit("download_fullchain", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(
        buf,
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name=f"{cert.safe_domain}-fullchain.pem",
    )


@app.route("/certificates/<int:cert_id>/download/components")
@login_required
def download_components(cert_id):
    """GET /certificates/<cert_id>/download/components — Download a ZIP containing individual PEM component files."""
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    intermediates = get_chain_intermediates(cert.chain_id)
    intermediates_pems = [ic.pem_data for ic in intermediates]

    buf = create_components_zip(
        cert.domain,
        cert.signed_cert_pem,
        cert.private_key_pem,
        intermediates_pems,
        csr_pem=cert.csr_pem,
    )
    _audit("download_components", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{cert.safe_domain}-certs.zip",
    )


@app.route("/certificates/<int:cert_id>/download/pkcs12", methods=["POST"])
@login_required
def download_pkcs12(cert_id):
    """POST /certificates/<cert_id>/download/pkcs12 — Generate and download a PKCS#12 (.p12) bundle."""
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    password      = request.form.get("password", "")
    friendly_name = request.form.get("friendly_name", "").strip() or normalize_alias(cert.domain)

    intermediates = get_chain_intermediates(cert.chain_id)
    intermediates_pems = [ic.pem_data for ic in intermediates]

    try:
        p12_bytes = create_pkcs12(cert.signed_cert_pem, cert.private_key_pem, intermediates_pems, password,
                                   name=friendly_name)
    except Exception as e:
        flash(f"Error creating PKCS#12: {e}", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    buf = BytesIO(p12_bytes)
    _audit("download_pkcs12", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(
        buf,
        mimetype="application/x-pkcs12",
        as_attachment=True,
        download_name=f"{cert.safe_domain}.p12",
    )


@app.route("/certificates/<int:cert_id>/download/jks", methods=["POST"])
@login_required
def download_jks(cert_id):
    """POST /certificates/<cert_id>/download/jks — Generate and download a Java KeyStore (.jks) file."""
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    password = request.form.get("password", "changeit")
    alias = request.form.get("alias", "").strip() or normalize_alias(cert.domain)

    intermediates = get_chain_intermediates(cert.chain_id)
    intermediates_pems = [ic.pem_data for ic in intermediates]

    try:
        jks_bytes = create_jks(cert.signed_cert_pem, cert.private_key_pem, intermediates_pems, password, alias=alias)
    except Exception as e:
        flash(f"Error creating JKS: {e}", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    buf = BytesIO(jks_bytes)
    _audit("download_jks", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(
        buf,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"{cert.safe_domain}.jks",
    )


@app.route("/certificates/<int:cert_id>/download/p7b")
@login_required
def download_p7b(cert_id):
    """GET /certificates/<cert_id>/download/p7b — Generate and download a PKCS#7 (.p7b) bundle via OpenSSL."""
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    intermediates = get_chain_intermediates(cert.chain_id)
    pem_list = [cert.signed_cert_pem] + [ic.pem_data for ic in intermediates]

    p7b_bytes = create_p7b(pem_list)
    if p7b_bytes is None:
        flash("P7B creation failed. Ensure OpenSSL is installed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    buf = BytesIO(p7b_bytes)
    _audit("download_p7b", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(
        buf,
        mimetype="application/x-pkcs7-certificates",
        as_attachment=True,
        download_name=f"{cert.safe_domain}.p7b",
    )


@app.route("/certificates/<int:cert_id>/download/der")
@login_required
def download_der(cert_id):
    """GET /certificates/<cert_id>/download/der — Download the signed certificate in DER (binary) format."""
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    x509_cert = x509.load_pem_x509_certificate(cert.signed_cert_pem.encode())
    der_bytes = x509_cert.public_bytes(serialization.Encoding.DER)
    buf = BytesIO(der_bytes)
    _audit("download_der", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(
        buf,
        mimetype="application/x-x509-ca-cert",
        as_attachment=True,
        download_name=f"{cert.safe_domain}.der",
    )


# ---- Settings / Profiles ----

@app.route("/settings")
@login_required
def settings():
    """GET /settings — Redirect to the profiles list (backwards-compat URL)."""
    return redirect(url_for("profiles"))


@app.route("/profiles")
@login_required
def profiles():
    """GET /profiles — List all certificate-subject profiles."""
    all_profiles = Settings.query.order_by(Settings.name.asc()).all()
    return render_template("profiles.html", profiles=all_profiles)


def _save_profile_from_form(profile):
    """Validate and apply POST form data to a Settings profile object.

    Args:
        profile: The Settings ORM instance to update in-place.

    Returns:
        An error string if validation fails, or ``None`` on success.
    """
    name    = _clean(request.form.get("name", ""), 128)
    country = _clean(request.form.get("country", ""), 2).upper()
    email   = _clean(request.form.get("email", ""), 256)

    if not name:
        return "Profile name is required."

    # Name must be unique (excluding the current profile when editing)
    existing = Settings.query.filter(Settings.name == name, Settings.id != profile.id).first()
    if existing:
        return f"A profile named \"{name}\" already exists."

    error = _validate_country(country) or _validate_email(email)
    if error:
        return error

    try:
        key_size = int(request.form.get("key_size", 2048))
    except (ValueError, TypeError):
        key_size = 2048

    profile.name     = name
    profile.key_size = key_size if key_size in (2048, 4096) else 2048
    profile.country  = country
    profile.state    = _clean(request.form.get("state",    ""), 128)
    profile.city     = _clean(request.form.get("city",     ""), 128)
    profile.org_name = _clean(request.form.get("org_name", ""), 256)
    profile.org_unit = _clean(request.form.get("org_unit", ""), 256)
    profile.email    = email
    return None


@app.route("/profiles/new", methods=["GET", "POST"])
@login_required
def profile_new():
    """GET/POST /profiles/new — Create a new certificate-subject profile."""
    profile = Settings(name="", key_size=2048)
    if request.method == "POST":
        err = _save_profile_from_form(profile)
        if err:
            flash(err, "error")
            return render_template("profile_form.html", profile=profile, action="new")
        # First profile automatically becomes the default
        if Settings.query.count() == 0:
            profile.is_default = True
        db.session.add(profile)
        db.session.commit()
        _audit("profile_created", "settings", profile.id, "success", f"name={profile.name!r}")
        flash(f"Profile \"{profile.name}\" created.", "success")
        return redirect(url_for("profiles"))
    return render_template("profile_form.html", profile=profile, action="new")


@app.route("/profiles/<int:profile_id>/edit", methods=["GET", "POST"])
@login_required
def profile_edit(profile_id):
    """GET/POST /profiles/<profile_id>/edit — Edit an existing certificate-subject profile."""
    profile = Settings.query.get_or_404(profile_id)
    if request.method == "POST":
        err = _save_profile_from_form(profile)
        if err:
            flash(err, "error")
            return render_template("profile_form.html", profile=profile, action="edit")
        db.session.commit()
        _audit("profile_updated", "settings", profile.id, "success", f"name={profile.name!r}")
        flash(f"Profile \"{profile.name}\" saved.", "success")
        return redirect(url_for("profiles"))
    return render_template("profile_form.html", profile=profile, action="edit")


@app.route("/profiles/<int:profile_id>/delete", methods=["POST"])
@login_required
def profile_delete(profile_id):
    """POST /profiles/<profile_id>/delete — Delete a profile; blocked when only one remains."""
    profile = Settings.query.get_or_404(profile_id)
    if Settings.query.count() <= 1:
        flash("Cannot delete the last profile.", "error")
        return redirect(url_for("profiles"))
    name = profile.name
    was_default = profile.is_default
    db.session.delete(profile)
    db.session.flush()
    if was_default:
        # Promote the first remaining profile
        new_default = Settings.query.order_by(Settings.name.asc()).first()
        if new_default:
            new_default.is_default = True
    db.session.commit()
    _audit("profile_deleted", "settings", profile_id, "success", f"name={name!r}")
    flash(f"Profile \"{name}\" deleted.", "success")
    return redirect(url_for("profiles"))


@app.route("/profiles/<int:profile_id>/set-default", methods=["POST"])
@login_required
def profile_set_default(profile_id):
    """POST /profiles/<profile_id>/set-default — Promote a profile to the default."""
    profile = Settings.query.get_or_404(profile_id)
    Settings.query.filter_by(is_default=True).update({"is_default": False})
    profile.is_default = True
    db.session.commit()
    _audit("profile_set_default", "settings", profile.id, "success", f"name={profile.name!r}")
    flash(f"Profile \"{profile.name}\" is now the default.", "success")
    return redirect(url_for("profiles"))


# ---- Certificate Chains ----

@app.route("/intermediates")
@login_required
def intermediates():
    """GET /intermediates — Legacy redirect to the /chains page."""
    return redirect(url_for("chains"))


@app.route("/chains")
@login_required
def chains():
    """GET /chains — List all certificate chains with their associated certificate counts."""
    all_chains = CertChain.query.order_by(CertChain.created_at.asc()).all()
    chain_cert_counts = {c.id: Certificate.query.filter_by(chain_id=c.id).count() for c in all_chains}
    return render_template("chains.html", chains=all_chains, chain_cert_counts=chain_cert_counts)


@app.route("/chains/new", methods=["GET", "POST"])
@login_required
def chain_new():
    """GET/POST /chains/new — Display and process the new-chain creation form."""
    if request.method == "POST":
        name        = _clean(request.form.get("name", ""), 256)
        description = _clean(request.form.get("description", ""), 512)
        if not name:
            flash("Chain name is required.", "error")
            return render_template("chain_form.html", chain=None)
        if CertChain.query.filter_by(name=name).first():
            flash(f"A chain named '{name}' already exists.", "error")
            return render_template("chain_form.html", chain=None)
        chain = CertChain(name=name, description=description)
        db.session.add(chain)
        db.session.commit()
        _audit("chain_created", "chain", chain.id, "success", f"name={name!r}")
        flash(f"Chain '{name}' created.", "success")
        return redirect(url_for("chain_detail", chain_id=chain.id))
    return render_template("chain_form.html", chain=None)


@app.route("/chains/<int:chain_id>")
@login_required
def chain_detail(chain_id):
    """GET /chains/<chain_id> — Show the details and intermediates for a specific chain."""
    chain = CertChain.query.get_or_404(chain_id)
    intermediates = sorted(chain.intermediates, key=lambda ic: ic.order)
    cert_count = Certificate.query.filter_by(chain_id=chain_id).count()
    return render_template("chain_detail.html", chain=chain, intermediates=intermediates, cert_count=cert_count)


@app.route("/chains/<int:chain_id>/edit")
@login_required
def chain_edit(chain_id):
    """GET /chains/<chain_id>/edit — Show the edit form for an existing chain."""
    chain = CertChain.query.get_or_404(chain_id)
    return render_template("chain_form.html", chain=chain)


@app.route("/chains/<int:chain_id>/update", methods=["POST"])
@login_required
def chain_update(chain_id):
    """POST /chains/<chain_id>/update — Save name and description changes to a chain."""
    chain = CertChain.query.get_or_404(chain_id)
    name        = _clean(request.form.get("name", ""), 256)
    description = _clean(request.form.get("description", ""), 512)
    if not name:
        flash("Chain name is required.", "error")
        return render_template("chain_form.html", chain=chain)
    dup = CertChain.query.filter(CertChain.name == name, CertChain.id != chain_id).first()
    if dup:
        flash(f"A chain named '{name}' already exists.", "error")
        return render_template("chain_form.html", chain=chain)
    chain.name = name
    chain.description = description
    db.session.commit()
    _audit("chain_updated", "chain", chain_id, "success", f"name={name!r}")
    flash(f"Chain '{name}' updated.", "success")
    return redirect(url_for("chain_detail", chain_id=chain_id))


@app.route("/chains/<int:chain_id>/delete", methods=["POST"])
@login_required
def chain_delete(chain_id):
    """POST /chains/<chain_id>/delete — Delete a chain and unlink any assigned certificates."""
    chain = CertChain.query.get_or_404(chain_id)
    Certificate.query.filter_by(chain_id=chain_id).update({"chain_id": None})
    name = chain.name
    db.session.delete(chain)
    db.session.commit()
    _audit("chain_deleted", "chain", chain_id, "success", f"name={name!r}")
    flash(f"Chain '{name}' deleted. Assigned certificates have been unlinked.", "success")
    return redirect(url_for("chains"))


@app.route("/chains/<int:chain_id>/intermediates/new")
@login_required
def chain_intermediate_form_new(chain_id):
    """GET /chains/<chain_id>/intermediates/new — Show the form to add a new intermediate certificate."""
    chain = CertChain.query.get_or_404(chain_id)
    return render_template("intermediate_form.html", cert=None, chain=chain,
                           action=url_for("chain_intermediate_new", chain_id=chain_id))


@app.route("/chains/<int:chain_id>/intermediates", methods=["POST"])
@login_required
def chain_intermediate_new(chain_id):
    """POST /chains/<chain_id>/intermediates — Validate and save a new intermediate certificate to a chain."""
    chain = CertChain.query.get_or_404(chain_id)
    name     = _clean(request.form.get("name", ""), 256)
    pem_data = (request.form.get("pem_data", "") or "").strip()
    try:
        order = max(0, int(request.form.get("order", 0)))
    except (ValueError, TypeError):
        order = 0
    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("chain_intermediate_form_new", chain_id=chain_id))
    if not pem_data:
        flash("PEM data is required.", "error")
        return redirect(url_for("chain_intermediate_form_new", chain_id=chain_id))
    try:
        x509.load_pem_x509_certificate(pem_data.encode())
    except Exception as e:
        flash(f"Invalid PEM certificate data: {e}", "error")
        return redirect(url_for("chain_intermediate_form_new", chain_id=chain_id))
    ic = IntermediateCert(name=name, pem_data=pem_data, order=order, chain_id=chain_id)
    db.session.add(ic)
    db.session.commit()
    _audit("intermediate_created", "intermediate", ic.id, "success", f"name={name!r} chain_id={chain_id}")
    flash(f"Certificate '{name}' added.", "success")
    return redirect(url_for("chain_detail", chain_id=chain_id))


@app.route("/chains/<int:chain_id>/intermediates/<int:ic_id>/edit")
@login_required
def chain_intermediate_edit(chain_id, ic_id):
    """GET /chains/<chain_id>/intermediates/<ic_id>/edit — Show the edit form for an intermediate certificate."""
    chain = CertChain.query.get_or_404(chain_id)
    ic = IntermediateCert.query.get_or_404(ic_id)
    return render_template("intermediate_form.html", cert=ic, chain=chain,
                           action=url_for("chain_intermediate_update", chain_id=chain_id, ic_id=ic_id))


@app.route("/chains/<int:chain_id>/intermediates/<int:ic_id>/update", methods=["POST"])
@login_required
def chain_intermediate_update(chain_id, ic_id):
    """POST /chains/<chain_id>/intermediates/<ic_id>/update — Save edits to an existing intermediate certificate."""
    chain = CertChain.query.get_or_404(chain_id)
    ic = IntermediateCert.query.get_or_404(ic_id)
    name     = _clean(request.form.get("name", ""), 256)
    pem_data = (request.form.get("pem_data", "") or "").strip()
    try:
        order = max(0, int(request.form.get("order", 0)))
    except (ValueError, TypeError):
        order = 0
    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("chain_intermediate_edit", chain_id=chain_id, ic_id=ic_id))
    if not pem_data:
        flash("PEM data is required.", "error")
        return redirect(url_for("chain_intermediate_edit", chain_id=chain_id, ic_id=ic_id))
    try:
        x509.load_pem_x509_certificate(pem_data.encode())
    except Exception as e:
        flash(f"Invalid PEM certificate data: {e}", "error")
        return redirect(url_for("chain_intermediate_edit", chain_id=chain_id, ic_id=ic_id))
    ic.name = name
    ic.pem_data = pem_data
    ic.order = order
    db.session.commit()
    _audit("intermediate_updated", "intermediate", ic_id, "success", f"name={name!r} chain_id={chain_id}")
    flash(f"Certificate '{name}' updated.", "success")
    return redirect(url_for("chain_detail", chain_id=chain_id))


@app.route("/chains/<int:chain_id>/intermediates/<int:ic_id>/delete", methods=["POST"])
@login_required
def chain_intermediate_delete(chain_id, ic_id):
    """POST /chains/<chain_id>/intermediates/<ic_id>/delete — Remove an intermediate certificate from a chain."""
    ic = IntermediateCert.query.get_or_404(ic_id)
    name = ic.name
    db.session.delete(ic)
    db.session.commit()
    _audit("intermediate_deleted", "intermediate", ic_id, "success", f"name={name!r} chain_id={chain_id}")
    flash(f"Certificate '{name}' deleted.", "success")
    return redirect(url_for("chain_detail", chain_id=chain_id))


@app.route("/chains/<int:chain_id>/reorder", methods=["POST"])
@login_required
def chain_reorder(chain_id):
    """POST /chains/<chain_id>/reorder — Accept a JSON list of {id, order} pairs and update sort positions."""
    data = request.get_json()
    if not data or not isinstance(data, list):
        return {"error": "Invalid data"}, 400
    for item in data:
        ic = IntermediateCert.query.get(item.get("id"))
        if ic is not None:
            ic.order = item.get("order", 0)
    db.session.commit()
    return {"status": "ok"}


@app.route("/chains/<int:chain_id>/import", methods=["GET", "POST"])
@login_required
def chain_import(chain_id):
    """GET/POST /chains/<chain_id>/import — Import a PEM bundle (file or pasted text) into a chain, skipping duplicates."""
    chain = CertChain.query.get_or_404(chain_id)

    if request.method == "GET":
        return render_template("chain_import.html", chain=chain)

    # Collect PEM text from file upload or pasted textarea
    pem_text = ""
    uploaded = request.files.get("bundle_file")
    if uploaded and uploaded.filename:
        try:
            pem_text = uploaded.read().decode("utf-8", errors="replace")
        except Exception as e:
            flash(f"Could not read uploaded file: {e}", "error")
            return render_template("chain_import.html", chain=chain)
    else:
        pem_text = request.form.get("pem_text", "").strip()

    if not pem_text:
        flash("No PEM data provided.", "error")
        return render_template("chain_import.html", chain=chain)

    try:
        pem_blocks = parse_pem_bundle(pem_text)
    except ValueError as e:
        flash(str(e), "error")
        return render_template("chain_import.html", chain=chain)

    # Determine starting order: place imported certs after existing ones
    existing = IntermediateCert.query.filter_by(chain_id=chain_id).order_by(
        IntermediateCert.order.desc()
    ).first()
    next_order = (existing.order + 1) if existing else 0

    added = 0
    skipped = []
    for pem in pem_blocks:
        try:
            parsed = x509.load_pem_x509_certificate(pem.encode())
        except Exception as e:
            skipped.append(f"(unparseable block: {e})")
            continue

        # Derive name from CN (fall back to full subject string)
        try:
            cn = parsed.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            cn = str(parsed.subject)

        # Skip if an identical PEM already exists in this chain
        already = IntermediateCert.query.filter_by(chain_id=chain_id, pem_data=pem).first()
        if already:
            skipped.append(cn)
            continue

        ic = IntermediateCert(name=cn, pem_data=pem, order=next_order, chain_id=chain_id)
        db.session.add(ic)
        next_order += 1
        added += 1

    db.session.commit()

    if added:
        _audit("chain_import", "chain", chain_id, "success", f"imported={added} skipped={len(skipped)}")
        flash(f"Imported {added} certificate(s) successfully.", "success")
    if skipped:
        flash(f"Skipped {len(skipped)} duplicate/invalid certificate(s): {', '.join(skipped)}", "warning")
    if not added and not skipped:
        flash("No certificates were imported.", "warning")

    return redirect(url_for("chain_detail", chain_id=chain_id))


# ---- Database integrity check ----

@app.route("/admin/db-check")
@superadmin_required
def db_integrity_check():
    """GET /admin/db-check — Run SQLite integrity checks and report results (superadmin only)."""
    from sqlalchemy import text
    results = {}
    try:
        with db.engine.connect() as conn:
            # Full structural integrity check
            rows = conn.execute(text("PRAGMA integrity_check")).fetchall()
            results["integrity_check"] = [r[0] for r in rows]

            # Quick check (index/page consistency, faster than full)
            rows = conn.execute(text("PRAGMA quick_check")).fetchall()
            results["quick_check"] = [r[0] for r in rows]

            # WAL journal mode confirmation
            row = conn.execute(text("PRAGMA journal_mode")).fetchone()
            results["journal_mode"] = row[0] if row else "unknown"

            # Foreign key violations
            rows = conn.execute(text("PRAGMA foreign_key_check")).fetchall()
            results["foreign_key_violations"] = len(rows)
            results["foreign_key_details"] = [
                {"table": r[0], "rowid": r[1], "parent": r[2], "fkid": r[3]}
                for r in rows
            ]

            # Database page stats
            row = conn.execute(text("PRAGMA page_count")).fetchone()
            results["page_count"] = row[0] if row else 0
            row = conn.execute(text("PRAGMA page_size")).fetchone()
            results["page_size"] = row[0] if row else 0
            row = conn.execute(text("PRAGMA freelist_count")).fetchone()
            results["freelist_count"] = row[0] if row else 0

        integrity_ok = results["integrity_check"] == ["ok"]
        quick_ok     = results["quick_check"]     == ["ok"]
        fk_ok        = results["foreign_key_violations"] == 0
        overall_ok   = integrity_ok and quick_ok and fk_ok

        _audit("db_integrity_check", result="success" if overall_ok else "failure",
               detail=f"integrity={'ok' if integrity_ok else 'FAIL'} "
                      f"quick={'ok' if quick_ok else 'FAIL'} "
                      f"fk_violations={results['foreign_key_violations']}")
    except Exception as e:
        results = {"error": str(e)}
        overall_ok = False
        _audit("db_integrity_check", result="failure", detail=f"exception={e!r}")

    return render_template("db_check.html", results=results, overall_ok=overall_ok)


# ---- Audit log viewer ----

@app.route("/audit")
@superadmin_required
def audit_log_view():
    """GET /audit — Display paginated audit log entries (superadmin only)."""
    page = request.args.get("page", 1, type=int)
    per_page = 50
    pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template("audit.html", entries=pagination.items, pagination=pagination)


# ---- Error handlers ----

@app.errorhandler(404)
def not_found(e):
    """Render a custom 404 page and log the missing-path event."""
    _audit("not_found", result="failure", detail=f"path={request.path!r}")
    return render_template("404.html"), 404


@app.errorhandler(403)
def forbidden(e):
    """Render a custom 403 page and log the forbidden-access event."""
    _audit("forbidden", result="failure", detail=f"path={request.path!r}")
    return render_template("403.html"), 403


# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------

_ALLOWED_MIGRATIONS = {
    ("intermediate_cert", "chain_id INTEGER REFERENCES cert_chain(id)"),
    ("certificate",       "chain_id INTEGER REFERENCES cert_chain(id)"),
    ("certificate",       "profile_id INTEGER REFERENCES settings(id)"),
    ("settings",          "name TEXT NOT NULL DEFAULT 'Default'"),
    ("settings",          "is_default INTEGER NOT NULL DEFAULT 0"),
}


def _add_column_if_missing(engine, table, column_def):
    """Add a column to an existing SQLite table if it doesn't already exist.

    Only whitelisted (table, column_def) pairs are permitted to prevent
    accidental or malicious schema changes.
    """
    if (table, column_def) not in _ALLOWED_MIGRATIONS:
        raise ValueError(f"Unrecognised migration: {table!r} / {column_def!r}")
    from sqlalchemy import inspect as sa_inspect, text
    inspector = sa_inspect(engine)
    cols = [c["name"] for c in inspector.get_columns(table)]
    if column_def.split()[0] not in cols:
        with engine.connect() as conn:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column_def}"))
            conn.commit()


with app.app_context():
    db.create_all()
    # Ensure new columns exist on databases created before this schema version
    _add_column_if_missing(db.engine, "intermediate_cert", "chain_id INTEGER REFERENCES cert_chain(id)")
    _add_column_if_missing(db.engine, "certificate", "chain_id INTEGER REFERENCES cert_chain(id)")
    _add_column_if_missing(db.engine, "certificate", "profile_id INTEGER REFERENCES settings(id)")
    _add_column_if_missing(db.engine, "settings", "name TEXT NOT NULL DEFAULT 'Default'")
    _add_column_if_missing(db.engine, "settings", "is_default INTEGER NOT NULL DEFAULT 0")
    # Seed initial profile or migrate legacy singleton
    if Settings.query.first() is None:
        db.session.add(Settings(name="Default", is_default=True, key_size=2048))
        db.session.commit()
    else:
        # Ensure exactly one profile is marked as the default
        if not Settings.query.filter_by(is_default=True).first():
            first = Settings.query.order_by(Settings.id.asc()).first()
            first.is_default = True
            db.session.commit()
    # Backfill profile_id for certificates created before profiles were introduced
    try:
        default_p = Settings.query.filter_by(is_default=True).first()
        if default_p:
            Certificate.query.filter_by(profile_id=None).update({"profile_id": default_p.id})
            db.session.commit()
    except Exception:
        db.session.rollback()
    # Migrate intermediates that pre-date named chains into a "Default Chain"
    try:
        orphans = IntermediateCert.query.filter_by(chain_id=None).all()
        if orphans:
            default_chain = CertChain.query.filter_by(name="Default Chain").first()
            if default_chain is None:
                default_chain = CertChain(name="Default Chain",
                                          description="Migrated from previous version")
                db.session.add(default_chain)
                db.session.flush()
            for ic in orphans:
                ic.chain_id = default_chain.id
            db.session.commit()
    except Exception:
        db.session.rollback()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
