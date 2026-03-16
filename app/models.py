# ==============================================================================
# FILE:           app/models.py
# DESCRIPTION:    SQLAlchemy ORM models: User, Settings, CertChain,
#                 IntermediateCert, Certificate, AuditLog.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import json
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager
from .validators import normalize_alias


class User(db.Model, UserMixin):
    """Application user with role-based access control."""

    __tablename__ = "user"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False)
    email         = db.Column(db.String(256), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(16), default="user", nullable=False)  # superadmin | user
    active        = db.Column(db.Boolean, default=True, nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.now)

    @property
    def is_active(self):
        """Return whether this user account is active."""
        return self.active

    def set_password(self, password: str) -> None:
        """Hash and store the given password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify a plain-text password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    @property
    def is_superadmin(self) -> bool:
        """Return True if the user has the superadmin role."""
        return self.role == "superadmin"


@login_manager.user_loader
def load_user(user_id: str):
    """Load a user by ID for Flask-Login session management."""
    return db.session.get(User, int(user_id))


def _superadmin_count() -> int:
    """Return the number of active superadmin users."""
    return User.query.filter_by(role="superadmin", active=True).count()


class Settings(db.Model):
    """Named profile of certificate-subject defaults used when generating new CSRs."""

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
    created_at = db.Column(db.DateTime, default=datetime.now)
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
    created_at = db.Column(db.DateTime, default=datetime.now)

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
    def days_until_expiry(self):
        """Return the number of days until the certificate expires, or None if not set."""
        if self.expiry_date is None:
            return None
        now = datetime.now(timezone.utc)
        exp = self.expiry_date
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return (exp - now).days

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
    created_at = db.Column(db.DateTime, default=datetime.now)
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
        """Domain name safe for use in filenames and keystore aliases."""
        return normalize_alias(self.domain)


class CertificateAuthority(db.Model):
    """Self-signed root CA used to sign internal certificates."""

    __tablename__ = "certificate_authority"

    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(256), nullable=False, unique=True)
    description     = db.Column(db.String(512), default="")
    key_size        = db.Column(db.Integer, default=4096)
    private_key_pem = db.Column(db.Text, nullable=False)
    cert_pem        = db.Column(db.Text, nullable=False)
    created_at      = db.Column(db.DateTime, default=datetime.now)

    @property
    def parsed_cert(self):
        """Return the parsed x509 certificate object, or None on failure."""
        try:
            return x509.load_pem_x509_certificate(self.cert_pem.encode())
        except Exception:
            return None

    @property
    def expiry_date(self):
        """Return the CA certificate expiry as a timezone-aware datetime, or None."""
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
    def days_until_expiry(self):
        """Return the number of days until the CA certificate expires, or None."""
        if self.expiry_date is None:
            return None
        now = datetime.now(timezone.utc)
        exp = self.expiry_date
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return (exp - now).days

    @property
    def common_name(self):
        """Return the CA certificate Common Name."""
        cert = self.parsed_cert
        if cert is None:
            return self.name
        try:
            return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            return self.name


class AuditLog(db.Model):
    """Immutable record of a security-relevant action performed in the application."""

    __tablename__ = "audit_log"

    id            = db.Column(db.Integer, primary_key=True)
    timestamp     = db.Column(db.DateTime, default=datetime.now, index=True)
    username      = db.Column(db.String(64))
    user_id       = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    ip_address    = db.Column(db.String(45))
    action        = db.Column(db.String(64), nullable=False)
    resource_type = db.Column(db.String(32))
    resource_id   = db.Column(db.Integer)
    result        = db.Column(db.String(16))   # "success" | "failure"
    detail        = db.Column(db.String(512))
