# ==============================================================================
# FILE:           app/crypto.py
# DESCRIPTION:    Cryptographic helper functions: RSA key/CSR generation,
#                 certificate parsing, and multi-format bundle creation
#                 (PKCS#12, JKS, P7B, ZIP, PEM fullchain).
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import os
import re
import subprocess
import tempfile
from datetime import timezone
from io import BytesIO
from zipfile import ZipFile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from .extensions import db
from .models import IntermediateCert, Settings


# ---------------------------------------------------------------------------
# Profile helpers
# ---------------------------------------------------------------------------

def get_default_profile():
    """Return the active default Settings profile, creating one if none exist.

    Resolution order:
      1. The profile with ``is_default=True``.
      2. The only existing profile (when exactly one exists).
      3. A newly-created "Default" profile (first run).
    """
    default = Settings.query.filter_by(is_default=True).first()
    if default:
        return default
    profiles = Settings.query.all()
    if len(profiles) == 1:
        profiles[0].is_default = True
        db.session.commit()
        return profiles[0]
    if not profiles:
        profile = Settings(name="Default", is_default=True, key_size=2048)
        db.session.add(profile)
        db.session.commit()
        return profile
    profiles[0].is_default = True
    db.session.commit()
    return profiles[0]


# Keep the old name as an alias so any call sites missed by this refactor
# still work correctly.
get_settings = get_default_profile


# ---------------------------------------------------------------------------
# Chain helpers
# ---------------------------------------------------------------------------

def get_intermediates_ordered():
    """Return all intermediate certs sorted by order ascending (legacy helper)."""
    return IntermediateCert.query.order_by(IntermediateCert.order.asc()).all()


def get_chain_intermediates(chain_id):
    """Return intermediate certs for a specific chain, sorted by order."""
    if chain_id is None:
        return []
    return IntermediateCert.query.filter_by(chain_id=chain_id).order_by(IntermediateCert.order.asc()).all()


# ---------------------------------------------------------------------------
# Key and CSR generation
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------

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


def parse_pem_bundle(text):
    """Split a concatenated PEM bundle into a list of individual PEM strings.

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
# Bundle creation
# ---------------------------------------------------------------------------

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

    return pkcs12.serialize_key_and_certificates(
        name=name,
        key=key,
        cert=cert,
        cas=cas if cas else None,
        encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption(),
    )


def create_jks(cert_pem, key_pem, intermediates_pem_list, store_password, alias="certificate"):
    """Create JKS keystore. Returns bytes."""
    import jks

    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    key_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

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
            return f.read()
    finally:
        os.unlink(tmp_path)


def create_p7b(cert_pem_list):
    """Create PKCS#7 P7B bundle from list of PEM strings. Returns bytes or None."""
    try:
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
            return f.read()
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
      private_key.pem  — RSA private key only
      certificate.pem  — signed certificate only
      chain.pem        — intermediates concatenated (no cert, no key)
      fullchain.pem    — signed cert + intermediates (no private key)
      certificate.csr  — original CSR (if available)
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