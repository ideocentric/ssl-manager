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
from datetime import datetime, timedelta, timezone
from io import BytesIO
from zipfile import ZipFile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7 as _pkcs7
from cryptography.x509.oid import NameOID

from .extensions import db
from .models import CertChain, IntermediateCert, Settings


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
# CA key/certificate generation and CSR signing
# ---------------------------------------------------------------------------

def generate_ca_key_and_cert(common_name, key_size, validity_days, country, state, city, org_name, org_unit, email):
    """Generate a self-signed root CA key and certificate.

    Returns (private_key_pem, cert_pem) as strings.
    """
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
    name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    subject = x509.Name(name_attrs)
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return private_key_pem, cert_pem


def sign_csr_with_ca(csr_pem, ca_cert_pem, ca_key_pem, validity_days=365):
    """Sign a CSR with a CA key/cert. Returns signed certificate PEM string."""
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)

    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    # Copy SANs from CSR if present
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san_ext.value, critical=False)
    except x509.ExtensionNotFound:
        pass

    cert = builder.sign(ca_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


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


def normalize_pem(text):
    """Normalize PEM text to LF line endings.

    Browsers submit <textarea> content with CRLF line breaks (HTML form
    convention), and some vendor bundles ship CRLF/CR. Storing LF keeps the
    database and every text export (fullchain.pem, chain.pem) consistent.
    No-op on already-LF or empty input.
    """
    if not text:
        return text
    return text.replace("\r\n", "\n").replace("\r", "\n")


def parse_pem_bundle(text):
    """Split a concatenated PEM bundle into a list of individual PEM strings.

    Line endings are normalized to LF first, so a bundle pasted into a textarea
    (CRLF) or shipped by a vendor as CRLF is stored consistently. Raises
    ValueError if no valid certificates are found.
    """
    text = normalize_pem(text)
    pattern = re.compile(
        r"(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)",
        re.MULTILINE,
    )
    certs = pattern.findall(text)
    if not certs:
        raise ValueError("No PEM certificate blocks found in the provided text.")
    return [c.strip() for c in certs]


def parse_p7b_bundle(data):
    """Parse a DER or PEM PKCS#7 bundle and return a list of PEM cert strings.

    Raises ValueError if the file cannot be parsed or contains no certificates.
    """
    try:
        certs = _pkcs7.load_der_pkcs7_certificates(data)
    except Exception:
        try:
            certs = _pkcs7.load_pem_pkcs7_certificates(data)
        except Exception as e:
            raise ValueError(f"Could not parse P7B file: {e}") from e
    if not certs:
        raise ValueError("P7B file contains no certificates.")
    return [c.public_bytes(serialization.Encoding.PEM).decode() for c in certs]


def is_ca_cert(cert):
    """Return True if cert has BasicConstraints ca=True."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return bc.value.ca
    except x509.ExtensionNotFound:
        return False


def split_bundle_by_role(certs):
    """Split a list of x509.Certificate into (leaves, intermediates) by BasicConstraints.

    Leaves have CA:FALSE or no BasicConstraints; intermediates have CA:TRUE.
    """
    leaves = [c for c in certs if not is_ca_cert(c)]
    intermediates = [c for c in certs if is_ca_cert(c)]
    return leaves, intermediates


def identify_leaf_cert(leaves, csr_pem=None):
    """Return the leaf certificate from a list of non-CA certs.

    Single leaf → returns it directly.
    Multiple leaves + csr_pem → matches by public key.
    Otherwise → returns None (ambiguous).
    """
    if len(leaves) == 1:
        return leaves[0]
    if not leaves:
        return None
    if csr_pem:
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            csr_pub = csr.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            for leaf in leaves:
                leaf_pub = leaf.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                if leaf_pub == csr_pub:
                    return leaf
        except Exception:
            pass
    return None


def find_matching_chain(intermediate_serials):
    """Return a CertChain whose intermediates cover all given serial numbers, or None."""
    if not intermediate_serials:
        return None
    for chain in CertChain.query.all():
        chain_serials = set()
        for ic in chain.intermediates:
            try:
                chain_serials.add(
                    x509.load_pem_x509_certificate(ic.pem_data.encode()).serial_number
                )
            except Exception:
                pass
        if intermediate_serials.issubset(chain_serials):
            return chain
    return None


def parse_pkcs12(data, password):
    """Parse a PKCS#12 bundle. Returns (private_key_pem, leaf_cert_pem, ca_cert_pem_list).

    Raises ValueError on wrong password or malformed data.
    Private key is serialized without encryption.
    """
    pwd = password.encode() if password else b""
    try:
        p12 = pkcs12.load_pkcs12(data, pwd)
    except Exception as e:
        raise ValueError(f"Could not read PKCS#12 file: {e}") from e
    if p12.key is None:
        raise ValueError("No private key found in PKCS#12 file.")
    if p12.cert is None:
        raise ValueError("No certificate found in PKCS#12 file.")

    key_pem = p12.key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cert_pem = p12.cert.certificate.public_bytes(serialization.Encoding.PEM).decode()
    ca_pems = []
    if p12.additional_certs:
        for ac in p12.additional_certs:
            ca_pems.append(ac.certificate.public_bytes(serialization.Encoding.PEM).decode())
    return key_pem, cert_pem, ca_pems


def keys_match(private_key_pem, cert_pem):
    """Return True if the private key's public key matches the certificate's public key."""
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        key_pub = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cert_pub = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return key_pub == cert_pub
    except Exception:
        return False


def get_key_info(private_key_pem):
    """Return a dict describing the private key type and size."""
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        if isinstance(key, rsa.RSAPrivateKey):
            return {"type": "RSA", "bits": key.key_size}
        if isinstance(key, _ec.EllipticCurvePrivateKey):
            return {"type": "EC", "bits": key.key_size, "curve": key.curve.name}
        return {"type": "other", "bits": None}
    except Exception:
        return {"type": "unknown", "bits": None}


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
    """Create a JKS keystore with the key and its certificate chain. Returns bytes.

    Backed by the dependency-free app.jks_writer — no pyjks and no JRE/keytool
    are required at runtime.
    """
    from .jks_writer import build_jks

    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    key_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    cert_chain_der = [cert.public_bytes(serialization.Encoding.DER)]
    for pem in intermediates_pem_list:
        if pem and pem.strip():
            try:
                ic = x509.load_pem_x509_certificate(pem.encode())
                cert_chain_der.append(ic.public_bytes(serialization.Encoding.DER))
            except Exception:
                pass

    return build_jks(key_der, cert_chain_der, store_password, alias=alias)


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


def create_components_zip(domain, cert_pem, key_pem, intermediates_pem_list):
    """Create a ZIP of component PEM files. Returns BytesIO.

    Contents:
      private_key.pem  — RSA private key only
      certificate.pem  — signed certificate only
      chain.pem        — intermediates concatenated (no cert, no key)
      fullchain.pem    — signed cert + intermediates (no private key)
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

    buf.seek(0)
    return buf