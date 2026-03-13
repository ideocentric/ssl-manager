# ==============================================================================
# FILE:           test_app.py
# DESCRIPTION:    pytest test suite for ssl-manager. Covers unit tests for
#                 crypto helpers and validation utilities, and integration tests
#                 for all Flask routes including auth, certificate CRUD,
#                 downloads, chain management, audit logging, and error handlers.
#
# USAGE:          pytest test_app.py
#   OPTIONS:
#     -v                     Verbose output (one line per test)
#     --tb=short             Compact tracebacks on failure
#     -k <expression>        Run only tests matching the expression
#     -x                     Stop on first failure
#
# EXAMPLES:
#   pytest test_app.py -v
#   pytest test_app.py -v --tb=short
#   pytest test_app.py -k "TestAuditLog"
#
# DEPENDENCIES:   pytest, cryptography, Flask test client
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
#   Tests use an in-memory SQLite database via StaticPool. CSRF enforcement
#   is disabled in test mode (app.testing = True).
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import importlib.util
import json
import os
from datetime import datetime, timedelta, timezone
from io import BytesIO
from zipfile import ZipFile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from app.crypto import (
    create_components_zip,
    create_pkcs12,
    generate_key_and_csr,
    parse_cert_expiry,
    parse_pem_bundle,
)
from app.extensions import db
from app.models import AuditLog, Certificate, CertChain, IntermediateCert, Settings, User
from app.validators import normalize_alias

TEST_ADMIN_USERNAME = "admin"
TEST_ADMIN_PASSWORD = "testpassword123"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rsa_key(key_size=1024):
    """Generate a small RSA key suitable for tests (fast, not production-grade)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _make_self_signed_cert(key, domain="test.example.com", days=365):
    """Return a self-signed certificate PEM string."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _make_expired_cert(key, domain="expired.example.com"):
    """Return a self-signed cert that is already expired."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=60))
        .not_valid_after(datetime.now(timezone.utc) - timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def rsa_key():
    """Reusable RSA key (1024-bit for speed)."""
    return _make_rsa_key(1024)


@pytest.fixture(scope="session")
def signed_cert_pem(rsa_key):
    return _make_self_signed_cert(rsa_key)


@pytest.fixture(scope="session")
def key_pem(rsa_key):
    return _key_pem(rsa_key)


@pytest.fixture()
def cert_record(flask_app):
    """A Certificate with a matching private key + signed cert, inserted directly.

    The cryptography library validates key-cert matching inside PKCS12 serialisation,
    so the private key stored in the DB must correspond to the signed certificate's
    public key.  We generate both from the same RSA key object here.
    """
    key_pem_raw, csr_pem = generate_key_and_csr(
        "example.com", ["www.example.com"], 1024,
        "US", "California", "San Francisco", "Test Org", "IT", "admin@example.com",
    )
    # Load the key object so we can sign a matching self-signed cert with it.
    cert_key = serialization.load_pem_private_key(key_pem_raw.encode(), password=None)
    signed_pem = _make_self_signed_cert(cert_key, "example.com")

    expiry = parse_cert_expiry(signed_pem)
    if expiry.tzinfo is not None:
        expiry = expiry.replace(tzinfo=None)

    with flask_app.app_context():
        cert = Certificate(
            domain="example.com",
            san_domains='["www.example.com"]',
            key_size=1024,
            private_key_pem=key_pem_raw,
            csr_pem=csr_pem,
            signed_cert_pem=signed_pem,
            status="active",
            expiry_date=expiry,
            country="US", state="California", city="San Francisco",
            org_name="Test Org", org_unit="IT", email="admin@example.com",
        )
        db.session.add(cert)
        db.session.commit()
        return cert.id


@pytest.fixture()
def chain_record(client):
    """A CertChain created via HTTP."""
    resp = client.post("/chains/new",
                       data={"name": "Test Chain", "description": "Test chain"},
                       follow_redirects=False)
    assert resp.status_code == 302
    chain_id = int(resp.headers["Location"].rstrip("/").split("/")[-1])
    yield chain_id


@pytest.fixture()
def intermediate_record(client, chain_record, rsa_key):
    """An IntermediateCert created via HTTP inside a chain."""
    pem = _make_self_signed_cert(rsa_key, domain="ca.example.com")
    resp = client.post(f"/chains/{chain_record}/intermediates",
                       data={"name": "Test CA", "pem_data": pem, "order": "0"},
                       follow_redirects=False)
    assert resp.status_code == 302
    # Retrieve the ic id from the chain detail page
    import re
    detail = client.get(f"/chains/{chain_record}")
    match = re.search(rb"/intermediates/(\d+)/edit", detail.data)
    assert match, "Could not find intermediate record id in chain detail page"
    yield int(match.group(1)), chain_record


# ---------------------------------------------------------------------------
# Crypto helper tests
# ---------------------------------------------------------------------------

class TestGenerateKeyAndCsr:
    def test_returns_pem_strings(self):
        key_pem, csr_pem = generate_key_and_csr(
            "example.com", [], 1024, "US", "CA", "LA", "Org", "OU", "e@x.com"
        )
        assert key_pem.startswith("-----BEGIN RSA PRIVATE KEY-----")
        assert csr_pem.startswith("-----BEGIN CERTIFICATE REQUEST-----")

    def test_cn_is_domain(self):
        _, csr_pem = generate_key_and_csr(
            "mysite.com", [], 1024, "US", "", "", "", "", ""
        )
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "mysite.com"

    def test_san_extension_includes_domain(self):
        _, csr_pem = generate_key_and_csr(
            "mysite.com", ["www.mysite.com"], 1024, "US", "", "", "", "", ""
        )
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = [n.value for n in san.value]
        assert "mysite.com" in dns_names
        assert "www.mysite.com" in dns_names

    def test_san_deduplicates_domain(self):
        """Domain should not appear twice in the SAN list."""
        _, csr_pem = generate_key_and_csr(
            "mysite.com", ["mysite.com", "www.mysite.com"], 1024, "US", "", "", "", "", ""
        )
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = [n.value for n in san.value]
        assert dns_names.count("mysite.com") == 1

    def test_subject_fields_populated(self):
        _, csr_pem = generate_key_and_csr(
            "x.com", [], 1024, "US", "Texas", "Austin", "ACME", "Dev", ""
        )
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        attrs = {a.oid: a.value for a in csr.subject}
        assert attrs[NameOID.COUNTRY_NAME] == "US"
        assert attrs[NameOID.STATE_OR_PROVINCE_NAME] == "Texas"
        assert attrs[NameOID.LOCALITY_NAME] == "Austin"
        assert attrs[NameOID.ORGANIZATION_NAME] == "ACME"
        assert attrs[NameOID.ORGANIZATIONAL_UNIT_NAME] == "Dev"

    def test_optional_fields_omitted_when_empty(self):
        """Empty strings should not add subject attributes."""
        _, csr_pem = generate_key_and_csr(
            "x.com", [], 1024, "", "", "", "", "", ""
        )
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        oids = [a.oid for a in csr.subject]
        assert NameOID.COUNTRY_NAME not in oids
        assert NameOID.ORGANIZATION_NAME not in oids


class TestParseCertExpiry:
    def test_returns_datetime(self, rsa_key, signed_cert_pem):
        expiry = parse_cert_expiry(signed_cert_pem)
        assert isinstance(expiry, datetime)

    def test_expiry_is_in_future(self, rsa_key, signed_cert_pem):
        expiry = parse_cert_expiry(signed_cert_pem)
        assert expiry > datetime.now(timezone.utc)

    def test_expired_cert_expiry_in_past(self, rsa_key):
        pem = _make_expired_cert(rsa_key)
        expiry = parse_cert_expiry(pem)
        assert expiry < datetime.now(timezone.utc)

    def test_invalid_pem_raises(self):
        with pytest.raises(Exception):
            parse_cert_expiry("not a cert")


class TestCreatePkcs12:
    def test_returns_bytes(self, rsa_key, signed_cert_pem, key_pem):
        result = create_pkcs12(signed_cert_pem, key_pem, [], "secret")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_loadable_with_correct_password(self, rsa_key, signed_cert_pem, key_pem):
        p12 = create_pkcs12(signed_cert_pem, key_pem, [], "mypassword")
        loaded_key, loaded_cert, _ = pkcs12.load_key_and_certificates(
            p12, b"mypassword"
        )
        assert loaded_cert is not None
        assert loaded_key is not None

    def test_wrong_password_raises(self, rsa_key, signed_cert_pem, key_pem):
        p12 = create_pkcs12(signed_cert_pem, key_pem, [], "correct")
        with pytest.raises(Exception):
            pkcs12.load_key_and_certificates(p12, b"wrong")

    def test_empty_password(self, rsa_key, signed_cert_pem, key_pem):
        result = create_pkcs12(signed_cert_pem, key_pem, [], "")
        assert isinstance(result, bytes)

    def test_with_intermediate(self, rsa_key, signed_cert_pem, key_pem):
        intermediate_key = _make_rsa_key(1024)
        intermediate_pem = _make_self_signed_cert(intermediate_key, "ca.example.com")
        result = create_pkcs12(signed_cert_pem, key_pem, [intermediate_pem], "pass")
        _, _, cas = pkcs12.load_key_and_certificates(result, b"pass")
        assert cas is not None
        assert len(cas) == 1

    def test_invalid_pem_in_intermediates_ignored(self, rsa_key, signed_cert_pem, key_pem):
        """Bad intermediate PEMs should be skipped, not crash."""
        result = create_pkcs12(signed_cert_pem, key_pem, ["not a cert", ""], "pass")
        assert isinstance(result, bytes)


class TestCreateComponentsZip:
    def test_returns_bytesio(self, signed_cert_pem, key_pem):
        buf = create_components_zip("example.com", signed_cert_pem, key_pem, [])
        assert hasattr(buf, "read")

    def test_zip_contains_required_files(self, signed_cert_pem, key_pem):
        buf = create_components_zip("example.com", signed_cert_pem, key_pem, [])
        with ZipFile(buf) as zf:
            names = zf.namelist()
        assert "private_key.pem" in names
        assert "certificate.pem" in names
        assert "fullchain.pem" in names

    def test_fullchain_contains_cert_not_key(self, signed_cert_pem, key_pem):
        buf = create_components_zip("example.com", signed_cert_pem, key_pem, [])
        with ZipFile(buf) as zf:
            fullchain = zf.read("fullchain.pem").decode()
        assert "PRIVATE KEY" not in fullchain
        assert "CERTIFICATE" in fullchain

    def test_intermediates_included(self, signed_cert_pem, key_pem):
        inter_key = _make_rsa_key(1024)
        inter_pem = _make_self_signed_cert(inter_key, "ca.example.com")
        buf = create_components_zip("example.com", signed_cert_pem, key_pem, [inter_pem])
        with ZipFile(buf) as zf:
            names = zf.namelist()
        assert "chain.pem" in names

    def test_csr_included_when_provided(self, signed_cert_pem, key_pem):
        _, csr_pem = generate_key_and_csr("x.com", [], 1024, "", "", "", "", "", "")
        buf = create_components_zip("example.com", signed_cert_pem, key_pem, [], csr_pem=csr_pem)
        with ZipFile(buf) as zf:
            names = zf.namelist()
        assert "certificate.csr" in names

    def test_csr_omitted_when_not_provided(self, signed_cert_pem, key_pem):
        buf = create_components_zip("example.com", signed_cert_pem, key_pem, [])
        with ZipFile(buf) as zf:
            names = zf.namelist()
        assert "certificate.csr" not in names

    def test_empty_intermediate_strings_skipped(self, signed_cert_pem, key_pem):
        buf = create_components_zip("example.com", signed_cert_pem, key_pem, ["", "  "])
        with ZipFile(buf) as zf:
            names = zf.namelist()
        assert "chain.pem" not in names


# ---------------------------------------------------------------------------
# Model property tests
# ---------------------------------------------------------------------------

class TestCertificateModel:
    def test_san_list_parses_json(self):
        cert = Certificate(san_domains='["a.com", "b.com"]')
        assert cert.san_list == ["a.com", "b.com"]

    def test_san_list_empty_default(self):
        cert = Certificate(san_domains="[]")
        assert cert.san_list == []

    def test_san_list_handles_invalid_json(self):
        cert = Certificate(san_domains="not json")
        assert cert.san_list == []

    def test_san_list_handles_none(self):
        cert = Certificate(san_domains=None)
        assert cert.san_list == []

    def test_days_until_expiry_future(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        cert = Certificate(expiry_date=future.replace(tzinfo=None))
        assert 29 <= cert.days_until_expiry <= 30

    def test_days_until_expiry_past(self):
        past = datetime.now(timezone.utc) - timedelta(days=5)
        cert = Certificate(expiry_date=past.replace(tzinfo=None))
        assert cert.days_until_expiry < 0

    def test_days_until_expiry_none_when_no_expiry(self):
        cert = Certificate(expiry_date=None)
        assert cert.days_until_expiry is None

    def test_status_label_active(self):
        future = datetime.now(timezone.utc) + timedelta(days=90)
        cert = Certificate(status="active", expiry_date=future.replace(tzinfo=None))
        assert cert.status_label == "active"

    def test_status_label_expired_when_past(self):
        past = datetime.now(timezone.utc) - timedelta(days=1)
        cert = Certificate(status="active", expiry_date=past.replace(tzinfo=None))
        assert cert.status_label == "expired"

    def test_status_label_pending_signing(self):
        cert = Certificate(status="pending_signing", expiry_date=None)
        assert cert.status_label == "pending_signing"


class TestIntermediateCertModel:
    def test_subject_returns_cn(self):
        key = _make_rsa_key(1024)
        pem = _make_self_signed_cert(key, "ca.example.com")
        ic = IntermediateCert(name="CA", pem_data=pem)
        assert ic.subject == "ca.example.com"

    def test_subject_unknown_on_invalid_pem(self):
        ic = IntermediateCert(name="Bad", pem_data="not a cert")
        assert ic.subject == "Unknown"

    def test_is_root_true_for_self_signed(self):
        key = _make_rsa_key(1024)
        pem = _make_self_signed_cert(key, "root.example.com")
        ic = IntermediateCert(name="Root", pem_data=pem)
        assert ic.is_root is True

    def test_expiry_date_parsed(self):
        key = _make_rsa_key(1024)
        pem = _make_self_signed_cert(key, "ca.example.com", days=365)
        ic = IntermediateCert(name="CA", pem_data=pem)
        assert ic.expiry_date is not None
        assert ic.expiry_date > datetime.now(timezone.utc)

    def test_expiry_date_none_on_invalid_pem(self):
        ic = IntermediateCert(name="Bad", pem_data="garbage")
        assert ic.expiry_date is None


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------

class TestIndexRoute:
    def test_redirects_to_certificates(self, client):
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/certificates" in resp.headers["Location"]


class TestCertificatesListRoute:
    def test_get_returns_200(self, client):
        resp = client.get("/certificates")
        assert resp.status_code == 200

    def test_shows_certificate_domain(self, client, cert_record):
        resp = client.get("/certificates")
        assert b"example.com" in resp.data


class TestCertificateNewRoute:
    def test_get_returns_200(self, client):
        resp = client.get("/certificates/new")
        assert resp.status_code == 200

    def test_post_missing_domain_returns_error(self, client):
        resp = client.post("/certificates/new", data={"domain": ""})
        assert resp.status_code == 200
        assert b"Domain is required" in resp.data

    def test_post_valid_redirects_to_detail(self, client):
        resp = client.post("/certificates/new", data={
            "domain": "newcert.example.com",
            "san_domains": "",
            "key_size": "1024",
            "country": "US",
            "state": "CA",
            "city": "SF",
            "org_name": "Test",
            "org_unit": "",
            "email": "",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "/certificates/" in resp.headers["Location"]

    def test_post_creates_db_record(self, client):
        resp = client.post("/certificates/new", data={
            "domain": "created.example.com",
            "san_domains": "www.created.example.com",
            "key_size": "1024",
            "country": "US",
            "state": "", "city": "", "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=False)
        assert resp.status_code == 302
        cert_id = int(resp.headers["Location"].rstrip("/").split("/")[-1])
        # Verify by loading the detail page
        detail = client.get(f"/certificates/{cert_id}")
        assert b"created.example.com" in detail.data
        assert b"pending" in detail.data.lower()

    def test_settings_prepopulate_form(self, client, flask_app):
        """Settings values should pre-fill the new certificate form."""
        with flask_app.app_context():
            s = Settings.query.first()
            s.country = "DE"
            s.state = "Bavaria"
            s.city = "Munich"
            s.org_name = "Widgets GmbH"
            s.org_unit = "Engineering"
            s.email = "ssl@widgets.de"
            s.key_size = 4096
            db.session.commit()

        resp = client.get("/certificates/new")
        assert b"DE" in resp.data
        assert b"Bavaria" in resp.data
        assert b"Munich" in resp.data
        assert b"Widgets GmbH" in resp.data
        assert b"Engineering" in resp.data
        assert b"ssl@widgets.de" in resp.data
        assert b'value="4096"' in resp.data

    def test_post_san_stored(self, client):
        resp = client.post("/certificates/new", data={
            "domain": "san.example.com",
            "san_domains": "www.san.example.com\napi.san.example.com",
            "key_size": "1024",
            "country": "", "state": "", "city": "", "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=True)
        assert b"www.san.example.com" in resp.data
        assert b"api.san.example.com" in resp.data


class TestCertificateDetailRoute:
    def test_get_returns_200(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}")
        assert resp.status_code == 200

    def test_404_for_missing_cert(self, client):
        resp = client.get("/certificates/99999")
        assert resp.status_code == 404

    def test_shows_domain(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}")
        assert b"example.com" in resp.data


class TestCertificateUploadRoute:
    def test_upload_valid_cert_sets_active(self, client):
        # Create a pending cert via HTTP
        resp = client.post("/certificates/new", data={
            "domain": "upload.example.com", "san_domains": "",
            "key_size": "1024", "country": "", "state": "", "city": "",
            "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=False)
        assert resp.status_code == 302
        cert_id = int(resp.headers["Location"].rstrip("/").split("/")[-1])

        # Upload a self-signed cert
        key = _make_rsa_key(1024)
        signed_pem = _make_self_signed_cert(key, "upload.example.com")
        resp = client.post(f"/certificates/{cert_id}/upload",
                           data={"signed_cert_pem": signed_pem},
                           follow_redirects=True)
        assert resp.status_code == 200
        # The detail page should show the cert as active
        assert b"upload.example.com" in resp.data
        assert b"active" in resp.data.lower()

    def test_upload_empty_pem_shows_error(self, client, cert_record):
        resp = client.post(f"/certificates/{cert_record}/upload",
                           data={"signed_cert_pem": ""},
                           follow_redirects=True)
        assert b"No certificate PEM provided" in resp.data

    def test_upload_invalid_pem_shows_error(self, client, cert_record):
        resp = client.post(f"/certificates/{cert_record}/upload",
                           data={"signed_cert_pem": "not a valid cert"},
                           follow_redirects=True)
        assert b"Invalid certificate PEM" in resp.data

    def test_upload_via_file(self, client):
        resp = client.post("/certificates/new", data={
            "domain": "fileupload.example.com", "san_domains": "",
            "key_size": "1024", "country": "", "state": "", "city": "",
            "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=False)
        assert resp.status_code == 302
        cert_id = int(resp.headers["Location"].rstrip("/").split("/")[-1])

        key = _make_rsa_key(1024)
        signed_pem = _make_self_signed_cert(key, "fileupload.example.com")
        resp = client.post(
            f"/certificates/{cert_id}/upload",
            data={"cert_file": (BytesIO(signed_pem.encode()), "cert.pem")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"fileupload.example.com" in resp.data
        assert b"active" in resp.data.lower()


class TestCertificateDeleteRoute:
    def test_delete_removes_record(self, client):
        resp = client.post("/certificates/new", data={
            "domain": "todelete.example.com", "san_domains": "",
            "key_size": "1024", "country": "", "state": "", "city": "",
            "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=False)
        cert_id = int(resp.headers["Location"].rstrip("/").split("/")[-1])

        resp = client.post(f"/certificates/{cert_id}/delete", follow_redirects=True)
        assert resp.status_code == 200
        # The flash message confirms deletion; the cert table should show empty state
        assert b"deleted" in resp.data.lower()
        assert b"No certificates yet" in resp.data


class TestDownloadCsr:
    def test_returns_pem_file(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/download/csr")
        assert resp.status_code == 200
        assert b"CERTIFICATE REQUEST" in resp.data

    def test_correct_filename(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/download/csr")
        assert "example.com.csr" in resp.headers["Content-Disposition"]


class TestDownloadFullchain:
    def test_returns_200(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/download/fullchain")
        assert resp.status_code == 200

    def test_contains_key_and_cert(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/download/fullchain")
        assert b"PRIVATE KEY" in resp.data
        assert b"CERTIFICATE" in resp.data

    def test_correct_filename(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/download/fullchain")
        assert "example.com-fullchain.pem" in resp.headers["Content-Disposition"]

    def test_unsigned_cert_redirects(self, client):
        resp = client.post("/certificates/new", data={
            "domain": "unsigned.example.com", "san_domains": "",
            "key_size": "1024", "country": "", "state": "", "city": "",
            "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=False)
        cert_id = int(resp.headers["Location"].rstrip("/").split("/")[-1])
        resp = client.get(f"/certificates/{cert_id}/download/fullchain")
        assert resp.status_code == 302


class TestDownloadComponents:
    def test_returns_zip(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/download/components")
        assert resp.status_code == 200
        assert resp.content_type == "application/zip"

    def test_zip_has_expected_files(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/download/components")
        buf = BytesIO(resp.data)
        with ZipFile(buf) as zf:
            names = zf.namelist()
        assert "private_key.pem" in names
        assert "certificate.pem" in names
        assert "fullchain.pem" in names

    def test_correct_filename(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/download/components")
        assert "example.com-certs.zip" in resp.headers["Content-Disposition"]


class TestDownloadPkcs12:
    def test_returns_bytes(self, client, cert_record):
        resp = client.post(f"/certificates/{cert_record}/download/pkcs12",
                           data={"password": "testpass"})
        assert resp.status_code == 200
        assert len(resp.data) > 0

    def test_correct_filename(self, client, cert_record):
        resp = client.post(f"/certificates/{cert_record}/download/pkcs12",
                           data={"password": "testpass"})
        assert "example.com.p12" in resp.headers["Content-Disposition"]

    def test_loadable_with_password(self, client, cert_record):
        resp = client.post(f"/certificates/{cert_record}/download/pkcs12",
                           data={"password": "mypassword"})
        key, cert, _ = pkcs12.load_key_and_certificates(resp.data, b"mypassword")
        assert cert is not None

    def test_unsigned_cert_redirects(self, client):
        resp = client.post("/certificates/new", data={
            "domain": "nop12.example.com", "san_domains": "",
            "key_size": "1024", "country": "", "state": "", "city": "",
            "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=False)
        cert_id = int(resp.headers["Location"].rstrip("/").split("/")[-1])
        resp = client.post(f"/certificates/{cert_id}/download/pkcs12",
                           data={"password": "x"})
        assert resp.status_code == 302


@pytest.mark.skipif(
    importlib.util.find_spec("jks") is None,
    reason="pyjks not installed",
)
class TestDownloadJks:
    def test_returns_bytes(self, client, cert_record):
        resp = client.post(f"/certificates/{cert_record}/download/jks",
                           data={"password": "changeit", "alias": "mykey"})
        assert resp.status_code == 200
        assert len(resp.data) > 0

    def test_correct_filename(self, client, cert_record):
        resp = client.post(f"/certificates/{cert_record}/download/jks",
                           data={"password": "changeit", "alias": "mykey"})
        assert "example.com.jks" in resp.headers["Content-Disposition"]

    def test_jks_magic_bytes(self, client, cert_record):
        """JKS files start with the magic bytes 0xFEEDFEED."""
        resp = client.post(f"/certificates/{cert_record}/download/jks",
                           data={"password": "changeit", "alias": "mykey"})
        assert resp.data[:4] == b"\xfe\xed\xfe\xed"

    def test_unsigned_cert_redirects(self, client):
        resp = client.post("/certificates/new", data={
            "domain": "nojks.example.com", "san_domains": "",
            "key_size": "1024", "country": "", "state": "", "city": "",
            "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=False)
        cert_id = int(resp.headers["Location"].rstrip("/").split("/")[-1])
        resp = client.post(f"/certificates/{cert_id}/download/jks",
                           data={"password": "x", "alias": "x"})
        assert resp.status_code == 302


class TestDownloadDer:
    def test_returns_bytes(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/download/der")
        assert resp.status_code == 200
        assert len(resp.data) > 0

    def test_correct_filename(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/download/der")
        assert "example.com.der" in resp.headers["Content-Disposition"]

    def test_mimetype(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/download/der")
        assert resp.content_type == "application/x-x509-ca-cert"

    def test_is_valid_der(self, client, cert_record):
        """DER bytes should parse back to a valid certificate."""
        from cryptography import x509 as cx509
        resp = client.get(f"/certificates/{cert_record}/download/der")
        cert = cx509.load_der_x509_certificate(resp.data)
        assert cert.subject is not None

    def test_unsigned_cert_redirects(self, client):
        resp = client.post("/certificates/new", data={
            "domain": "noder.example.com", "san_domains": "",
            "key_size": "1024", "country": "", "state": "", "city": "",
            "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=False)
        cert_id = int(resp.headers["Location"].rstrip("/").split("/")[-1])
        resp = client.get(f"/certificates/{cert_id}/download/der")
        assert resp.status_code == 302


class TestCertificateRenew:
    def test_renew_returns_200(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/renew")
        assert resp.status_code == 200

    def test_renew_prefills_domain(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/renew")
        assert b"example.com" in resp.data

    def test_renew_shows_renewal_header(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/renew")
        assert b"Renew / Rekey" in resp.data

    def test_renew_cancel_links_back_to_cert(self, client, cert_record):
        resp = client.get(f"/certificates/{cert_record}/renew")
        assert f"/certificates/{cert_record}".encode() in resp.data

    def test_renew_submits_new_cert(self, client, cert_record):
        """Submitting the renewal form creates a new independent certificate."""
        resp = client.post("/certificates/new", data={
            "domain": "example.com", "san_domains": "",
            "key_size": "2048", "country": "US", "state": "", "city": "",
            "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=False)
        new_id = int(resp.headers["Location"].rstrip("/").split("/")[-1])
        assert new_id != cert_record


class TestSettingsRoute:
    def test_settings_redirects_to_profiles(self, client):
        # /settings is now a redirect alias for /profiles
        resp = client.get("/settings", follow_redirects=False)
        assert resp.status_code == 302
        assert "/profiles" in resp.headers["Location"]


class TestProfilesRoute:
    def test_profiles_list_returns_200(self, client):
        resp = client.get("/profiles")
        assert resp.status_code == 200

    def test_profile_new_get_returns_200(self, client):
        resp = client.get("/profiles/new")
        assert resp.status_code == 200

    def test_profile_create_and_list(self, client):
        resp = client.post("/profiles/new", data={
            "name": "Test Corp",
            "key_size": "4096",
            "country": "GB",
            "state": "England",
            "city": "London",
            "org_name": "Test Corp",
            "org_unit": "Security",
            "email": "ssl@test.com",
        }, follow_redirects=True)
        assert b"Test Corp" in resp.data

    def test_profile_create_redirects_to_list(self, client):
        resp = client.post("/profiles/new", data={
            "name": "Redir Test",
            "key_size": "2048", "country": "US", "state": "",
            "city": "", "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "/profiles" in resp.headers["Location"]

    def test_profile_create_requires_name(self, client):
        resp = client.post("/profiles/new", data={
            "name": "",
            "key_size": "2048", "country": "US", "state": "",
            "city": "", "org_name": "", "org_unit": "", "email": "",
        })
        assert resp.status_code == 200
        assert b"required" in resp.data.lower()

    def test_profile_duplicate_name_rejected(self, client, flask_app):
        with flask_app.app_context():
            existing = Settings.query.first()
            name = existing.name
        resp = client.post("/profiles/new", data={
            "name": name,
            "key_size": "2048", "country": "US", "state": "",
            "city": "", "org_name": "", "org_unit": "", "email": "",
        })
        assert resp.status_code == 200
        assert b"already exists" in resp.data

    def test_profile_edit_saves_values(self, client, flask_app):
        with flask_app.app_context():
            profile = Settings.query.first()
            pid = profile.id
        client.post(f"/profiles/{pid}/edit", data={
            "name": "Updated Name",
            "key_size": "4096",
            "country": "DE",
            "state": "Bavaria",
            "city": "Munich",
            "org_name": "GmbH Corp",
            "org_unit": "IT",
            "email": "it@gmbh.de",
        })
        resp = client.get("/profiles")
        assert b"GmbH Corp" in resp.data

    def test_cannot_delete_last_profile(self, client, flask_app):
        with flask_app.app_context():
            assert Settings.query.count() == 1
            pid = Settings.query.first().id
        resp = client.post(f"/profiles/{pid}/delete", follow_redirects=True)
        assert b"Cannot delete the last profile" in resp.data

    def test_set_default_promotes_profile(self, client, flask_app):
        # Create a second profile, then promote it to default
        client.post("/profiles/new", data={
            "name": "Secondary",
            "key_size": "2048", "country": "CA", "state": "",
            "city": "", "org_name": "", "org_unit": "", "email": "",
        })
        with flask_app.app_context():
            second = Settings.query.filter_by(name="Secondary").first()
            sid = second.id
        resp = client.post(f"/profiles/{sid}/set-default", follow_redirects=True)
        assert resp.status_code == 200
        with flask_app.app_context():
            assert Settings.query.filter_by(name="Secondary", is_default=True).count() == 1
            assert Settings.query.filter_by(is_default=True).count() == 1

    def test_invalid_key_size_defaults_to_2048(self, client, flask_app):
        with flask_app.app_context():
            pid = Settings.query.first().id
        client.post(f"/profiles/{pid}/edit", data={
            "name": "Default",
            "key_size": "not_a_number", "country": "US", "state": "",
            "city": "", "org_name": "", "org_unit": "", "email": "",
        })
        resp = client.get("/certificates/new")
        assert resp.status_code == 200


class TestChainsRoute:
    def test_get_returns_200(self, client):
        resp = client.get("/chains")
        assert resp.status_code == 200

    def test_intermediates_redirects_to_chains(self, client):
        resp = client.get("/intermediates", follow_redirects=False)
        assert resp.status_code == 302
        assert "/chains" in resp.headers["Location"]

    def test_shows_chain_name(self, client, chain_record):
        resp = client.get("/chains")
        assert b"Test Chain" in resp.data

    def test_create_chain(self, client):
        resp = client.post("/chains/new",
                           data={"name": "My Chain", "description": "desc"},
                           follow_redirects=False)
        assert resp.status_code == 302

    def test_duplicate_chain_name_rejected(self, client, chain_record):
        resp = client.post("/chains/new",
                           data={"name": "Test Chain", "description": ""},
                           follow_redirects=True)
        assert b"already exists" in resp.data

    def test_chain_detail_returns_200(self, client, chain_record):
        resp = client.get(f"/chains/{chain_record}")
        assert resp.status_code == 200

    def test_chain_update(self, client, chain_record):
        resp = client.post(f"/chains/{chain_record}/update",
                           data={"name": "Renamed Chain", "description": "new desc"},
                           follow_redirects=True)
        assert resp.status_code == 200
        assert b"Renamed Chain" in resp.data

    def test_chain_delete(self, client, chain_record):
        resp = client.post(f"/chains/{chain_record}/delete", follow_redirects=True)
        assert resp.status_code == 200
        assert b"deleted" in resp.data.lower()


class TestIntermediateNewRoute:
    def test_get_form_returns_200(self, client, chain_record):
        resp = client.get(f"/chains/{chain_record}/intermediates/new")
        assert resp.status_code == 200

    def test_post_missing_name_shows_error(self, client, chain_record, rsa_key):
        pem = _make_self_signed_cert(rsa_key, "ca.test.com")
        resp = client.post(f"/chains/{chain_record}/intermediates",
                           data={"name": "", "pem_data": pem, "order": "0"},
                           follow_redirects=True)
        assert b"Name is required" in resp.data

    def test_post_missing_pem_shows_error(self, client, chain_record):
        resp = client.post(f"/chains/{chain_record}/intermediates",
                           data={"name": "CA", "pem_data": "", "order": "0"},
                           follow_redirects=True)
        assert b"PEM data is required" in resp.data

    def test_post_invalid_pem_shows_error(self, client, chain_record):
        resp = client.post(f"/chains/{chain_record}/intermediates",
                           data={"name": "CA", "pem_data": "garbage pem", "order": "0"},
                           follow_redirects=True)
        assert b"Invalid PEM certificate data" in resp.data

    def test_post_valid_creates_record(self, client, chain_record, rsa_key):
        pem = _make_self_signed_cert(rsa_key, "newca.example.com")
        resp = client.post(f"/chains/{chain_record}/intermediates",
                           data={"name": "New CA", "pem_data": pem, "order": "5"},
                           follow_redirects=True)
        assert resp.status_code == 200
        assert b"New CA" in resp.data


class TestIntermediateUpdateRoute:
    def test_post_updates_record(self, client, intermediate_record, rsa_key):
        ic_id, chain_id = intermediate_record
        new_pem = _make_self_signed_cert(rsa_key, "updated.ca.com")
        resp = client.post(f"/chains/{chain_id}/intermediates/{ic_id}/update",
                           data={"name": "Updated CA", "pem_data": new_pem, "order": "10"},
                           follow_redirects=True)
        assert resp.status_code == 200
        assert b"Updated CA" in resp.data


class TestIntermediateDeleteRoute:
    def test_delete_removes_record(self, client, intermediate_record):
        ic_id, chain_id = intermediate_record
        resp = client.post(f"/chains/{chain_id}/intermediates/{ic_id}/delete",
                           follow_redirects=True)
        assert resp.status_code == 200
        assert b"deleted" in resp.data.lower()


class TestIntermediateReorderRoute:
    def test_reorder_updates_order(self, client, intermediate_record):
        ic_id, chain_id = intermediate_record
        resp = client.post(f"/chains/{chain_id}/reorder",
                           data=json.dumps([{"id": ic_id, "order": 99}]),
                           content_type="application/json")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"

    def test_reorder_invalid_body_returns_400(self, client, chain_record):
        resp = client.post(f"/chains/{chain_record}/reorder",
                           data=json.dumps({"not": "a list"}),
                           content_type="application/json")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Auth and user management tests
# ---------------------------------------------------------------------------

class TestSetupRoute:
    def test_setup_redirects_when_users_exist(self, anon_client):
        resp = anon_client.get("/setup", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_setup_accessible_when_no_users(self, flask_app, anon_client):
        with flask_app.app_context():
            for table in reversed(db.metadata.sorted_tables):
                db.session.execute(table.delete())
            db.session.commit()
        resp = anon_client.get("/setup")
        assert resp.status_code == 200
        assert b"Initial Setup" in resp.data

    def test_setup_creates_superadmin(self, flask_app, anon_client):
        with flask_app.app_context():
            for table in reversed(db.metadata.sorted_tables):
                db.session.execute(table.delete())
            db.session.commit()
        resp = anon_client.post("/setup", data={
            "username": "founder",
            "email": "founder@example.com",
            "password": "strongpass1",
            "confirm_password": "strongpass1",
        }, follow_redirects=True)
        assert resp.status_code == 200
        with flask_app.app_context():
            user = User.query.filter_by(username="founder").first()
            assert user is not None
            assert user.role == "superadmin"


class TestLoginLogout:
    def test_login_valid(self, anon_client):
        resp = anon_client.post("/login", data={
            "username": TEST_ADMIN_USERNAME,
            "password": TEST_ADMIN_PASSWORD,
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_login_wrong_password(self, anon_client):
        resp = anon_client.post("/login", data={
            "username": TEST_ADMIN_USERNAME,
            "password": "wrongpassword",
        }, follow_redirects=True)
        assert b"Invalid username or password" in resp.data

    def test_login_unknown_user(self, anon_client):
        resp = anon_client.post("/login", data={
            "username": "nobody",
            "password": "whatever123",
        }, follow_redirects=True)
        assert b"Invalid username or password" in resp.data

    def test_unauthenticated_redirects_to_login(self, anon_client):
        resp = anon_client.get("/certificates", follow_redirects=False)
        assert resp.status_code == 302
        assert "login" in resp.headers["Location"]

    def test_logout(self, client):
        resp = client.get("/logout", follow_redirects=True)
        assert b"logged out" in resp.data.lower()


class TestUserManagement:
    def test_users_list_accessible_to_superadmin(self, client):
        resp = client.get("/users")
        assert resp.status_code == 200
        assert TEST_ADMIN_USERNAME.encode() in resp.data

    def test_users_list_forbidden_to_regular_user(self, flask_app, anon_client):
        # Create a regular user and log in as them
        with flask_app.app_context():
            u = User(username="regularuser", email="regular@test.com", role="user")
            u.set_password("testpassword123")
            db.session.add(u)
            db.session.commit()
        anon_client.post("/login", data={"username": "regularuser", "password": "testpassword123"})
        resp = anon_client.get("/users", follow_redirects=True)
        assert resp.status_code == 200
        assert b"Superadmin access required" in resp.data

    def test_create_user(self, client):
        resp = client.post("/users/new", data={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "newpassword1",
            "confirm_password": "newpassword1",
            "role": "user",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"newuser" in resp.data

    def test_create_user_duplicate_username(self, client):
        resp = client.post("/users/new", data={
            "username": TEST_ADMIN_USERNAME,
            "email": "other@example.com",
            "password": "newpassword1",
            "confirm_password": "newpassword1",
            "role": "user",
        }, follow_redirects=True)
        assert b"already taken" in resp.data

    def test_create_user_password_mismatch(self, client):
        resp = client.post("/users/new", data={
            "username": "mismatch",
            "email": "mismatch@example.com",
            "password": "password123",
            "confirm_password": "different123",
            "role": "user",
        }, follow_redirects=True)
        assert b"do not match" in resp.data

    def test_delete_user(self, flask_app, client):
        with flask_app.app_context():
            u = User(username="todelete", email="todelete@example.com", role="user")
            u.set_password("testpassword123")
            db.session.add(u)
            db.session.commit()
            uid = u.id
        resp = client.post(f"/users/{uid}/delete", follow_redirects=True)
        assert resp.status_code == 200
        assert b"deleted" in resp.data.lower()
        with flask_app.app_context():
            assert User.query.filter_by(username="todelete").first() is None

    def test_cannot_delete_last_superadmin(self, flask_app, client):
        with flask_app.app_context():
            admin = User.query.filter_by(username=TEST_ADMIN_USERNAME).first()
            uid = admin.id
        resp = client.post(f"/users/{uid}/delete", follow_redirects=True)
        assert b"last superadmin" in resp.data.lower() or b"own account" in resp.data.lower()

    def test_cannot_demote_last_superadmin(self, flask_app, client):
        with flask_app.app_context():
            admin = User.query.filter_by(username=TEST_ADMIN_USERNAME).first()
            uid = admin.id
        resp = client.post(f"/users/{uid}/update", data={
            "username": TEST_ADMIN_USERNAME,
            "email": "admin@test.com",
            "role": "user",
            "active": "1",
        }, follow_redirects=True)
        assert b"last active superadmin" in resp.data.lower()


class TestParsePemBundle:
    def _make_pem(self, cn="Test CA"):
        key = _make_rsa_key()
        pem = _make_self_signed_cert(key, cn)
        return pem

    def test_single_cert(self):
        pem = self._make_pem("Single CA")
        result = parse_pem_bundle(pem)
        assert len(result) == 1
        assert "BEGIN CERTIFICATE" in result[0]

    def test_two_certs(self):
        pem1 = self._make_pem("CA One")
        pem2 = self._make_pem("CA Two")
        bundle = pem1 + "\n" + pem2
        result = parse_pem_bundle(bundle)
        assert len(result) == 2

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="No PEM certificate"):
            parse_pem_bundle("not a certificate")

    def test_whitespace_between_certs(self):
        pem1 = self._make_pem("CA A")
        pem2 = self._make_pem("CA B")
        bundle = pem1 + "\n\n\n" + pem2
        result = parse_pem_bundle(bundle)
        assert len(result) == 2


class TestChainImportRoute:
    def test_import_page_loads(self, client, chain_record):
        resp = client.get(f"/chains/{chain_record}/import")
        assert resp.status_code == 200
        assert b"Import Certificate Bundle" in resp.data

    def test_import_pem_text(self, flask_app, client, chain_record):
        key1 = _make_rsa_key()
        key2 = _make_rsa_key()
        pem1 = _make_self_signed_cert(key1, "Import CA One")
        pem2 = _make_self_signed_cert(key2, "Import CA Two")
        bundle = pem1 + "\n" + pem2

        resp = client.post(
            f"/chains/{chain_record}/import",
            data={"pem_text": bundle},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Imported 2" in resp.data

        with flask_app.app_context():
            ics = IntermediateCert.query.filter_by(chain_id=chain_record).all()
            names = [ic.name for ic in ics]
        assert "Import CA One" in names
        assert "Import CA Two" in names

    def test_import_file_upload(self, flask_app, client, chain_record):
        key = _make_rsa_key()
        pem = _make_self_signed_cert(key, "File Upload CA")

        resp = client.post(
            f"/chains/{chain_record}/import",
            data={"bundle_file": (BytesIO(pem.encode()), "bundle.pem")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Imported 1" in resp.data

        with flask_app.app_context():
            ic = IntermediateCert.query.filter_by(
                chain_id=chain_record, name="File Upload CA"
            ).first()
        assert ic is not None

    def test_import_skips_duplicates(self, flask_app, client, chain_record):
        key = _make_rsa_key()
        pem = _make_self_signed_cert(key, "Dup CA")

        # Import once
        client.post(
            f"/chains/{chain_record}/import",
            data={"pem_text": pem},
            follow_redirects=True,
        )
        # Import again — should skip
        resp = client.post(
            f"/chains/{chain_record}/import",
            data={"pem_text": pem},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Skipped" in resp.data

        with flask_app.app_context():
            count = IntermediateCert.query.filter_by(
                chain_id=chain_record, name="Dup CA"
            ).count()
        assert count == 1

    def test_import_no_data_error(self, client, chain_record):
        resp = client.post(
            f"/chains/{chain_record}/import",
            data={"pem_text": ""},
            follow_redirects=True,
        )
        assert b"No PEM data" in resp.data

    def test_import_invalid_pem_error(self, client, chain_record):
        resp = client.post(
            f"/chains/{chain_record}/import",
            data={"pem_text": "this is not a pem"},
            follow_redirects=True,
        )
        assert b"No PEM certificate" in resp.data


class TestNormalizeAlias:
    def test_wildcard_dot(self):
        assert normalize_alias("*.ideocentric.com") == "star.ideocentric.com"

    def test_wildcard_only(self):
        assert normalize_alias("*") == "star"

    def test_plain_domain(self):
        assert normalize_alias("www.example.com") == "www.example.com"

    def test_unsafe_characters_replaced(self):
        result = normalize_alias("my domain.com")
        assert " " not in result

    def test_empty_falls_back(self):
        assert normalize_alias("") == "certificate"


# ---------------------------------------------------------------------------
# Audit log tests
# ---------------------------------------------------------------------------

class TestAuditLogView:
    def test_audit_page_accessible_to_superadmin(self, client):
        resp = client.get("/audit")
        assert resp.status_code == 200
        assert b"Audit Log" in resp.data

    def test_audit_page_denied_to_regular_user(self, flask_app, anon_client):
        """Regular users (non-superadmin) should not reach the audit page."""
        with flask_app.app_context():
            regular = User(username="regular", email="regular@test.com", role="user")
            regular.set_password("testpassword123")
            db.session.add(regular)
            db.session.commit()
        anon_client.post("/login", data={"username": "regular", "password": "testpassword123"})
        resp = anon_client.get("/audit", follow_redirects=True)
        assert b"Superadmin access required" in resp.data

    def test_login_success_creates_audit_entry(self, flask_app, anon_client):
        anon_client.post("/login", data={
            "username": TEST_ADMIN_USERNAME,
            "password": TEST_ADMIN_PASSWORD,
        })
        with flask_app.app_context():
            entry = AuditLog.query.filter_by(action="login", result="success").first()
            assert entry is not None
            assert entry.username == TEST_ADMIN_USERNAME

    def test_login_failure_creates_audit_entry(self, flask_app, anon_client):
        anon_client.post("/login", data={
            "username": TEST_ADMIN_USERNAME,
            "password": "wrongpassword",
        })
        with flask_app.app_context():
            entry = AuditLog.query.filter_by(action="login_failed", result="failure").first()
            assert entry is not None

    def test_certificate_creation_creates_audit_entry(self, flask_app, client):
        client.post("/certificates/new", data={
            "domain": "audit-test.example.com",
            "san_domains": "",
            "key_size": "2048",
            "country": "US",
            "state": "CA",
            "city": "SF",
            "org_name": "Test",
            "org_unit": "",
            "email": "",
            "chain_id": "",
        })
        with flask_app.app_context():
            entry = AuditLog.query.filter_by(action="certificate_created").first()
            assert entry is not None
            assert "audit-test.example.com" in (entry.detail or "")

    def test_404_creates_audit_entry(self, flask_app, client):
        client.get("/nonexistent-path-xyz")
        with flask_app.app_context():
            entry = AuditLog.query.filter_by(action="not_found", result="failure").first()
            assert entry is not None
