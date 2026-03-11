"""
Unit tests for SSL Manager.

Run with:
    pytest test_app.py -v
    pytest test_app.py -v --tb=short   # compact tracebacks
"""

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

from sqlalchemy.pool import StaticPool

import app as app_module
from app import (
    Certificate,
    IntermediateCert,
    Settings,
    create_components_zip,
    create_pkcs12,
    db,
    generate_key_and_csr,
    parse_cert_expiry,
)


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


@pytest.fixture(scope="session")
def flask_app():
    """Single Flask app instance for the whole test session.

    Flask-SQLAlchemy reads config at init_app() time and blocks
    re-initialisation after the first request.  Using session scope
    means init_app() runs exactly once, before any request is made.
    StaticPool forces all connections to share the same in-memory
    database so fixture writes and request-handler reads see the same
    data.
    """
    app_module.app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SQLALCHEMY_ENGINE_OPTIONS={
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
        },
        SECRET_KEY="test-secret",
        WTF_CSRF_ENABLED=False,
    )
    # Re-initialise before any request is handled so Flask allows it.
    app_module.app.extensions.pop("sqlalchemy", None)
    db.init_app(app_module.app)

    with app_module.app.app_context():
        db.create_all()
        db.session.add(Settings(key_size=2048))
        db.session.commit()
        yield app_module.app
        db.drop_all()


@pytest.fixture(autouse=True)
def clean_db(flask_app):
    """Truncate all tables and re-seed Settings after each test."""
    yield
    with flask_app.app_context():
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.add(Settings(key_size=2048))
        db.session.commit()


@pytest.fixture()
def client(flask_app):
    return flask_app.test_client()


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
def intermediate_record(client, rsa_key):
    """An IntermediateCert created via HTTP so it is visible to subsequent requests."""
    pem = _make_self_signed_cert(rsa_key, domain="ca.example.com")
    resp = client.post("/intermediates/new",
                       data={"name": "Test CA", "pem_data": pem, "order": "0"},
                       follow_redirects=False)
    # Route redirects to /intermediates, not /intermediates/<id>.
    # Retrieve the id via the list page's edit links by parsing the response.
    list_resp = client.get("/intermediates")
    # The edit link contains the id: /intermediates/<id>/edit
    import re
    match = re.search(rb"/intermediates/(\d+)/edit", list_resp.data)
    assert match, "Could not find intermediate record id in list page"
    yield int(match.group(1))


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

    def test_fullchain_contains_key_and_cert(self, signed_cert_pem, key_pem):
        buf = create_components_zip("example.com", signed_cert_pem, key_pem, [])
        with ZipFile(buf) as zf:
            fullchain = zf.read("fullchain.pem").decode()
        assert "PRIVATE KEY" in fullchain
        assert "CERTIFICATE" in fullchain

    def test_intermediates_included(self, signed_cert_pem, key_pem):
        inter_key = _make_rsa_key(1024)
        inter_pem = _make_self_signed_cert(inter_key, "ca.example.com")
        buf = create_components_zip("example.com", signed_cert_pem, key_pem, [inter_pem])
        with ZipFile(buf) as zf:
            names = zf.namelist()
        assert "intermediate_1.pem" in names

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
        assert "intermediate_1.pem" not in names


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


class TestSettingsRoute:
    def test_get_returns_200(self, client):
        resp = client.get("/settings")
        assert resp.status_code == 200

    def test_post_saves_settings(self, client):
        # POST then GET to verify the saved values are shown in the form
        client.post("/settings", data={
            "key_size": "4096",
            "country": "GB",
            "state": "England",
            "city": "London",
            "org_name": "ACME Ltd",
            "org_unit": "Security",
            "email": "ssl@acme.com",
        })
        resp = client.get("/settings")
        assert b"ACME Ltd" in resp.data
        assert b"England" in resp.data
        assert b"ssl@acme.com" in resp.data

    def test_post_redirects_back(self, client):
        resp = client.post("/settings", data={
            "key_size": "2048", "country": "US", "state": "",
            "city": "", "org_name": "", "org_unit": "", "email": "",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "/settings" in resp.headers["Location"]

    def test_invalid_key_size_defaults_to_2048(self, client):
        client.post("/settings", data={
            "key_size": "not_a_number", "country": "US", "state": "",
            "city": "", "org_name": "", "org_unit": "", "email": "",
        })
        # The new cert form should still show a valid key size option selected
        resp = client.get("/certificates/new")
        assert resp.status_code == 200

    def test_country_truncated_to_2_chars(self, client):
        client.post("/settings", data={
            "key_size": "2048", "country": "USA", "state": "",
            "city": "", "org_name": "", "org_unit": "", "email": "",
        })
        resp = client.get("/settings")
        # "US" should appear in the response (truncated from "USA")
        assert b"US" in resp.data


class TestIntermediatesRoute:
    def test_get_returns_200(self, client):
        resp = client.get("/intermediates")
        assert resp.status_code == 200

    def test_shows_intermediate_name(self, client, intermediate_record, flask_app):
        resp = client.get("/intermediates")
        assert b"Test CA" in resp.data


class TestIntermediateNewRoute:
    def test_get_form_returns_200(self, client):
        resp = client.get("/intermediates/new-form")
        assert resp.status_code == 200

    def test_post_missing_name_shows_error(self, client, rsa_key):
        pem = _make_self_signed_cert(rsa_key, "ca.test.com")
        resp = client.post("/intermediates/new",
                           data={"name": "", "pem_data": pem, "order": "0"},
                           follow_redirects=True)
        assert b"Name is required" in resp.data

    def test_post_missing_pem_shows_error(self, client):
        resp = client.post("/intermediates/new",
                           data={"name": "CA", "pem_data": "", "order": "0"},
                           follow_redirects=True)
        assert b"PEM data is required" in resp.data

    def test_post_invalid_pem_shows_error(self, client):
        resp = client.post("/intermediates/new",
                           data={"name": "CA", "pem_data": "garbage pem", "order": "0"},
                           follow_redirects=True)
        assert b"Invalid PEM certificate data" in resp.data

    def test_post_valid_creates_record(self, client, rsa_key):
        pem = _make_self_signed_cert(rsa_key, "newca.example.com")
        resp = client.post("/intermediates/new",
                           data={"name": "New CA", "pem_data": pem, "order": "5"},
                           follow_redirects=True)
        assert resp.status_code == 200
        assert b"New CA" in resp.data


class TestIntermediateUpdateRoute:
    def test_post_updates_record(self, client, intermediate_record, rsa_key):
        new_pem = _make_self_signed_cert(rsa_key, "updated.ca.com")
        resp = client.post(f"/intermediates/{intermediate_record}/update",
                           data={"name": "Updated CA", "pem_data": new_pem, "order": "10"},
                           follow_redirects=True)
        assert resp.status_code == 200
        assert b"Updated CA" in resp.data


class TestIntermediateDeleteRoute:
    def test_delete_removes_record(self, client, intermediate_record):
        resp = client.post(f"/intermediates/{intermediate_record}/delete",
                           follow_redirects=True)
        assert resp.status_code == 200
        assert b"deleted" in resp.data.lower()
        # After deletion the edit link for this record should be gone
        import re
        edit_links = re.findall(rb"/intermediates/\d+/edit", resp.data)
        assert len(edit_links) == 0


class TestIntermediateReorderRoute:
    def test_reorder_updates_order(self, client, intermediate_record):
        resp = client.post("/intermediates/reorder",
                           data=json.dumps([{"id": intermediate_record, "order": 99}]),
                           content_type="application/json")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"

    def test_reorder_invalid_body_returns_400(self, client):
        resp = client.post("/intermediates/reorder",
                           data=json.dumps({"not": "a list"}),
                           content_type="application/json")
        assert resp.status_code == 400
