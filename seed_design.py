#!/usr/bin/env python3
# ==============================================================================
# FILE:           seed_design.py
# DESCRIPTION:    Populates the SSL Manager database with realistic design seed
#                 data covering every UI state, visual component, user role,
#                 certificate status, and audit log action type.
#
#                 Intended for designer workflow via Docker Compose.
#                 All cryptographic keys use 1024 bits for fast generation —
#                 never use this data in production.
#
# USAGE:
#   # Via Docker Compose design overlay (recommended):
#   docker compose -f docker-compose.yml -f docker-compose.design.yml up --build
#
#   # Manual (inside the running container or local venv):
#   python seed_design.py            # only seeds if database is empty
#   python seed_design.py --force    # wipe all data first, then seed
#
# CREDENTIALS (after seeding):
#   designer  /  design123   — superadmin
#   alice     /  design123   — regular user
#   bob       /  design123   — inactive account (cannot log in)
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app import create_app
from app.crypto import generate_ca_key_and_cert, generate_key_and_csr, sign_csr_with_ca
from app.extensions import db
from app.models import (
    AuditLog, Certificate, CertChain, CertificateAuthority,
    IntermediateCert, Settings, User,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEY_SIZE = 1024          # Small keys so seeding completes in seconds
NOW      = datetime.now(timezone.utc)
PASSWORD = "design123"   # Shared password for all seed accounts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dt(days):
    """Timezone-naive UTC datetime offset from now by *days* days."""
    return (NOW + timedelta(days=days)).replace(tzinfo=None)


def _make_signed_cert(ca_key_pem, ca_cert_pem, domain, san_list,
                      country="US", state="California", city="San Francisco",
                      org="Acme Corp", ou="IT", email="ssl@acme.com",
                      validity_days=365):
    """Generate a key+CSR and sign it with the given CA. Returns (key_pem, csr_pem, signed_pem)."""
    key_pem, csr_pem = generate_key_and_csr(
        domain, san_list, KEY_SIZE, country, state, city, org, ou, email,
    )
    signed_pem = sign_csr_with_ca(csr_pem, ca_cert_pem, ca_key_pem, validity_days=validity_days)
    return key_pem, csr_pem, signed_pem


def _add_cert(session, **kwargs):
    c = Certificate(**kwargs)
    session.add(c)
    session.flush()
    return c


def _log(session, action, resource_type=None, resource_id=None, result="success",
         detail=None, username="designer", user_id=None, ip="203.0.113.10", days_ago=0):
    ts = (NOW - timedelta(days=days_ago)).replace(tzinfo=None)
    entry = AuditLog(
        username=username,
        user_id=user_id,
        ip_address=ip,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        detail=(detail or "")[:512],
    )
    entry.timestamp = ts
    session.add(entry)


# ---------------------------------------------------------------------------
# Seed
# ---------------------------------------------------------------------------

def seed(force=False):
    app = create_app()
    with app.app_context():

        if User.query.count() > 0 and not force:
            print("Database already contains user data.")
            print("Run with --force to wipe and re-seed.")
            return

        # Wipe all tables (handles both fresh DBs that have a default Settings
        # row from create_app, and existing seeded databases when --force is used)
        print("Clearing existing data…")
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()

        print("Seeding design data  (1024-bit keys — NOT for production)…")

        # -------------------------------------------------------------------
        # Users
        # -------------------------------------------------------------------
        print("  users…")

        designer = User(username="designer", email="designer@acme.com", role="superadmin")
        designer.set_password(PASSWORD)

        alice = User(username="alice", email="alice@acme.com", role="user")
        alice.set_password(PASSWORD)

        bob = User(username="bob", email="bob@acme.com", role="user", active=False)
        bob.set_password(PASSWORD)

        db.session.add_all([designer, alice, bob])
        db.session.flush()

        d_id = designer.id
        a_id = alice.id
        b_id = bob.id

        # -------------------------------------------------------------------
        # Profiles
        # -------------------------------------------------------------------
        print("  profiles…")

        p_us = Settings(
            name="Acme Corp — US", is_default=True, key_size=2048,
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="IT", email="ssl@acme.com",
        )
        p_eu = Settings(
            name="EU Subsidiary", is_default=False, key_size=4096,
            country="DE", state="Bavaria", city="Munich",
            org_name="Acme GmbH", org_unit="Operations", email="ssl@acme.de",
        )
        p_infra = Settings(
            name="Internal Services", is_default=False, key_size=2048,
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="Infrastructure", email="infra@acme.com",
        )
        db.session.add_all([p_us, p_eu, p_infra])
        db.session.flush()

        # -------------------------------------------------------------------
        # Internal Certificate Authorities — one per expiry-badge colour
        #   > 365 days  → success (green)
        #   90–365 days → info (blue)
        #   30–90 days  → warning (yellow)
        #   < 30 days   → danger (red)
        # -------------------------------------------------------------------
        print("  certificate authorities  (generating keys — a few seconds)…")

        root_key, root_cert = generate_ca_key_and_cert(
            "Acme Internal Root CA", KEY_SIZE, 3650,
            "US", "California", "San Francisco", "Acme Corp", "IT", "ssl@acme.com",
        )
        ca_root = CertificateAuthority(
            name="Acme Internal Root CA",
            description="Primary internal root CA for signing internal services and lab certificates.",
            key_size=KEY_SIZE, private_key_pem=root_key, cert_pem=root_cert,
        )

        dev_key, dev_cert = generate_ca_key_and_cert(
            "Dev Testing CA", KEY_SIZE, 200,
            "US", "California", "San Francisco", "Acme Corp", "Engineering", "dev@acme.com",
        )
        ca_dev = CertificateAuthority(
            name="Dev Testing CA",
            description="Development and staging use only. Expires in ~200 days.",
            key_size=KEY_SIZE, private_key_pem=dev_key, cert_pem=dev_cert,
        )

        stg_key, stg_cert = generate_ca_key_and_cert(
            "Staging CA", KEY_SIZE, 60,
            "US", "California", "San Francisco", "Acme Corp", "DevOps", "devops@acme.com",
        )
        ca_staging = CertificateAuthority(
            name="Staging CA",
            description="Staging environment CA — renewal required within 90 days.",
            key_size=KEY_SIZE, private_key_pem=stg_key, cert_pem=stg_cert,
        )

        lab_key, lab_cert = generate_ca_key_and_cert(
            "Lab CA (Expiring)", KEY_SIZE, 10,
            "US", "California", "San Francisco", "Acme Corp", "Labs", "labs@acme.com",
        )
        ca_lab = CertificateAuthority(
            name="Lab CA (Expiring)",
            description="Lab CA — critical: expires in 10 days. Replace immediately.",
            key_size=KEY_SIZE, private_key_pem=lab_key, cert_pem=lab_cert,
        )

        db.session.add_all([ca_root, ca_dev, ca_staging, ca_lab])
        db.session.flush()

        # -------------------------------------------------------------------
        # Certificate Chains — real PEMs so parsed_cert works in the UI
        # -------------------------------------------------------------------
        print("  chains…")

        # Chain 1: DigiCert (2 intermediates)
        chain_dc = CertChain(
            name="DigiCert 2024",
            description="DigiCert TLS RSA SHA256 2020 CA1 intermediate chain.",
        )
        db.session.add(chain_dc)
        db.session.flush()

        _, dc_int1 = generate_ca_key_and_cert(
            "DigiCert TLS RSA SHA256 2020 CA1", KEY_SIZE, 3650, "US", "", "", "DigiCert Inc", "", "",
        )
        _, dc_root = generate_ca_key_and_cert(
            "DigiCert Global Root CA", KEY_SIZE, 7300, "US", "", "", "DigiCert Inc", "", "",
        )
        db.session.add(IntermediateCert(
            name="DigiCert TLS RSA SHA256 2020 CA1",
            pem_data=dc_int1, order=1, chain_id=chain_dc.id,
        ))
        db.session.add(IntermediateCert(
            name="DigiCert Global Root CA",
            pem_data=dc_root, order=2, chain_id=chain_dc.id,
        ))

        # Chain 2: Let's Encrypt (1 intermediate)
        chain_le = CertChain(
            name="Let's Encrypt R11",
            description="Let's Encrypt R11 intermediate.",
        )
        db.session.add(chain_le)
        db.session.flush()

        _, le_int = generate_ca_key_and_cert(
            "Let's Encrypt R11", KEY_SIZE, 1825, "US", "", "", "Let's Encrypt", "", "",
        )
        db.session.add(IntermediateCert(
            name="Let's Encrypt R11",
            pem_data=le_int, order=1, chain_id=chain_le.id,
        ))

        # Chain 3: Internal — uses the root CA cert as trust anchor
        chain_internal = CertChain(
            name="Internal Root CA",
            description="Trust anchor for certificates signed by the Acme Internal Root CA.",
        )
        db.session.add(chain_internal)
        db.session.flush()

        db.session.add(IntermediateCert(
            name="Acme Internal Root CA",
            pem_data=root_cert, order=1, chain_id=chain_internal.id,
        ))

        db.session.flush()

        # -------------------------------------------------------------------
        # Certificates — every visual state enumerated
        # -------------------------------------------------------------------
        print("  certificates…")

        # 1. Active — green (> 90 days), multi-SAN, DigiCert chain
        k, csr, sig = _make_signed_cert(root_key, root_cert, "www.acme.com",
                                        ["api.acme.com", "acme.com"])
        c1 = _add_cert(db.session,
            domain="www.acme.com",
            san_domains=json.dumps(["api.acme.com", "acme.com"]),
            key_size=2048, private_key_pem=k, csr_pem=csr, signed_cert_pem=sig,
            status="active", expiry_date=_dt(200),
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="IT", email="ssl@acme.com",
            chain_id=chain_dc.id, profile_id=p_us.id,
        )

        # 2. Active — yellow (30–90 days), DigiCert chain
        k, csr, sig = _make_signed_cert(root_key, root_cert, "api.acme.com", [])
        c2 = _add_cert(db.session,
            domain="api.acme.com", san_domains="[]", key_size=2048,
            private_key_pem=k, csr_pem=csr, signed_cert_pem=sig,
            status="active", expiry_date=_dt(55),
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="Engineering", email="ssl@acme.com",
            chain_id=chain_dc.id, profile_id=p_us.id,
        )

        # 3. Active — red (< 30 days), DigiCert chain
        k, csr, sig = _make_signed_cert(root_key, root_cert, "shop.acme.com", [])
        c3 = _add_cert(db.session,
            domain="shop.acme.com", san_domains="[]", key_size=2048,
            private_key_pem=k, csr_pem=csr, signed_cert_pem=sig,
            status="active", expiry_date=_dt(18),
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="E-Commerce", email="ssl@acme.com",
            chain_id=chain_dc.id, profile_id=p_us.id,
        )

        # 4. Active — critical red (< 7 days)
        k, csr, sig = _make_signed_cert(root_key, root_cert, "portal.acme.com", [])
        c4 = _add_cert(db.session,
            domain="portal.acme.com", san_domains="[]", key_size=2048,
            private_key_pem=k, csr_pem=csr, signed_cert_pem=sig,
            status="active", expiry_date=_dt(5),
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="Customer Portal", email="ssl@acme.com",
            chain_id=chain_le.id, profile_id=p_us.id,
        )

        # 5. Active — expired (status_label shows "expired"), DigiCert chain
        k, csr, sig = _make_signed_cert(root_key, root_cert, "legacy.acme.com", [])
        c5 = _add_cert(db.session,
            domain="legacy.acme.com", san_domains="[]", key_size=2048,
            private_key_pem=k, csr_pem=csr, signed_cert_pem=sig,
            status="active", expiry_date=_dt(-45),
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="IT", email="ssl@acme.com",
            chain_id=chain_dc.id, profile_id=p_us.id,
        )

        # 6. Active — wildcard, green (> 365 days), Let's Encrypt chain, 4096-bit
        k, csr, sig = _make_signed_cert(root_key, root_cert, "*.acme.com", [])
        c6 = _add_cert(db.session,
            domain="*.acme.com", san_domains="[]", key_size=4096,
            private_key_pem=k, csr_pem=csr, signed_cert_pem=sig,
            status="active", expiry_date=_dt(340),
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="IT", email="ssl@acme.com",
            chain_id=chain_le.id, profile_id=p_us.id,
        )

        # 7. Active — many SANs (VPN), green, DigiCert chain
        k, csr, sig = _make_signed_cert(
            root_key, root_cert, "vpn.acme.com",
            ["vpn1.acme.com", "vpn2.acme.com", "vpn3.acme.com", "gateway.acme.com"],
        )
        c7 = _add_cert(db.session,
            domain="vpn.acme.com",
            san_domains=json.dumps(["vpn1.acme.com", "vpn2.acme.com",
                                    "vpn3.acme.com", "gateway.acme.com"]),
            key_size=2048, private_key_pem=k, csr_pem=csr, signed_cert_pem=sig,
            status="active", expiry_date=_dt(180),
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="Network", email="ssl@acme.com",
            chain_id=chain_dc.id, profile_id=p_us.id,
        )

        # 8. Active — signed by internal CA, internal chain, green
        k, csr, sig = _make_signed_cert(root_key, root_cert, "internal.acme.com", [],
                                        ou="Infrastructure", email="infra@acme.com")
        c8 = _add_cert(db.session,
            domain="internal.acme.com", san_domains="[]", key_size=2048,
            private_key_pem=k, csr_pem=csr, signed_cert_pem=sig,
            status="active", expiry_date=_dt(365),
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="Infrastructure", email="infra@acme.com",
            chain_id=chain_internal.id, profile_id=p_infra.id,
        )

        # 9. Active — EU subsidiary, Let's Encrypt chain, yellow (30–90 days)
        k, csr, sig = _make_signed_cert(
            root_key, root_cert, "acme.de", [],
            country="DE", state="Bavaria", city="Munich",
            org="Acme GmbH", ou="Operations", email="ssl@acme.de",
        )
        c9 = _add_cert(db.session,
            domain="acme.de", san_domains="[]", key_size=4096,
            private_key_pem=k, csr_pem=csr, signed_cert_pem=sig,
            status="active", expiry_date=_dt(70),
            country="DE", state="Bavaria", city="Munich",
            org_name="Acme GmbH", org_unit="Operations", email="ssl@acme.de",
            chain_id=chain_le.id, profile_id=p_eu.id,
        )

        # 10. Active — no chain assigned, green
        k, csr, sig = _make_signed_cert(root_key, root_cert, "mail.acme.com", [])
        c10 = _add_cert(db.session,
            domain="mail.acme.com", san_domains="[]", key_size=2048,
            private_key_pem=k, csr_pem=csr, signed_cert_pem=sig,
            status="active", expiry_date=_dt(120),
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="IT", email="ssl@acme.com",
            profile_id=p_us.id,
        )

        # 11. Pending signing — created via New Certificate, has private key, chain assigned
        k, csr = generate_key_and_csr(
            "new.acme.com", [], KEY_SIZE,
            "US", "California", "San Francisco", "Acme Corp", "IT", "ssl@acme.com",
        )
        c11 = _add_cert(db.session,
            domain="new.acme.com", san_domains="[]", key_size=2048,
            private_key_pem=k, csr_pem=csr,
            status="pending_signing",
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="IT", email="ssl@acme.com",
            chain_id=chain_dc.id, profile_id=p_us.id,
        )

        # 12. Pending signing — has private key, multi-SAN, no chain assigned yet
        k, csr = generate_key_and_csr(
            "beta.acme.com", ["staging.acme.com", "test.acme.com"], KEY_SIZE,
            "US", "California", "San Francisco", "Acme Corp", "Engineering", "dev@acme.com",
        )
        c12 = _add_cert(db.session,
            domain="beta.acme.com",
            san_domains=json.dumps(["staging.acme.com", "test.acme.com"]),
            key_size=2048, private_key_pem=k, csr_pem=csr,
            status="pending_signing",
            country="US", state="California", city="San Francisco",
            org_name="Acme Corp", org_unit="Engineering", email="dev@acme.com",
            profile_id=p_us.id,
        )

        # 13. CSR import — pending signing, no private key stored (e.g. Cisco ISE)
        #     Multi-SAN to show that the device embedded SANs in the CSR
        _, csr_import1 = generate_key_and_csr(
            "ise.acme.internal",
            ["ise-psn1.acme.internal", "ise-psn2.acme.internal"], KEY_SIZE,
            "US", "California", "San Jose", "Acme Corp", "Network", "noc@acme.com",
        )
        c13 = _add_cert(db.session,
            domain="ise.acme.internal", san_domains="[]",
            key_size=0, csr_pem=csr_import1,
            status="pending_signing",
            chain_id=chain_internal.id,
        )

        # 14. CSR import — signed by internal CA, active, NO private key stored
        #     Downloads section shows the restricted-format warning
        _, csr_import2 = generate_key_and_csr(
            "fw.acme.internal", [], KEY_SIZE,
            "US", "California", "San Francisco", "Acme Corp", "Network", "noc@acme.com",
        )
        sig_import2 = sign_csr_with_ca(csr_import2, root_cert, root_key, validity_days=365)
        c14 = _add_cert(db.session,
            domain="fw.acme.internal", san_domains="[]",
            key_size=0, csr_pem=csr_import2, signed_cert_pem=sig_import2,
            status="active", expiry_date=_dt(365),
            chain_id=chain_internal.id,
        )

        db.session.flush()

        # -------------------------------------------------------------------
        # Audit Log — every action type, both results, multiple users/IPs
        # -------------------------------------------------------------------
        print("  audit log entries…")

        # Shorthand: pre-bind session
        L = lambda *a, **kw: _log(db.session, *a, **kw)  # noqa: E731

        # ── First-run setup ─────────────────────────────────────────────────
        L("setup_failed", result="failure",
          detail="Password must be at least 8 characters.",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=30)
        L("setup_failed", result="failure",
          detail="Passwords do not match.",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=30)
        L("setup", "user", d_id, "success",
          "superadmin created: designer",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=30)

        # ── Login / logout ───────────────────────────────────────────────────
        L("login_failed", "user", None, "failure",
          "username='admin'",
          username=None, user_id=None, ip="198.51.100.5", days_ago=29)
        L("login_failed", "user", None, "failure",
          "username='administrator'",
          username=None, user_id=None, ip="198.51.100.7", days_ago=28)
        L("login", "user", d_id, "success",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=27)
        L("login", "user", a_id, "success",
          username="alice", user_id=a_id, ip="203.0.113.15", days_ago=25)
        L("logout", "user", a_id, "success",
          username="alice", user_id=a_id, ip="203.0.113.15", days_ago=25)
        L("login", "user", d_id, "success",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=20)
        L("logout", "user", d_id, "success",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=20)
        L("login", "user", a_id, "success",
          username="alice", user_id=a_id, ip="203.0.113.15", days_ago=15)
        L("login_failed", "user", None, "failure",
          "username='bob'",
          username=None, user_id=None, ip="10.0.0.22", days_ago=12)
        L("logout", "user", d_id, "success",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=1)

        # ── User management ──────────────────────────────────────────────────
        L("user_created", "user", a_id, "success",
          "username='alice' role=user",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=29)
        L("user_created", "user", b_id, "success",
          "username='bob' role=user",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=29)
        L("user_updated", "user", a_id, "success",
          "email updated",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=14)
        L("user_updated", "user", b_id, "success",
          "account deactivated",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=10)
        L("user_deleted", "user", 99, "success",
          "username='contractor1' deleted",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=5)

        # ── Profile management ───────────────────────────────────────────────
        L("profile_created", "settings", p_us.id, "success",
          "name='Acme Corp — US'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=29)
        L("profile_created", "settings", p_eu.id, "success",
          "name='EU Subsidiary'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=29)
        L("profile_created", "settings", p_infra.id, "success",
          "name='Internal Services'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=28)
        L("profile_updated", "settings", p_us.id, "success",
          "name='Acme Corp — US' key_size updated to 4096",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=14)
        L("profile_deleted", "settings", 99, "success",
          "name='Old Profile' deleted",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=3)

        # ── Chain management ─────────────────────────────────────────────────
        L("chain_created", "cert_chain", chain_dc.id, "success",
          "name='DigiCert 2024'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=28)
        L("chain_created", "cert_chain", chain_le.id, "success",
          "name='Let's Encrypt R11'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=28)
        L("chain_created", "cert_chain", chain_internal.id, "success",
          "name='Internal Root CA'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=27)
        L("chain_updated", "cert_chain", chain_dc.id, "success",
          "intermediate order updated",
          username="alice", user_id=a_id, ip="203.0.113.15", days_ago=20)
        L("chain_deleted", "cert_chain", 99, "success",
          "name='Old Chain' deleted",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=4)

        # ── CA management ────────────────────────────────────────────────────
        L("ca_created", "ca", ca_root.id, "success",
          "CA 'Acme Internal Root CA' created",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=27)
        L("ca_created", "ca", ca_dev.id, "success",
          "CA 'Dev Testing CA' created",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=27)
        L("ca_created", "ca", ca_staging.id, "success",
          "CA 'Staging CA' created",
          username="alice", user_id=a_id, ip="203.0.113.15", days_ago=26)
        L("ca_created", "ca", ca_lab.id, "success",
          "CA 'Lab CA (Expiring)' created",
          username="alice", user_id=a_id, ip="203.0.113.15", days_ago=26)
        L("ca_download", "ca", ca_root.id, "success",
          "CA cert downloaded for 'Acme Internal Root CA'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=26)
        L("ca_download", "ca", ca_dev.id, "success",
          "CA cert downloaded for 'Dev Testing CA'",
          username="alice", user_id=a_id, ip="203.0.113.15", days_ago=15)
        L("ca_delete", "ca", 99, "success",
          "CA 'Legacy Lab CA' deleted",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=5)

        # ── Certificate creation ─────────────────────────────────────────────
        for cert, domain, days_ago, uid, uname, ip in [
            (c1,  "www.acme.com",      25, d_id, "designer", "203.0.113.10"),
            (c2,  "api.acme.com",      24, d_id, "designer", "203.0.113.10"),
            (c3,  "shop.acme.com",     23, d_id, "designer", "203.0.113.10"),
            (c4,  "portal.acme.com",  350, d_id, "designer", "203.0.113.10"),
            (c5,  "legacy.acme.com",  400, d_id, "designer", "203.0.113.10"),
            (c6,  "*.acme.com",        22, d_id, "designer", "203.0.113.10"),
            (c7,  "vpn.acme.com",      20, a_id, "alice",    "203.0.113.15"),
            (c8,  "internal.acme.com", 15, a_id, "alice",    "203.0.113.15"),
            (c9,  "acme.de",           14, d_id, "designer", "203.0.113.10"),
            (c10, "mail.acme.com",     13, a_id, "alice",    "203.0.113.15"),
            (c11, "new.acme.com",       2, d_id, "designer", "203.0.113.10"),
            (c12, "beta.acme.com",      1, a_id, "alice",    "203.0.113.15"),
        ]:
            L("certificate_created", "certificate", cert.id, "success",
              f"domain={domain!r}",
              username=uname, user_id=uid, ip=ip, days_ago=days_ago)

        # ── Certificate signing (external CA — upload) ────────────────────────
        for cert, domain, days_ago, uid, uname, ip in [
            (c1,  "www.acme.com",      25, d_id, "designer", "203.0.113.10"),
            (c2,  "api.acme.com",      24, d_id, "designer", "203.0.113.10"),
            (c3,  "shop.acme.com",     23, d_id, "designer", "203.0.113.10"),
            (c4,  "portal.acme.com",  350, d_id, "designer", "203.0.113.10"),
            (c5,  "legacy.acme.com",  400, d_id, "designer", "203.0.113.10"),
            (c6,  "*.acme.com",        22, d_id, "designer", "203.0.113.10"),
            (c7,  "vpn.acme.com",      20, a_id, "alice",    "203.0.113.15"),
            (c9,  "acme.de",           14, d_id, "designer", "203.0.113.10"),
            (c10, "mail.acme.com",     13, a_id, "alice",    "203.0.113.15"),
        ]:
            L("certificate_signed", "certificate", cert.id, "success",
              f"domain={domain!r}",
              username=uname, user_id=uid, ip=ip, days_ago=days_ago)

        # ── Certificate signing (internal CA) ────────────────────────────────
        L("cert_sign", "certificate", c8.id, "success",
          "Signed by CA 'Acme Internal Root CA', valid 365 days",
          username="alice", user_id=a_id, ip="203.0.113.15", days_ago=15)
        L("cert_sign", "certificate", c14.id, "success",
          "Signed by CA 'Acme Internal Root CA', valid 365 days",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=8)
        # Signing failure
        L("cert_sign", "certificate", c11.id, "failure",
          "CSR signature is invalid.",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=2)

        # ── CSR import ───────────────────────────────────────────────────────
        L("csr_import", "certificate", c13.id, "success",
          "domain='ise.acme.internal'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=3)
        L("csr_import", "certificate", c14.id, "success",
          "domain='fw.acme.internal'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=8)

        # ── Certificate deletion ──────────────────────────────────────────────
        L("certificate_deleted", "certificate", 99, "success",
          "domain='old.acme.com'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=10)

        # ── Downloads — every format ──────────────────────────────────────────
        L("download_csr", "certificate", c1.id, "success",
          "domain='www.acme.com'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=25)
        L("download_fullchain", "certificate", c1.id, "success",
          "domain='www.acme.com'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=24)
        L("download_components", "certificate", c1.id, "success",
          "domain='www.acme.com'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=24)
        L("download_pkcs12", "certificate", c1.id, "success",
          "domain='www.acme.com'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=24)
        L("download_jks", "certificate", c7.id, "success",
          "domain='vpn.acme.com'",
          username="alice", user_id=a_id, ip="203.0.113.15", days_ago=19)
        L("download_p7b", "certificate", c6.id, "success",
          "domain='*.acme.com'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=22)
        L("download_der", "certificate", c9.id, "success",
          "domain='acme.de'",
          username="alice", user_id=a_id, ip="203.0.113.15", days_ago=13)
        L("download_cert_pem", "certificate", c14.id, "success",
          "domain='fw.acme.internal'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=7)
        L("download_csr", "certificate", c13.id, "success",
          "domain='ise.acme.internal'",
          username="designer", user_id=d_id, ip="203.0.113.10", days_ago=3)

        # ── Security events ───────────────────────────────────────────────────
        L("csrf_failure", result="failure",
          detail="endpoint=certificates.certificate_new method=POST",
          username="designer", user_id=d_id, ip="198.51.100.22", days_ago=12)
        L("csrf_failure", result="failure",
          detail="endpoint=certificates.certificate_delete method=POST",
          username=None, user_id=None, ip="198.51.100.50", days_ago=6)
        L("not_found", result="failure",
          detail="path='/admin'",
          username=None, user_id=None, ip="198.51.100.5", days_ago=18)
        L("not_found", result="failure",
          detail="path='/wp-login.php'",
          username=None, user_id=None, ip="198.51.100.99", days_ago=7)
        L("not_found", result="failure",
          detail="path='/.env'",
          username=None, user_id=None, ip="203.0.113.200", days_ago=3)
        L("forbidden", result="failure",
          detail="path='/users'",
          username="alice", user_id=a_id, ip="203.0.113.15", days_ago=20)

        # ── Backups — system-generated, one per day for the past 4 weeks ─────
        for days_ago in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 21, 28]:
            date_str = (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%d_%H%M%S")
            size_k = 48 + (days_ago % 7) * 6
            L("backup", "database", None, "success",
              f"file=ssl_manager_{date_str}.db.gz size={size_k}K days=7 pruned=0",
              username="system", user_id=None, ip="127.0.0.1", days_ago=days_ago)

        # One backup failure for visual completeness
        L("backup", "database", None, "failure",
          "sqlite3 error: database is locked",
          username="system", user_id=None, ip="127.0.0.1", days_ago=17)

        db.session.commit()

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    print("  Seed complete.")
    print()
    print("  Credentials")
    print("  ───────────────────────────────────────")
    print("  designer  /  design123   superadmin")
    print("  alice     /  design123   regular user")
    print("  bob       /  design123   inactive (cannot log in)")
    print()
    print("  Open http://localhost:5001 in your browser.")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Seed the SSL Manager database with design data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python seed_design.py              # seed if database is empty\n"
            "  python seed_design.py --force      # wipe all data and re-seed\n"
        ),
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Wipe all existing data before seeding.",
    )
    args = parser.parse_args()
    seed(force=args.force)