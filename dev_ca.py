#!/usr/bin/env python3
"""
Local development CA for testing ssl-manager.

Commands:
  python dev_ca.py init              — create a local root CA (ca.key + ca.crt)
  python dev_ca.py sign <csr_file>   — sign a CSR and print the signed cert PEM
  python dev_ca.py info              — show CA cert details
  python dev_ca.py chain             — print the CA cert PEM (for the Chain Certificates page)

Files created in ./dev-ca/:
  ca.key   — CA private key  (keep this safe, even for dev)
  ca.crt   — CA certificate  (self-signed root)
  signed/  — each signed cert saved here as <domain>.crt
"""

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CA_DIR = Path(__file__).parent / "dev-ca"
CA_KEY_PATH = CA_DIR / "ca.key"
CA_CRT_PATH = CA_DIR / "ca.crt"
SIGNED_DIR = CA_DIR / "signed"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_ca():
    if not CA_KEY_PATH.exists() or not CA_CRT_PATH.exists():
        sys.exit("CA not initialised. Run:  python dev_ca.py init")
    key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(CA_CRT_PATH.read_bytes())
    return key, cert


def _pem(obj) -> str:
    if hasattr(obj, "public_bytes"):
        return obj.public_bytes(serialization.Encoding.PEM).decode()
    raise TypeError(f"Cannot serialise {type(obj)}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args):
    if CA_KEY_PATH.exists() and not args.force:
        sys.exit(
            "CA already exists. Use --force to overwrite.\n"
            f"  {CA_KEY_PATH}\n  {CA_CRT_PATH}"
        )

    CA_DIR.mkdir(parents=True, exist_ok=True)
    SIGNED_DIR.mkdir(exist_ok=True)

    print("Generating CA key (2048-bit RSA)…")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Dev"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Dev CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Local Dev Root CA"),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))  # 10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    CA_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    CA_CRT_PATH.write_bytes(_pem(cert).encode())

    print(f"CA key  → {CA_KEY_PATH}")
    print(f"CA cert → {CA_CRT_PATH}")
    print()
    print("Next steps:")
    print("  1. In ssl-manager, go to Chain Certificates → Add, paste the output of:")
    print("       python dev_ca.py chain")
    print("  2. Download a CSR from the Certificates page")
    print("  3. Sign it:  python dev_ca.py sign <file.csr>")
    print("  4. Paste the printed PEM into the Upload section for that domain")


def cmd_sign(args):
    ca_key, ca_cert = _load_ca()

    csr_path = Path(args.csr)
    if not csr_path.exists():
        sys.exit(f"CSR file not found: {csr_path}")

    csr = x509.load_pem_x509_csr(csr_path.read_bytes())
    if not csr.is_signature_valid:
        sys.exit("CSR signature is invalid.")

    now = datetime.now(timezone.utc)
    validity_days = args.days

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    # Carry over SANs from the CSR if present
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san_ext.value, critical=False)
    except x509.ExtensionNotFound:
        # Fall back to CN as a DNS SAN so modern browsers are happy
        cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(cn_attrs[0].value)]),
                critical=False,
            )

    signed_cert = builder.sign(ca_key, hashes.SHA256())
    signed_pem = _pem(signed_cert)

    # Save to dev-ca/signed/<cn>.crt
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    domain = cn_attrs[0].value if cn_attrs else "unknown"
    out_path = SIGNED_DIR / f"{domain}.crt"
    SIGNED_DIR.mkdir(exist_ok=True)
    out_path.write_text(signed_pem)

    print(f"Signed cert saved → {out_path}")
    print(f"Valid for {validity_days} days  |  CN={domain}")
    print()
    print("=" * 64)
    print("Paste the following PEM into the Upload section in ssl-manager:")
    print("=" * 64)
    print(signed_pem)


def cmd_info(args):
    _, cert = _load_ca()
    print(f"Subject : {cert.subject.rfc4514_string()}")
    print(f"Issuer  : {cert.issuer.rfc4514_string()}")
    print(f"Serial  : {cert.serial_number}")
    print(f"Valid from : {cert.not_valid_before_utc}")
    print(f"Valid until: {cert.not_valid_after_utc}")


def cmd_chain(args):
    _, cert = _load_ca()
    print("Copy and paste this into Chain Certificates → Add in ssl-manager:")
    print()
    print(_pem(cert))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Local dev CA for testing ssl-manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create a new local root CA")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing CA")

    p_sign = sub.add_parser("sign", help="Sign a CSR file")
    p_sign.add_argument("csr", metavar="CSR_FILE", help="Path to the .csr file")
    p_sign.add_argument(
        "--days", type=int, default=365,
        help="Certificate validity in days (default: 365)",
    )

    sub.add_parser("info", help="Show CA certificate details")
    sub.add_parser("chain", help="Print CA cert PEM for Chain Certificates page")

    args = parser.parse_args()
    {
        "init": cmd_init,
        "sign": cmd_sign,
        "info": cmd_info,
        "chain": cmd_chain,
    }[args.command](args)


if __name__ == "__main__":
    main()
