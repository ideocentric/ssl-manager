#!/usr/bin/env python3
# ==============================================================================
# FILE:           dev_ca.py
# DESCRIPTION:    Local development Certificate Authority helper for ssl-manager.
#                 Creates a two-tier CA hierarchy (root → intermediate) that
#                 mirrors real-world CAs, allowing end-to-end UI testing without
#                 a live Certificate Authority.
#
# USAGE:          python dev_ca.py <command> [OPTIONS]
#   COMMANDS:
#     init                   Create root CA and intermediate CA (run once)
#     sign <csr_file>        Sign a CSR with the intermediate CA
#     chain                  Print chain PEMs for the Chains UI (import bundle)
#     info                   Show subject, issuer, and validity for both CAs
#   OPTIONS:
#     --days <n>             Validity period in days for signed certs (default: 365)
#     --force                Re-generate CAs, overwriting existing files (init only)
#
# EXAMPLES:
#   python dev_ca.py init
#   python dev_ca.py sign ~/Downloads/example.com.csr
#   python dev_ca.py sign example.com.csr --days 90
#   python dev_ca.py init --force
#
# DEPENDENCIES:   cryptography
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
#   The dev-ca/ directory is gitignored. Keep root.key and intermediate.key
#   out of version control.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CA_DIR = Path(__file__).parent / "dev-ca"
ROOT_KEY_PATH = CA_DIR / "root.key"
ROOT_CRT_PATH = CA_DIR / "root.crt"
INT_KEY_PATH  = CA_DIR / "intermediate.key"
INT_CRT_PATH  = CA_DIR / "intermediate.crt"
SIGNED_DIR    = CA_DIR / "signed"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gen_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _save_key(key: rsa.RSAPrivateKey, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _pem(obj) -> str:
    return obj.public_bytes(serialization.Encoding.PEM).decode()


def _load_root():
    if not ROOT_KEY_PATH.exists() or not ROOT_CRT_PATH.exists():
        sys.exit("CA not initialised. Run:  python dev_ca.py init")
    key  = serialization.load_pem_private_key(ROOT_KEY_PATH.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(ROOT_CRT_PATH.read_bytes())
    return key, cert


def _load_intermediate():
    if not INT_KEY_PATH.exists() or not INT_CRT_PATH.exists():
        sys.exit("CA not initialised. Run:  python dev_ca.py init")
    key  = serialization.load_pem_private_key(INT_KEY_PATH.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(INT_CRT_PATH.read_bytes())
    return key, cert


def _ca_key_usage(cert_sign=False):
    return x509.KeyUsage(
        digital_signature=True,
        key_cert_sign=cert_sign,
        crl_sign=cert_sign,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        encipher_only=False,
        decipher_only=False,
    )


def _cert_info(cert) -> str:
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return (
        f"  Subject : {cert.subject.rfc4514_string()}\n"
        f"  Issuer  : {cert.issuer.rfc4514_string()}\n"
        f"  Serial  : {cert.serial_number}\n"
        f"  Valid   : {nb}  →  {na}"
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args):
    if ROOT_KEY_PATH.exists() and not args.force:
        sys.exit(
            "CA already exists. Use --force to overwrite.\n"
            f"  {ROOT_KEY_PATH}\n  {INT_KEY_PATH}"
        )

    CA_DIR.mkdir(parents=True, exist_ok=True)
    SIGNED_DIR.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc)

    # ---- Root CA ----
    print("Generating root CA key (2048-bit RSA)…")
    root_key = _gen_key()

    root_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Dev"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Dev CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Local Dev Root CA"),
    ])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_ca_key_usage(cert_sign=True), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    _save_key(root_key, ROOT_KEY_PATH)
    ROOT_CRT_PATH.write_bytes(_pem(root_cert).encode())
    print(f"  key  → {ROOT_KEY_PATH}")
    print(f"  cert → {ROOT_CRT_PATH}")

    # ---- Intermediate CA ----
    print("Generating intermediate CA key (2048-bit RSA)…")
    int_key = _gen_key()

    int_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Dev"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Dev CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Local Dev Intermediate CA"),
    ])

    int_cert = (
        x509.CertificateBuilder()
        .subject_name(int_name)
        .issuer_name(root_name)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1825))  # 5 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(cert_sign=True), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    _save_key(int_key, INT_KEY_PATH)
    INT_CRT_PATH.write_bytes(_pem(int_cert).encode())
    print(f"  key  → {INT_KEY_PATH}")
    print(f"  cert → {INT_CRT_PATH}")

    print()
    print("Chain Certificates setup (run once in ssl-manager):")
    print("  Chain Certificates → Add  →  name: 'Local Dev Intermediate CA'  order: 1")
    print("    paste output of:  python dev_ca.py chain --intermediate")
    print("  Chain Certificates → Add  →  name: 'Local Dev Root CA'          order: 2")
    print("    paste output of:  python dev_ca.py chain --root")
    print()
    print("Then for each domain:")
    print("  python dev_ca.py sign <file.csr>")


def cmd_sign(args):
    int_key, int_cert = _load_intermediate()

    csr_path = Path(args.csr)
    if not csr_path.exists():
        sys.exit(f"CSR file not found: {csr_path}")

    csr = x509.load_pem_x509_csr(csr_path.read_bytes())
    if not csr.is_signature_valid:
        sys.exit("CSR signature is invalid.")

    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(int_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=args.days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
            x509.AuthorityKeyIdentifier.from_issuer_public_key(int_key.public_key()),
            critical=False,
        )
    )

    # Carry over SANs from the CSR, or fall back to CN
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san_ext.value, critical=False)
    except x509.ExtensionNotFound:
        cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(cn_attrs[0].value)]),
                critical=False,
            )

    signed_cert = builder.sign(int_key, hashes.SHA256())
    signed_pem  = _pem(signed_cert)

    cn_attrs    = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    domain      = cn_attrs[0].value if cn_attrs else "unknown"
    safe_domain = domain.replace("*.", "star.").replace("*", "star")
    out_path    = SIGNED_DIR / f"{safe_domain}.crt"
    SIGNED_DIR.mkdir(exist_ok=True)
    out_path.write_text(signed_pem)

    print(f"Signed cert saved → {out_path}")
    print(f"Signed by: Local Dev Intermediate CA  |  valid for {args.days} days  |  CN={domain}")
    print()
    print("=" * 64)
    print("Paste the following PEM into the Upload section in ssl-manager:")
    print("=" * 64)
    print(signed_pem)


def cmd_info(args):
    _, root_cert = _load_root()
    _, int_cert  = _load_intermediate()
    print("Root CA:")
    print(_cert_info(root_cert))
    print()
    print("Intermediate CA:")
    print(_cert_info(int_cert))


def cmd_chain(args):
    _, root_cert = _load_root()
    _, int_cert  = _load_intermediate()

    if args.root and args.intermediate:
        sys.exit("Specify at most one of --root or --intermediate.")

    if args.root:
        print("# Root CA — add as Chain Certificate (order 2)\n")
        print(_pem(root_cert))
    elif args.intermediate:
        print("# Intermediate CA — add as Chain Certificate (order 1)\n")
        print(_pem(int_cert))
    else:
        # Default: print both with instructions
        print("Add these two entries under Chain Certificates in ssl-manager.")
        print()
        print("Entry 1 — name: 'Local Dev Intermediate CA'  order: 1")
        print("-" * 64)
        print(_pem(int_cert))
        print("Entry 2 — name: 'Local Dev Root CA'  order: 2")
        print("-" * 64)
        print(_pem(root_cert))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Local two-tier dev CA for testing ssl-manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create root CA and intermediate CA")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing CA files")

    p_sign = sub.add_parser("sign", help="Sign a CSR with the intermediate CA")
    p_sign.add_argument("csr", metavar="CSR_FILE", help="Path to the .csr file")
    p_sign.add_argument(
        "--days", type=int, default=365,
        help="Certificate validity in days (default: 365)",
    )

    sub.add_parser("info", help="Show details for both CA certificates")

    p_chain = sub.add_parser("chain", help="Print CA PEMs for the Chain Certificates page")
    chain_grp = p_chain.add_mutually_exclusive_group()
    chain_grp.add_argument("--root",         action="store_true", help="Print root CA cert only")
    chain_grp.add_argument("--intermediate", action="store_true", help="Print intermediate CA cert only")

    args = parser.parse_args()
    {
        "init":  cmd_init,
        "sign":  cmd_sign,
        "info":  cmd_info,
        "chain": cmd_chain,
    }[args.command](args)


if __name__ == "__main__":
    main()
