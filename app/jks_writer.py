# ==============================================================================
# FILE:           app/jks_writer.py
# DESCRIPTION:    Minimal, dependency-free writer for Java KeyStore (JKS) files
#                 containing a single private-key entry with its certificate
#                 chain. Pure standard library (hashlib + struct) — no JRE and
#                 no third-party package required at runtime.
#
#                 We only ever WRITE a JKS from our own trusted key/cert data;
#                 this module deliberately contains no keystore *parsing* code
#                 (where keystore-library vulnerabilities almost always live).
#
# DERIVED FROM:   The JKS on-disk format and the "JavaSoft proprietary key
#                 protection algorithm" (OID 1.3.6.1.4.1.42.2.17.1.1) as
#                 implemented by pyjks (https://github.com/kurtbrose/pyjks),
#                 Copyright (c) Kurt Rose and Jeroen De Ridder, MIT License.
#                 Reimplemented here for the JKS write path only so the project
#                 carries no dependency on pyjks or its transitive packages.
#
# REFERENCE:      sun/security/provider/KeyProtector.java and
#                 sun/security/provider/JavaKeyStore.java in the OpenJDK sources.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
#                 (incorporates MIT-licensed format details from pyjks)
# ==============================================================================

import hashlib
import os
import struct
import time

# JKS keystore magic number and version (big-endian).
_MAGIC = b"\xfe\xed\xfe\xed"
_VERSION = 2

# Salt mixed into the keystore integrity digest (Oracle's literal constant).
_SIGNATURE_WHITENING = b"Mighty Aphrodite"

# DER of the AlgorithmIdentifier for the Sun JKS key-protection algorithm:
#   SEQUENCE { OID 1.3.6.1.4.1.42.2.17.1.1, NULL }
# This is a fixed constant — it never varies — so it is hard-coded rather than
# built with an ASN.1 library.
_JKS_ALG_ID_DER = bytes.fromhex("300e060a2b060104012a021101010500")

_CERT_TYPE = "X.509"


# ── DER helpers (just enough to wrap the encrypted key) ───────────────────────

def _der_len(n: int) -> bytes:
    """Encode a DER length (short form < 128, else long form)."""
    if n < 0x80:
        return bytes([n])
    body = b""
    while n:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    return bytes([0x80 | len(body)]) + body


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _encrypted_private_key_info(encrypted: bytes) -> bytes:
    """EncryptedPrivateKeyInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }."""
    octet_string = _der(0x04, encrypted)
    return _der(0x30, _JKS_ALG_ID_DER + octet_string)


# ── JKS "JavaSoft proprietary" key protection (SHA-1 keystream) ───────────────

def _jks_keystream(iv: bytes, password_utf16: bytes):
    """Infinite SHA-1 keystream: cur = SHA1(password || cur), starting at iv."""
    cur = iv
    while True:
        cur = hashlib.sha1(password_utf16 + cur).digest()
        yield from cur


def _jks_pkey_encrypt(pkcs8_der: bytes, password_utf16: bytes, iv: bytes) -> bytes:
    """Return iv(20) || (pkcs8 XOR keystream) || SHA1(password || pkcs8)(20)."""
    ks = _jks_keystream(iv, password_utf16)
    data = bytes(b ^ next(ks) for b in pkcs8_der)
    check = hashlib.sha1(password_utf16 + pkcs8_der).digest()
    return iv + data + check


# ── Field writers (Java DataOutputStream conventions) ─────────────────────────

def _write_utf(text: str) -> bytes:
    """u2 length prefix + UTF-8 bytes (matches Java writeUTF for ASCII/BMP)."""
    encoded = text.encode("utf-8")
    return struct.pack(">H", len(encoded)) + encoded


def _write_data(data: bytes) -> bytes:
    """u4 length prefix + raw bytes."""
    return struct.pack(">L", len(data)) + data


# ── Public API ────────────────────────────────────────────────────────────────

def build_jks(key_pkcs8_der, cert_chain_der, store_password, alias="certificate",
              *, key_password=None, iv=None, timestamp_ms=None):
    """Build a JKS keystore with one private-key entry. Returns bytes.

    Args:
        key_pkcs8_der:  Private key as PKCS#8 DER (bytes).
        cert_chain_der: List of DER-encoded certificates; index 0 is the leaf
                        belonging to the key, the rest are the chain in order.
        store_password: Keystore password (str or bytes).
        alias:          Entry alias. Lower-cased, because Java keytool/Keytool
                        Explorer corrupt the keystore on mixed-case aliases.
        key_password:   Password protecting the key entry. Defaults to
                        store_password (keytool's single-password behaviour).
        iv:             20-byte protection IV. Defaults to os.urandom(20).
                        Injectable so tests can produce byte-deterministic output.
        timestamp_ms:   Entry creation time in epoch milliseconds (Java long).
                        Defaults to the current time. Injectable for tests.

    Returns:
        The complete JKS file as a byte string.
    """
    if isinstance(store_password, bytes):
        store_password = store_password.decode()
    if key_password is None:
        key_password = store_password
    elif isinstance(key_password, bytes):
        key_password = key_password.decode()
    if iv is None:
        iv = os.urandom(20)
    if timestamp_ms is None:
        timestamp_ms = int(time.time()) * 1000

    key_pw_utf16 = key_password.encode("utf-16be")
    encrypted = _jks_pkey_encrypt(bytes(key_pkcs8_der), key_pw_utf16, iv)
    epki = _encrypted_private_key_info(encrypted)

    # ── One private-key entry ────────────────────────────────────────────────
    entry = struct.pack(">L", 1)                       # entry tag: private key
    entry += _write_utf(alias.lower())
    entry += struct.pack(">Q", timestamp_ms)
    entry += _write_data(epki)
    entry += struct.pack(">L", len(cert_chain_der))    # certs in chain
    for der in cert_chain_der:
        entry += _write_utf(_CERT_TYPE)
        entry += _write_data(bytes(der))

    body = _MAGIC + struct.pack(">L", _VERSION) + struct.pack(">L", 1) + entry

    # ── Keystore integrity digest over everything written so far ──────────────
    digest = hashlib.sha1(
        store_password.encode("utf-16be") + _SIGNATURE_WHITENING + body
    ).digest()
    return body + digest