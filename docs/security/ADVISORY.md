# Security Advisory

**Project:** SSL Manager
**Assessed:** 2026-03-30
**Assessed by:** Matt Comeione / ideocentric

This document records the CVE and security advisory review performed against the
project dependencies declared in `requirements.txt`.

---

## Summary

| Package | Version (before) | Version (after) | CVEs Found | Highest Severity | Action Taken |
|---|---|---|---|---|---|
| cryptography | 42.0.8 | **46.0.6** | 4 | High (CVSS 8.2) | Upgraded |
| Flask | 3.0.3 | **3.1.3** | 1 | Low (CVSS 2.3) | Upgraded |
| gunicorn | 22.0.0 | **23.0.0** | 0 | N/A | Upgraded (defence-in-depth) |
| Flask-SQLAlchemy | 3.1.1 | 3.1.1 | 0 | N/A | No change required |
| flask-login | 0.6.3 | 0.6.3 | 0 | N/A | No change required |
| pyjks | 20.0.0 | 20.0.0 | 0 | N/A | No CVEs; package is abandoned — see notes |

---

## Findings by Package

### cryptography 42.0.8 — 4 Active CVEs (Upgraded to 46.0.6)

#### CVE-2024-6119 / GHSA-h4gh-qq45-vh27 — High

- **Description:** Type confusion in OpenSSL's `do_x509_check()` function. An application
  performing DNS/email/IP name checks on X.509 `otherName` SANs can be crashed by a crafted
  certificate, causing a NULL pointer dereference.
- **Affected versions:** cryptography 37.0.0 – 43.0.0 (bundled OpenSSL in PyPI wheels)
- **Fixed in:** cryptography 43.0.1
- **References:**
  - https://github.com/advisories/GHSA-h4gh-qq45-vh27
  - https://www.openssl.org/news/secadv/20240904.txt

#### CVE-2024-12797 / GHSA-79v4-65xg-pq4g — High

- **Description:** The PyPI wheels for cryptography 42.0.0 – 44.0.0 bundle a vulnerable version
  of OpenSSL. Per the OpenSSL February 2025 security advisory, this enables a potential TLS
  handshake bypass. Affects wheel installs from PyPI only; source builds against a patched
  system OpenSSL are unaffected.
- **Affected versions:** cryptography 42.0.0 – 44.0.0
- **Fixed in:** cryptography 44.0.1
- **References:**
  - https://github.com/advisories/GHSA-79v4-65xg-pq4g
  - https://www.openssl.org/news/secadv/20250211.txt

#### CVE-2026-26007 / GHSA-r6ph-v2qm-q3c2 — High (CVSS 8.2)

- **Description:** Missing subgroup validation in public key loading for SECT elliptic curves.
  Attackers can supply low-order public keys in ECDH operations to partially leak private key
  bits, or forge ECDSA signatures.
- **Affected versions:** All cryptography versions through 46.0.4
- **Fixed in:** cryptography 46.0.5
- **References:**
  - https://osv.dev/vulnerability/GHSA-r6ph-v2qm-q3c2

#### CVE-2025-61727 — Low

- **Description:** Low-impact vulnerability in cryptography < 46.0.6.
- **Affected versions:** cryptography < 46.0.6
- **Fixed in:** cryptography 46.0.6
- **References:**
  - https://nvd.nist.gov/vuln/detail/CVE-2025-61727

---

### Flask 3.0.3 — 1 Active CVE (Upgraded to 3.1.3)

#### CVE-2026-27205 / GHSA-68rp-wp8r-4726 — Low (CVSS 2.3)

- **Description:** Flask fails to set the `Vary: Cookie` response header when the session
  object is accessed via certain methods (e.g. Python's `in` operator). A misconfigured caching
  proxy could serve a response containing session-specific data to a different user.
- **Exploitability note:** Only exploitable if the application sits behind a caching proxy
  that does not strip cookies and does not enforce `Cache-Control: private`. The ssl-manager
  production deployment (nginx on loopback, SSH tunnel for remote access, no public caching
  layer) significantly limits real-world exposure.
- **Affected versions:** Flask < 3.1.3
- **Fixed in:** Flask 3.1.3
- **References:**
  - https://github.com/pallets/flask/security/advisories/GHSA-68rp-wp8r-4726

---

### gunicorn 22.0.0 — No Active CVEs (Upgraded to 23.0.0)

gunicorn 22.0.0 was itself a security fix release, resolving:

- **CVE-2024-1135** (GHSA-w3h3-4rj7-4ph4, CVSS 8.2): Request smuggling via conflicting
  `Transfer-Encoding` headers. Fixed in 22.0.0.
- **CVE-2024-6827** (GHSA-hc5x-x2vx-497g, CVSS 7.5): TE.CL request smuggling via improper
  `Transfer-Encoding` header validation. Fixed in 22.0.0.

Version 22.0.0 carries no known unpatched CVEs. Upgraded to 23.0.0 for defence-in-depth and
ongoing HTTP/1.1 improvements.

---

### Flask-SQLAlchemy 3.1.1 — No CVEs

No CVEs, GitHub Security Advisories, or PyPI vulnerability notices found. No action required.

---

### flask-login 0.6.3 — No CVEs

No CVEs, GitHub Security Advisories, or PyPI vulnerability notices found. This is also the
current latest release. No action required.

---

### pyjks 20.0.0 — No CVEs (Abandoned Package)

No CVEs found. However, pyjks has had no repository activity since its 2020.0.0 release and
has no active security policy. The package parses Java KeyStore (JKS/JCEKS) files, which is
an inherently sensitive operation. Any future vulnerability would go unpatched.

**Recommendation:** Consider replacing pyjks with an actively maintained alternative or
delegating JKS generation to a `keytool` subprocess call. The functionality should only ever
be invoked with application-generated data (never with untrusted, externally supplied keystore
files).

---

## Sources

- [OSV.dev](https://osv.dev) — Open Source Vulnerabilities database
- [GitHub Advisory Database](https://github.com/advisories)
- [NIST NVD](https://nvd.nist.gov)
- [Snyk Vulnerability DB](https://security.snyk.io)
- [OpenSSL Security Advisories](https://www.openssl.org/news/vulnerabilities.html)