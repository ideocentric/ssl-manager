---
name: plan-smart-bundle-import
description: Implementation plan — smart bundle import, P7B support, PKCS12 import, keypair import; all sharing common crypto helpers
metadata:
  type: project
---

**Branch:** `feature/smart-bundle-import`
**Planned:** 2026-06-04

---

## Problems Being Solved

1. **Fragile leaf identification** — current upload takes the first PEM block as the leaf. A NameCheap bundle in a different order, or a P7B where order isn't guaranteed, stores the wrong cert, breaking PKCS12/JKS/DER exports.

2. **No chain matching** — always creates `"{domain} (imported)"` even when an existing chain already covers the same intermediates.

3. **No pre-import visibility** — user has no way to see what will happen before clicking Save.

4. **No P7B support** — GlobalSign and others ship bundles in PKCS#7 (`.p7b`) format. Currently unreadable.

5. **Silent invalid cert handling** — unparseable certs skipped without user notification.

6. **Chain import doesn't check role** — `/chains/<id>/import` would silently import a leaf cert as an intermediate.

7. **No way to import existing certificates with their private keys** — users migrating from external cert management (structured directories, other tools) have no path to bring signed certificates + private keys into the app. PKCS12 and raw keypair imports are both needed.

---

## New Backend Helpers (`app/crypto.py`)

All helpers below are shared across the upload, P7B, P12, and keypair import flows.

### Bundle parsing

**`parse_p7b_bundle(data: bytes) -> list[str]`**
Try `load_der_pkcs7_certificates(data)` first; on failure try `load_pem_pkcs7_certificates(data)`.
Return list of PEM strings. Raise `ValueError` if both fail or result is empty.

### Role classification

**`is_ca_cert(cert: x509.Certificate) -> bool`**
Returns True if `BasicConstraints.ca == True`. Returns False if extension absent or `ca == False`.

**`split_bundle_by_role(certs: list[x509.Certificate]) -> tuple[list, list]`**
Returns `(leaves, intermediates)`. Preserves order within each group.

### Leaf identification

**`identify_leaf_cert(leaves: list[x509.Certificate], csr_pem: str | None = None) -> x509.Certificate | None`**
- One leaf → return it.
- Multiple leaves + CSR → match by public key; return match.
- Multiple leaves, no match → return None (caller errors).

### Chain matching

**`find_matching_chain(intermediate_serials: set[int]) -> CertChain | None`**
Query all chains. Return the first chain whose intermediate serial set is a superset of (or equal to) `intermediate_serials`. Returns None if no match.

### PKCS12 parsing

**`parse_pkcs12(data: bytes, password: str) -> tuple[str, str, list[str]]`**
Wraps `cryptography.hazmat.primitives.serialization.pkcs12.load_pkcs12(data, password.encode())`.
Returns `(private_key_pem, leaf_cert_pem, ca_cert_pem_list)`.
Raises `ValueError` on wrong password or malformed data. The private key is serialized with `NoEncryption()` — SSL Manager always stores keys unencrypted at rest.

### Key / cert validation

**`keys_match(private_key_pem: str, cert_pem: str) -> bool`**
Compares `private_key.public_key().public_bytes(DER)` with `cert.public_key().public_bytes(DER)`. Returns True if they match.

**`get_key_info(private_key_pem: str) -> dict`**
Returns `{"type": "RSA"|"EC"|"other", "bits": int|None, "curve": str|None}` — used to populate `cert.key_size` and display in the preview panel.

---

## Shared Chain Resolution Logic

Used identically by upload, P12 import, and keypair import:

```
given: intermediates (list of x509.Certificate), cert (Certificate ORM object)

1. If no intermediates → chain_action = "none"
2. intermediate_serials = {c.serial_number for c in intermediates}
3. find_matching_chain(intermediate_serials):
   → found: use that chain; if cert.chain_id != found.id, assign it → chain_action = "use_existing"
4. elif cert.chain_id is not None:
   → add non-duplicate intermediates to assigned chain → chain_action = "add_to_assigned"
5. else:
   → create CertChain(name=f"{domain} (imported)"), assign → chain_action = "create"
```

---

## Part A: Upload Route Improvements (existing cert, new signed cert)

### Updated `certificate_upload` — `POST /certificates/<id>/upload`

1. Read file bytes.
2. Detect format by filename extension:
   - `.p7b` / `.p7` → `parse_p7b_bundle(data)` → list of PEM strings
   - Otherwise → decode UTF-8 → `parse_pem_bundle(text)` → list of PEM strings
3. Parse each PEM string to `x509.Certificate`; count failures as `invalid_count`.
4. `split_bundle_by_role(certs)` → `(leaves, intermediates)`
5. `identify_leaf_cert(leaves, cert.csr_pem)`:
   - None → flash error, abort.
   - Key mismatch vs CSR → flash warning, proceed (CA re-key is legitimate).
6. `parse_cert_expiry(leaf_pem)`.
7. Apply shared chain resolution.
8. Save leaf to `cert.signed_cert_pem`, commit, flash detail.

### New preview endpoint — `POST /certificates/<id>/upload/preview`

No DB writes. Returns JSON:

```json
{
  "ok": true,
  "format": "pem_bundle",
  "leaf": { "cn": "www.example.com", "expiry": "2027-06-01", "matches_csr": true },
  "intermediates": [
    { "cn": "Sectigo RSA DV...", "is_duplicate": false },
    { "cn": "USERTrust RSA...",  "is_duplicate": false }
  ],
  "invalid_count": 0,
  "chain_action": "create",
  "chain_name": "www.example.com (imported)",
  "existing_chain_id": null,
  "existing_chain_name": null,
  "error": null
}
```

`chain_action`: `"none"` | `"create"` | `"use_existing"` | `"add_to_assigned"`

### `cert_detail.html` changes

- File input `accept`: `.pem,.crt,.cer,.p7b,.p7`
- Helper text: "You can upload a single certificate, a PEM bundle, or a PKCS#7 (.p7b) file. Intermediates are extracted automatically."
- Add `<div id="bundle-preview">` preview panel rendered from preview endpoint JSON on file `change`.

---

## Part B: PKCS12 Import (new Certificate record)

### New routes — `GET/POST /certificates/import-p12`

**GET:** Renders `cert_import_p12.html` form.

**POST fields:** `p12_file` (file), `password` (text), `domain` (optional override), `chain_id` (optional).

**Logic:**

1. Read file bytes.
2. `parse_pkcs12(data, password)`:
   - Wrong password / malformed → flash error, re-render form.
3. `get_key_info(private_key_pem)` → key type + size.
4. Parse `leaf_cert_pem` → extract CN as default domain.
5. If `domain` form field provided → use it; else use CN.
6. `split_bundle_by_role(ca_certs_from_p12)` → `(unwanted_leaves, intermediates)`. Any non-CA certs in the P12 CA bag are noted but not imported as intermediates.
7. Apply shared chain resolution against `intermediates`.
8. Create `Certificate` record:
   - `domain`, `private_key_pem`, `signed_cert_pem`
   - `key_size` from `get_key_info`
   - `status = "active"`
   - `expiry_date` from `parse_cert_expiry`
   - `chain_id` from chain resolution
   - `csr_pem = None` (no CSR — key was generated externally)
9. Audit log, flash summary, redirect to new cert detail.

### New preview endpoint — `POST /certificates/import-p12/preview`

Same JSON schema as upload preview, extended:

```json
{
  "ok": true,
  "format": "pkcs12",
  "private_key": { "type": "RSA", "bits": 2048 },
  "leaf": { "cn": "www.example.com", "expiry": "2027-06-01", "matches_key": true },
  "intermediates": [...],
  "invalid_count": 0,
  "chain_action": "create",
  "chain_name": "www.example.com (imported)",
  "existing_chain_id": null,
  "existing_chain_name": null,
  "error": null
}
```

Preview requires the password to decrypt the P12 — the form submits both file + password to the preview endpoint via JS on file `change` or password field `blur`.

### `cert_import_p12.html`

- File input for `.p12` / `.pfx`.
- Password field. "Show password" toggle.
- Domain override field (pre-filled from preview).
- Chain selector dropdown.
- AJAX preview panel (same Bootstrap card pattern as upload preview).
- Submit: "Import P12".

---

## Part C: Keypair Import (new Certificate record)

### New routes — `GET/POST /certificates/import-keypair`

**GET:** Renders `cert_import_keypair.html` form.

**POST fields:** `key_file` (file) or `key_pem` (textarea), `cert_file` (file) or `cert_pem` (textarea), `key_password` (optional — for encrypted PEM keys), `domain` (optional override), `chain_id` (optional).

**Logic:**

1. Read private key:
   - `load_pem_private_key(key_data, password=key_password.encode() or None)`
   - Failure → flash error.
   - Serialize to unencrypted PEM.
2. Read cert data (bytes). Detect format:
   - `.p7b` → `parse_p7b_bundle`
   - Otherwise → `parse_pem_bundle`
3. Parse to x509 list; `split_bundle_by_role` → `(leaves, intermediates)`.
4. `identify_leaf_cert(leaves, csr_pem=None)` — no CSR available for keypair imports; if multiple leaves, user must specify or error.
5. **`keys_match(private_key_pem, leaf_cert_pem)`**:
   - False → flash error: "The private key does not match the certificate's public key. Import aborted." Do not create record.
6. Apply shared chain resolution.
7. Create `Certificate` record (same fields as P12 import; `csr_pem = None`).
8. Audit log, flash, redirect.

### New preview endpoint — `POST /certificates/import-keypair/preview`

Same JSON schema, `format: "keypair"`. `leaf.matches_key` replaces `matches_csr`. Requires both key and cert to be submitted for preview.

### `cert_import_keypair.html`

- Private key: file upload OR textarea paste. Optional password field for encrypted keys.
- Certificate: file upload OR textarea paste. Accepts PEM bundle or P7B.
- Domain override field.
- Chain selector.
- AJAX preview panel — fires when both key and cert are provided.
- Submit: "Import Certificate".

---

## Part D: UI Surface — Certificates Page Import Dropdown

Currently the Certificates page has two separate buttons: "New Certificate" and "Import CSR". With three additional import paths (P7B already handled by upload, P12, keypair), the button area will be too crowded.

Replace the flat buttons with:

- **"New Certificate"** primary button (unchanged)
- **"Import ▾"** secondary dropdown containing:
  - Import CSR (existing)
  - Import P12 / PFX (new)
  - Import Private Key + Certificate (new)

This keeps the nav clean and groups all import paths logically.

---

## Part E: Chain Import Role Check

`/chains/<id>/import` (`chains.py` + `chain_import.html`):

1. After `parse_pem_bundle`, parse each PEM to x509 and call `split_bundle_by_role`.
2. If any leaves found → flash warning: "N certificate(s) appear to be end-entity (non-CA) certificates and were skipped. Only CA certificates are added to chains."
3. Import only intermediates, with existing dedup logic unchanged.
4. Update `chain_import.html` helper text.

---

## Implementation Order

| Step | File(s) | Depends on |
|---|---|---|
| 1 | `app/crypto.py` — all new helpers | — |
| 2 | `app/routes/certificates.py` — upload + preview updates | 1 |
| 3 | `app/routes/certificates.py` — P12 import + preview | 1 |
| 4 | `app/routes/certificates.py` — keypair import + preview | 1 |
| 5 | `app/templates/cert_detail.html` — file accept, helper text, preview panel | 2 |
| 6 | `app/templates/cert_import_p12.html` — new template | 3 |
| 7 | `app/templates/cert_import_keypair.html` — new template | 4 |
| 8 | `app/templates/certificates.html` — import dropdown | 3, 4 |
| 9 | `app/routes/chains.py` + `chain_import.html` — role check | 1 |

Steps 2, 3, 4, and 9 are independent of each other once step 1 is done.

---

## Security Notes

- Preview endpoints do no DB writes — safe to call multiple times; require login.
- CSRF token required on all POST forms and AJAX previews (header `X-CSRFToken`).
- P7B parser: DER first, PEM fallback.
- P12 password: POST body only, never logged, never stored.
- Encrypted PEM key password: same handling as P12 password.
- Private keys serialized with `NoEncryption()` before storage — consistent with how SSL Manager stores generated keys.
- `keys_match` failure is a hard block on keypair import — prevents mismatched cert/key being stored.
- Public key mismatch (leaf vs CSR) on upload → warn only, don't block (CA re-key is legitimate).
- `find_matching_chain` uses serial numbers, not subject strings — resistant to CA cert renewals with same subject but new key.
- Audit log every import (success and failure) with domain and import format recorded in the detail field.