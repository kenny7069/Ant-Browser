# Work Package C2 — Enrollment and Secure Identity

## ID

`C2-WP1`

## Goal

Expose the existing Server P1.6 one-time enrollment primitive through a narrow
HTTP API, generate the Ed25519 device key on the Client, store it in the
current OS user's protected secret store, and make the standalone Host load
that identity without placing the private key in config, wire, logs,
diagnostics, process arguments, or crash output.

## Existing implementation

Server:

- `scraper_app.node_enrollment.issue_enrollment_code`
- `scraper_app.node_enrollment.consume_enrollment_code`
- the existing MySQL enrollment/node schema, TTL and conditional one-time
  transitions
- the existing P1.6 Ed25519 challenge and P1.7 authenticated Control WSS
- the deny-by-default Flask auth gate and admin/CSRF classifications

Client:

- C1 strict config and in-memory `FarmClientIdentity`
- `NewFarmControlWSSClient` Ed25519 authentication
- HKDF-SHA256 ownership-key derivation with the distinct
  `ant-farm-runtime-ownership-v1` label
- explicit application/state roots and secret-free version output

## Files allowed

Ant-Browser:

- new `backend/farm_client_enrollment*.go`
- new `backend/farm_client_identity_store*.go`
- new `backend/farm_client_diagnostics*.go`
- additive changes to `backend/farm_client_config.go`,
  `backend/farm_client_host.go`, and `backend/cmd/ant-farm-client/main.go`
- matching C2 tests and C0/C2 evidence documents
- dependency metadata only when required by a reviewed native secret-store
  implementation

auto-scraper:

- `主程式/scraper_app/routes_farm.py`
- `主程式/scraper_app/auth_gate.py`
- a new bounded enrollment guard module if needed
- `輔助程式/test_farm_enrollment_api.py` and narrowly related auth tests

## Files frozen

- Ant Browser/Farm/WSS/CDP lifecycle and protocol files listed in
  `file_ownership.md`
- Server `node_enrollment.py`, Control WSS and schema semantics unless an
  independently reviewed defect makes a minimal change unavoidable

The independent C2 security review found that a consumed code could not be
confirmed after a lost HTTP response. The approved exception is one additive,
read-only `confirm_consumed_enrollment` query in `node_enrollment.py`. It
requires the exact code hash, node UID and public key, expires 120 seconds
after the successful consume, and performs no state transition.

## Contract

1. `POST /api/farm/enrollment-codes` is admin-only, CSRF protected, bounded,
   and calls the existing issue primitive. The raw code is returned once and
   never logged.
2. `POST /api/farm/enroll` is the unauthenticated bootstrap endpoint. It is
   allowed only over HTTPS, except explicit loopback-only test/development
   operation, and is rate limited by source plus node UID.
3. The enroll request contains exactly `enrollment_code`, `node_uid`,
   `node_name`, `device_public_key`, `client_version`, `platform`, and
   `architecture`. Unknown fields and malformed/canonicalization failures are
   rejected with a stable response that contains no submitted secret.
4. The Server delegates the atomic consume to the existing P1.6 primitive. It
   does not implement a second enrollment store or authentication scheme.
5. The Client generates its Ed25519 key locally. Only the 32-byte public key is
   transmitted; the private seed/key never crosses the process boundary.
6. Production identity uses a validated `private_key_ref` and per-user secure
   storage: Windows DPAPI/protected credential storage, macOS Keychain, and
   Linux Secret Service when available with the specification-approved strict
   owner-only `0600` private-file fallback. Windows/macOS never fall back to a
   plaintext file.
7. C1 plaintext/environment identity remains an explicit development/test
   compatibility path and is mutually exclusive with `private_key_ref`.
8. Enrollment first creates or reuses one securely stored pending key, then
   sends only its public key. This makes network retries stable and prevents a
   successful Server consume from being followed by loss of the only key.
   Partial failures remain classified and never create a valid-looking Server
   identity with a different key.
9. Re-enrollment/reinstall may reuse an existing matching key reference, but
   must never silently overwrite a different enrolled identity.
10. Diagnostics and crash output are allowlisted. They may include version,
    GOOS/GOARCH, enrollment state and stable error codes, never the enrollment
    code, private key, raw public key, Authorization headers, URLs with query
    secrets, or native-store error text.
11. Ownership-store HMAC material continues to be derived from the enrolled
    device key with the existing distinct HKDF label; the raw device key is
    never written to the ownership file.

## Happy path

`admin issue code → client generates and durably stores pending key → HTTPS
enroll → atomic consume (or exact-tuple response-loss confirmation) → Host
loads key reference → authenticated WSS`

## Negative cases

- used, expired, revoked, malformed, wrong-node and wrong enrollment code
- malformed/wrong-length public key and unknown request fields
- non-HTTPS remote enrollment
- rate-limit exhaustion
- key-store unavailable/locked/corrupted entry
- conflicting plaintext/env/key-reference config
- attempted overwrite of an existing different identity
- Server/database/native-store exceptions containing secret canaries

## Race cases

- two clients consume one code
- retry after a response is lost
- simultaneous first-run enrollment for one key reference
- Host start while enrollment is storing the key
- delete/corrupt native key during load
- Secret Service locked/denied versus explicitly unavailable
- two state roots concurrently creating one Secret Service reference

## Required tests

- Server API contract, auth/CSRF, HTTPS, rate limit and secret-redaction tests
- existing P1.6 used/expired/replay/concurrency suite
- Client enrollment TLS, strict JSON, local key generation and secret-canary
  tests
- fake key-store round-trip/overwrite/delete/corruption tests
- native store opt-in tests on Windows, macOS and Linux
- reinstall and diagnostics/crash-output tests
- Windows, Linux and macOS compile gates

## Security review corrections

- Forwarded TLS/client-IP headers are accepted only from loopback or explicitly
  configured trusted proxy CIDRs; direct-port spoofing remains HTTP and fails.
- Source quota is consumed before parsing, and enrollment bodies require a
  positive content length no larger than 8 KiB.
- Linux pins an existing fallback identity, uses a per-user/per-reference
  cross-process lock around Secret Service first-save, and falls back only
  when Secret Service is definitively unsupported. Locked, denied and
  transient native errors fail closed.
- Loopback HTTP on the Client and Server requires an explicit development/test
  opt-in.
- A retry after response loss reuses the stored key and can only confirm the
  exact consumed tuple during a bounded 120-second post-consume window.

## Regression tests

- full Ant backend tests, race and vet
- Server enrollment, Control WSS, auth-gate and schema suites
- C1 real Chrome authenticated WSS acceptance

## Acceptance evidence

An admin-issued code is consumed exactly once by a real Client enrollment
request; the resulting native-stored device key authenticates the standalone
Host to Control WSS. Used/expired/replayed inputs and inaccessible/corrupted
key stores fail closed, and secret canaries are absent from wire responses,
logs, diagnostics and crash output.
