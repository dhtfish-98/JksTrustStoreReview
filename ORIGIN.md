# Origin and implementation scope

JksTrustStoreReview independently implements this selected scope: Bounded JKS v2 public truststore inventory, Java modified UTF-8 decoding, certificate parsing and validity/CA/key policy, with explicit externally pinned file digest.

The research source is [kurtbrose/pyjks](https://github.com/kurtbrose/pyjks) at fixed commit `0a046e54337a0c271ef5f7fdd9aa79c5ad350486`. Source archive SHA-256: `f44bed4f728a35c8dbfe85f9d2f9b1db9b12e24481006da6c9944a5fa269f666`. Its license is MIT; the exact source license notice is retained as `UPSTREAM_LICENSE`. The new application code and documentation are licensed under MIT (`LICENSE`). The upstream application is neither imported nor executed by the production package. No upstream application source is bundled in the production package.

## Selected source evidence

- [jks/jks.py](https://github.com/kurtbrose/pyjks/blob/0a046e54337a0c271ef5f7fdd9aa79c5ad350486/jks/jks.py) — SHA-256 `f0e16cf1d01e1c9aaa3ceb77c17e3101683d395680716fce0e61655d28dad7ba`.
- [jks/util.py](https://github.com/kurtbrose/pyjks/blob/0a046e54337a0c271ef5f7fdd9aa79c5ad350486/jks/util.py) — SHA-256 `d6a486a5283e5c69a1ec840bbb1d9ee8b58b1160c3abe53e8cff4b6663dd35c7`.

Full selected file contents and their inventory are retained in the research archive identified by `provenance/SOURCE_REVIEW.json`; those fixed links and hashes allow independent reconstruction. Review focused on JKS v2 entry layout and modified Java UTF-8, public certificate inventory without password or private-entry processing. This record does not assert a whole-platform source audit, original authorship of standards, or equivalence to all upstream behavior.

## Concrete new work

The new implementation owns bounded local input parsing, strict supported-field validation, the complete selected application logic, explicit trust input binding, fail-closed unsupported semantics, privacy-limited result fields, and a three-state CLI contract. Mature cryptographic primitives are reused rather than reimplemented. New scope and tests are substantive application work; a source SHA, rename, mirror or wrapper is not claimed as original contribution.

Required `file`, independently authenticated `expected_sha256` and timezone-aware `now` select a local JKS v2 trusted-certificate-only store. The parser handles bounded counts and blobs, modified UTF-8 aliases and timestamps, exact X.509 DER entries and the structural 20-byte trailer. Duplicate aliases/certificates, truncation, trailing data, any private/secret entry and other store versions fail closed. Validity interval, CA BasicConstraints, RSA minimum 2048, permitted NIST EC curves, supported key families and SHA-256/384/512 certificate signature-digest policy are audited. The password checksum, certificate signatures and PKIX trust chain are not verified; `verified=false` and `jks_password_integrity_verified=false` always remain explicit.

## Primitive policy

All Ed25519 keys and signature R points require canonical nonidentity main-subgroup points. The package calls libsodium point validation and also verifies [L-1]P+P equals identity with native scalar-multiplication/addition primitives, covering older system-library subgroup behavior. Certificate/CRL inner and outer AlgorithmIdentifiers must match exactly. The selected ASN.1 profile permits RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and absent-parameter Ed25519; family and digest must match the signer. These are deliberately strict declared limits.

Primary references: [libsodium point arithmetic](https://libsodium.gitbook.io/doc/advanced/point-arithmetic), [RFC 5280 certificate/CRL identifiers](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2), [RFC 8410 Ed25519 parameters](https://www.rfc-editor.org/rfc/rfc8410.html#section-3).

## Defensive use and application evidence

Inputs must belong to the authorized reviewer. Runtime performs no fetch, sample execution, private-key processing, key export, signing, remote modification or outbound communication. CVP organizational eligibility, evidence of a legitimate blocked task, application review and program acceptance remain OPEN. These local results alone do not establish them.
