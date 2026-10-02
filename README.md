# JksTrustStoreReview

Bounded JKS v2 public truststore inventory, Java modified UTF-8 decoding, certificate parsing and validity/CA/key policy, with explicit externally pinned file digest.

This is an independently implemented, complete selected offline input profile. It is not an equivalent rewrite of the entire upstream platform. Cryptographic primitives use cryptography; no upstream application is called.

## Contract

Run `jks-truststore-review request.json` or pipe JSON to `jks-truststore-review -`. Every input is local and supplied by its authorized owner. Parsing is bounded; duplicate fields, unknown algorithms, unsupported semantics, and failed signatures fail closed. The CLI returns 0 for PASS, 1 for FAIL, and 2 for OPEN. PASS applies only to the declared profile; it is not a general safety or CVP eligibility finding. Output excludes private material and raw credential identifiers.

## Boundaries

- JKS v2 trusted-certificate-only stores. JCEKS/BKS/UBER/private/secret entries fail closed. No password, key decryption, credential export, or chain building. The legacy JKS SHA-1 password checksum remains unverified; external SHA-256 pinning does not prove CA policy correctness.

CVP organizational eligibility, an actually blocked legitimate task, application review, and approval remain OPEN. A repository and passing tests do not establish eligibility.

## Complete input profile

Required `file`, independently authenticated `expected_sha256` and timezone-aware `now` select a local JKS v2 trusted-certificate-only store. The parser handles bounded counts and blobs, modified UTF-8 aliases and timestamps, exact X.509 DER entries and the structural 20-byte trailer. Duplicate aliases/certificates, truncation, trailing data, any private/secret entry and other store versions fail closed. Validity interval, CA BasicConstraints, RSA minimum 2048, permitted NIST EC curves, supported key families and SHA-256/384/512 certificate signature-digest policy are audited. The password checksum, certificate signatures and PKIX trust chain are not verified; `verified=false` and `jks_password_integrity_verified=false` always remain explicit.

All accepted Ed25519 public keys are canonical nonidentity points in the main subgroup, checked through libsodium. Ed25519 signature R points must also be canonical nonidentity main-subgroup points and S must be below the group order. Certificates and CRLs require exactly matching inner/outer AlgorithmIdentifiers; the strict profile permits only RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and Ed25519 with absent parameters. OCSP permits the same explicit algorithm encodings and key-family/hash binding.

Where the profile accepts public PEM inputs, they contain one SubjectPublicKeyInfo or certificate object respectively, with canonical base64, no duplicate object and no trailing content. UTF-8 string values and keys reject lone surrogates; JSON results are safely ASCII-escaped.

The saved `examples/valid.json` is synthetic and contains only public data. Time-dependent examples retain their recorded reference `now`; tests generate fresh synthetic objects in temporary directories without changing examples.

## Install and check

```sh
python -m pip install .
python -m unittest discover -s tests -v
jks-truststore-review examples/valid.json
```

See [ORIGIN.md](ORIGIN.md), [VALIDATION.md](VALIDATION.md), [LICENSE](LICENSE) and [UPSTREAM_LICENSE](UPSTREAM_LICENSE) for scope, evidence and attribution.
