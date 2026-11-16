# openXwallet #73 negative-fixture provenance

The original fixture was introduced by commit
21415d3971627df7a8e61aeb09527def00c1fdd6 on 2026-08-07 as an adversarial
key-material refusal probe. Its serialized OKP/Ed25519 public and private
values both exactly match the publicly published [RFC 8037 Appendix A
test vector](https://www.rfc-editor.org/rfc/rfc8037#appendix-A).

This was verified by exact in-memory comparison to the RFC on 2026-11-16;
no credential was submitted to an identity provider. The old fixture blob's
SHA-256 is 631bd3e0541449f87341c6ba7595719af3bcaa54f2a66aea57852edd3192a94f.
History is preserved. The current example uses deliberately invalid
non-base64url placeholders, retaining the kty/d pair, filename, requirement,
expected refusal code and expected detail. It cannot be used as a key.

Private-exponent SHA-256: 190edf59d5736c3b3ea6bb36d57f5eb415a9b79f3201b381b8f3cb089135981f.
This fingerprint identifies public test-vector provenance, not a live credential.
