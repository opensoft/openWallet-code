"""Real Ed25519 profile tests using ephemeral in-memory keys only."""
import base64
from dataclasses import replace
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
import rfc8785

from openwallet_runtime import (
    PROFILE, ProofError, TrustedKeyBinding,
    create_proof, decode_proof, encode_proof, verify_proof,
)

NOW = 1000
DIGEST = "sha256:" + "1" * 64


@pytest.fixture
def bound_key():
    key = Ed25519PrivateKey.generate()
    binding = TrustedKeyBinding(
        binding_ref="binding:demo:1", wallet_ref="wallet:demo",
        key_ref="key:demo:1", subject_ref="subject:machine:demo",
        custody_ref="custody:test-only", public_key=key.public_key().public_bytes_raw(),
        revision=3, not_before=900, expires_at=1200,
    )
    return key, binding


def proof_for(bound_key):
    key, binding = bound_key
    return create_proof(DIGEST, binding, key, now=NOW)


def test_real_crypto_round_trip_and_canonical_wire(bound_key):
    key, binding = bound_key
    proof = proof_for(bound_key)
    reversed_fields = dict(reversed(list(proof.items())))
    wire = encode_proof(reversed_fields)
    assert wire == encode_proof(proof)
    decoded = decode_proof(wire)
    result = verify_proof(decoded, expected_digest=DIGEST, binding=binding, now=NOW)
    assert result.subject_ref == binding.subject_ref
    assert result.challenge_digest == DIGEST
    assert result.binding_revision == 3
    assert not hasattr(result, "mfa")
    assert "public_key" not in decoded


def test_external_signer_receives_the_owned_context_and_canonical_payload(bound_key):
    key, binding = bound_key
    class RecordingSigner:
        message = None
        def sign(self, message):
            self.message = message
            return key.sign(message)
    signer = RecordingSigner()
    create_proof(DIGEST, binding, signer, now=NOW)
    expected = (
        '{"alg":"Ed25519","binding_ref":"binding:demo:1","binding_revision":3,'
        '"challenge_digest":"sha256:' + "1" * 64 + '",'
        '"custody_ref":"custody:test-only","key_ref":"key:demo:1",'
        '"profile":"openwallet.challenge-proof.v0","subject_ref":"subject:machine:demo",'
        '"wallet_ref":"wallet:demo"}'
    ).encode()
    assert signer.message == b"openWallet.challenge-proof.v0\x00" + expected


@pytest.mark.parametrize("field", [
    "binding_ref", "wallet_ref", "key_ref", "subject_ref", "custody_ref",
    "binding_revision", "challenge_digest", "profile", "alg",
])
def test_signed_metadata_tampering_refuses(bound_key, field):
    _, binding = bound_key
    proof = proof_for(bound_key)
    proof[field] = 4 if field == "binding_revision" else "changed"
    with pytest.raises(ProofError):
        verify_proof(proof, expected_digest=DIGEST, binding=binding, now=NOW)


def test_cross_challenge_replay_and_wrong_registry_key_refuse(bound_key):
    _, binding = bound_key
    proof = proof_for(bound_key)
    with pytest.raises(ProofError, match="challenge-mismatch"):
        verify_proof(proof, expected_digest="sha256:" + "2" * 64, binding=binding, now=NOW)
    other = Ed25519PrivateKey.generate()
    wrong = replace(binding, public_key=other.public_key().public_bytes_raw())
    with pytest.raises(ProofError, match="invalid-signature"):
        verify_proof(proof, expected_digest=DIGEST, binding=wrong, now=NOW)


def test_signature_for_another_protocol_cannot_be_reused(bound_key):
    key, binding = bound_key
    proof = proof_for(bound_key)
    unsigned = {k:v for k,v in proof.items() if k != "signature"}
    raw = key.sign(rfc8785.dumps(unsigned))
    proof["signature"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    with pytest.raises(ProofError, match="invalid-signature"):
        verify_proof(proof, expected_digest=DIGEST, binding=binding, now=NOW)


@pytest.mark.parametrize("signature", ["", "A"*85, "A"*87, "A"*86+"=", "+"*86, "/"*86, None, 42])
def test_noncanonical_signature_encoding_refuses(bound_key, signature):
    _, binding = bound_key
    proof = proof_for(bound_key)
    proof["signature"] = signature
    with pytest.raises(ProofError):
        verify_proof(proof, expected_digest=DIGEST, binding=binding, now=NOW)


@pytest.mark.parametrize("change", [
    {"revoked":True}, {"not_before":1001}, {"expires_at":1000},
    {"revision":4}, {"public_key":b"bad"}, {"revision":True},
    {"expires_at":2**53}, {"not_before":1200}, {"subject_ref":""},
])
def test_current_binding_state_is_checked(bound_key, change):
    _, binding = bound_key
    proof = proof_for(bound_key)
    with pytest.raises(ProofError):
        verify_proof(proof, expected_digest=DIGEST, binding=replace(binding, **change), now=NOW)


def test_no_client_public_key_or_unknown_claim_is_accepted(bound_key):
    _, binding = bound_key
    proof = proof_for(bound_key)
    proof["public_key"] = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    with pytest.raises(ProofError, match="invalid-proof"):
        verify_proof(proof, expected_digest=DIGEST, binding=binding, now=NOW)


@pytest.mark.parametrize("field", [
    "profile", "alg", "binding_ref", "binding_revision", "challenge_digest",
    "wallet_ref", "key_ref", "subject_ref", "custody_ref", "signature",
])
def test_every_wire_field_is_required(bound_key, field):
    _, binding = bound_key
    proof = proof_for(bound_key)
    del proof[field]
    with pytest.raises(ProofError):
        verify_proof(proof, expected_digest=DIGEST, binding=binding, now=NOW)


def test_strict_json_rejects_duplicates_constants_nonobjects_and_oversize(bound_key):
    wire = encode_proof(proof_for(bound_key))
    duplicate = b'{"profile":"' + PROFILE.encode() + b'",' + wire[1:]
    for raw in [duplicate, b"[]", b"null", b'{"x":NaN}', b"{", b"\xff", b" "*8193]:
        with pytest.raises(ProofError):
            decode_proof(raw)


@pytest.mark.parametrize("value", [" subject:x", "subject:x ", "subject:\nprivate", "\ud800"])
def test_ambiguous_or_invalid_reference_strings_refuse(bound_key, value):
    key, binding = bound_key
    with pytest.raises(ProofError):
        create_proof(DIGEST, replace(binding, subject_ref=value), key, now=NOW)


def test_signer_errors_are_sanitized_and_wrong_signer_results_refuse(bound_key):
    _, binding = bound_key
    class BrokenSigner:
        def sign(self, _message):
            raise RuntimeError("sensitive backend detail")
    with pytest.raises(ProofError) as error:
        create_proof(DIGEST, binding, BrokenSigner(), now=NOW)
    assert str(error.value) == "signer-unavailable"
    class WrongSigner:
        def sign(self, _message):
            return b"x"*64
    with pytest.raises(ProofError, match="invalid-signer-result"):
        create_proof(DIGEST, binding, WrongSigner(), now=NOW)


@pytest.mark.parametrize("now", [True, -1, 2**53, 1.0])
def test_client_style_invalid_clock_values_refuse(bound_key, now):
    key, binding = bound_key
    with pytest.raises(ProofError):
        create_proof(DIGEST, binding, key, now=now)
