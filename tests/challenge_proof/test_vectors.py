"""Known answers generated independently with Node/OpenSSL, not this runtime."""
import base64
from dataclasses import replace
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from openwallet_runtime import (
    ProofError, TrustedKeyBinding, create_proof, decode_proof, encode_proof, verify_proof,
)

VECTORS = json.loads(Path(__file__).with_name("vectors.json").read_text(encoding="utf-8"))


@pytest.fixture(params=VECTORS, ids=lambda vector: vector["name"])
def vector(request):
    return request.param


def binding_for(vector):
    return TrustedKeyBinding(public_key=bytes.fromhex(vector["public_key_hex"]), **vector["binding"])


def test_independent_proof_verifies_and_has_exact_wire_bytes(vector):
    proof = decode_proof(vector["wire_utf8"].encode())
    assert proof == vector["proof"]
    assert encode_proof(proof) == vector["wire_utf8"].encode()
    result = verify_proof(proof, expected_digest=proof["challenge_digest"],
                          binding=binding_for(vector), now=vector["now"])
    assert result.binding_revision == vector["binding"]["revision"]
    assert result.wallet_ref == vector["binding"]["wallet_ref"]


def test_python_signer_matches_independent_preimage_and_signature(vector):
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["public_test_seed_hex"]))
    assert key.public_key().public_bytes_raw().hex() == vector["public_key_hex"]

    class CheckedSigner:
        def sign(self, message):
            assert message.hex() == vector["message_hex"]
            assert message == b"openWallet.challenge-proof.v0\0" + vector["unsigned_canonical_utf8"].encode()
            return key.sign(message)

    actual = create_proof(vector["proof"]["challenge_digest"], binding_for(vector),
                          CheckedSigner(), now=vector["now"])
    assert actual == vector["proof"]


@pytest.mark.parametrize("message_change", ["wrong-domain", "changed-byte"])
def test_independently_signed_wrong_preimages_refuse(vector, message_change):
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["public_test_seed_hex"]))
    message = bytes.fromhex(vector["message_hex"])
    changed = (b"other-protocol\0" + vector["unsigned_canonical_utf8"].encode()
               if message_change == "wrong-domain" else message[:-1] + b" ")
    proof = {**vector["proof"], "signature": base64.urlsafe_b64encode(key.sign(changed)).rstrip(b"=").decode()}
    with pytest.raises(ProofError, match="invalid-signature"):
        verify_proof(proof, expected_digest=proof["challenge_digest"],
                     binding=binding_for(vector), now=vector["now"])


def test_fixed_vector_still_requires_current_binding_and_expected_digest(vector):
    binding = binding_for(vector)
    with pytest.raises(ProofError, match="revoked-binding"):
        verify_proof(vector["proof"], expected_digest=vector["proof"]["challenge_digest"],
                     binding=replace(binding, revoked=True), now=vector["now"])
    with pytest.raises(ProofError, match="challenge-mismatch"):
        verify_proof(vector["proof"], expected_digest="sha256:" + "0" * 64,
                     binding=binding, now=vector["now"])
