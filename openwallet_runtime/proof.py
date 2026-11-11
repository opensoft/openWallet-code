"""Offline candidate profile for a context-bound Ed25519 possession proof.

Bindings come from a caller-authenticated registry, never from the proof.
The issuer owns challenge freshness/one-use; custody and grants need their
own trusted evidence. A successful verification does not establish MFA,
human presence, agent composition, delegation or permission.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import re
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import rfc8785

PROFILE = "openwallet.challenge-proof.v0"
_CONTEXT = b"openWallet.challenge-proof.v0\x00"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}\Z")
_REFS = ("binding_ref", "wallet_ref", "key_ref", "subject_ref", "custody_ref")
_FIELDS = frozenset(("profile", "alg", "challenge_digest", "binding_revision", *_REFS))
_MAX_INT = 2**53 - 1


class ProofError(ValueError):
    """Fixed, secret-safe refusal code; never includes raw evidence."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class Signer(Protocol):
    """Opaque custody adapter. No key export method is required."""

    def sign(self, message: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class TrustedKeyBinding:
    """Server-resolved metadata, not a client claim or proof of custody."""
    binding_ref: str
    wallet_ref: str
    key_ref: str
    subject_ref: str
    custody_ref: str
    public_key: bytes
    revision: int
    not_before: int
    expires_at: int
    revoked: bool = False


@dataclass(frozen=True, slots=True)
class VerifiedPossession:
    binding_ref: str
    wallet_ref: str
    key_ref: str
    subject_ref: str
    custody_ref: str
    binding_revision: int
    challenge_digest: str


def _integer(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_INT


def _reference(value: object) -> bool:
    return (
        type(value) is str and 0 < len(value) <= 256 and value == value.strip()
        and not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
    )


def _digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _check_binding(binding: TrustedKeyBinding, now: int) -> None:
    if not isinstance(binding, TrustedKeyBinding) or not _integer(now):
        raise ProofError("invalid-binding")
    if not all(_reference(getattr(binding, k)) for k in _REFS):
        raise ProofError("invalid-binding")
    if (
        type(binding.public_key) is not bytes or len(binding.public_key) != 32
        or not _integer(binding.revision)
        or not _integer(binding.not_before) or not _integer(binding.expires_at)
        or binding.not_before >= binding.expires_at
        or type(binding.revoked) is not bool
    ):
        raise ProofError("invalid-binding")
    if binding.revoked:
        raise ProofError("revoked-binding")
    if not binding.not_before <= now < binding.expires_at:
        raise ProofError("inactive-binding")


def _unsigned(proof: object) -> dict:
    if type(proof) is not dict or set(proof) != _FIELDS | {"signature"}:
        raise ProofError("invalid-proof")
    if proof["profile"] != PROFILE or proof["alg"] != "Ed25519":
        raise ProofError("unsupported-profile")
    if (
        not _digest(proof["challenge_digest"])
        or not _integer(proof["binding_revision"])
        or not all(_reference(proof[k]) for k in _REFS)
        or type(proof["signature"]) is not str
        or _SIGNATURE.fullmatch(proof["signature"]) is None
    ):
        raise ProofError("invalid-proof")
    return {k: proof[k] for k in _FIELDS}


def _message(unsigned: dict) -> bytes:
    try:
        return _CONTEXT + rfc8785.dumps(unsigned)
    except (rfc8785.CanonicalizationError, UnicodeError, TypeError, ValueError):
        raise ProofError("invalid-proof") from None


def _signature(encoded: str) -> bytes:
    try:
        value = base64.b64decode(encoded + "==", altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        raise ProofError("invalid-proof") from None
    if len(value) != 64 or base64.urlsafe_b64encode(value).rstrip(b"=").decode() != encoded:
        raise ProofError("invalid-proof")
    return value


def create_proof(
    challenge_digest: str, binding: TrustedKeyBinding, signer: Signer, *, now: int
) -> dict:
    """Sign a caller-authenticated challenge digest through opaque custody.

    The caller must authenticate the verifier/challenge before requesting a
    signature. This primitive is not a remote signing broker.
    """
    _check_binding(binding, now)
    if not _digest(challenge_digest):
        raise ProofError("invalid-proof")
    unsigned = {
        "profile": PROFILE, "alg": "Ed25519",
        "challenge_digest": challenge_digest,
        "binding_revision": binding.revision,
        **{k: getattr(binding, k) for k in _REFS},
    }
    message = _message(unsigned)
    try:
        signature = signer.sign(message)
    except Exception:
        raise ProofError("signer-unavailable") from None
    if type(signature) is not bytes or len(signature) != 64:
        raise ProofError("invalid-signer-result")
    try:
        Ed25519PublicKey.from_public_bytes(binding.public_key).verify(signature, message)
    except (InvalidSignature, ValueError, TypeError):
        raise ProofError("invalid-signer-result") from None
    return {**unsigned, "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}


def verify_proof(
    proof: dict, *, expected_digest: str, binding: TrustedKeyBinding, now: int
) -> VerifiedPossession:
    """Verify real crypto against the expected digest and current trusted binding."""
    _check_binding(binding, now)
    unsigned = _unsigned(proof)
    if not _digest(expected_digest) or proof["challenge_digest"] != expected_digest:
        raise ProofError("challenge-mismatch")
    if (
        any(proof[k] != getattr(binding, k) for k in _REFS)
        or proof["binding_revision"] != binding.revision
    ):
        raise ProofError("binding-mismatch")
    signature = _signature(proof["signature"])
    try:
        Ed25519PublicKey.from_public_bytes(binding.public_key).verify(signature, _message(unsigned))
    except (InvalidSignature, ValueError, TypeError):
        raise ProofError("invalid-signature") from None
    return VerifiedPossession(
        **{k: getattr(binding, k) for k in _REFS},
        binding_revision=binding.revision, challenge_digest=expected_digest,
    )


def _unique(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProofError("invalid-proof")
        result[key] = value
    return result


def _constant(_value: str):
    raise ProofError("invalid-proof")


def decode_proof(raw: bytes) -> dict:
    """Bounded strict JSON decode. Shape validation does not verify a signature."""
    if type(raw) is not bytes or len(raw) > 8192:
        raise ProofError("invalid-proof")
    try:
        proof = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ProofError("invalid-proof") from None
    _unsigned(proof)
    return proof


def encode_proof(proof: dict) -> bytes:
    _unsigned(proof)
    try:
        return rfc8785.dumps(proof)
    except (rfc8785.CanonicalizationError, UnicodeError, TypeError, ValueError):
        raise ProofError("invalid-proof") from None
