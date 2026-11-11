"""Candidate possession-proof runtime; no domain authorization is implied."""
from .proof import (
    PROFILE, ProofError, Signer, TrustedKeyBinding, VerifiedPossession,
    create_proof, decode_proof, encode_proof, verify_proof,
)
__all__ = [
    "PROFILE", "ProofError", "Signer", "TrustedKeyBinding", "VerifiedPossession",
    "create_proof", "decode_proof", "encode_proof", "verify_proof",
]
