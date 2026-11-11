# Candidate wallet possession proof

Status: draft implementation; no accepted runtime release or live MFA claim.

`openwallet_runtime` implements real Ed25519 signing and verification for the candidate `openwallet.challenge-proof.v0` wire profile. The signing input is the fixed product domain separator, NUL, then RFC 8785 bytes of all unsigned fields. It accepts a trusted current `TrustedKeyBinding` and an opaque `Signer`; a client proof cannot select its public key. A successful result establishes possession over the expected challenge digest only.

The canonical candidate proof schema belongs to `opensoft/openWallet-spec` at `contracts/challenge-proof-v0.schema.json`. The legacy Q7 placement override does not move this new contract into code. Governance and the sole task list belong to feature `016-challenge-proof-runtime` in that spec leg.

## Local checks

Use an isolated environment in the declared development bench, from this code leg:

```sh
pip install -e . pytest
python -m pytest tests/ -q
```

Run the existing wallet syntax and plain/strict validator gates as well. Tests use ephemeral in-memory keys. No key export API, replay database or network call is part of this primitive; the registry and challenge issuer own current trust and one-use.

## Trust and limits

The caller authenticates the issuer/challenge before asking custody to sign. Registry references are not proof that remote custody or measured agent composition actually exists. This candidate does not validate a signing broker, trusted supervisor or delegation chain.

A proof or receipt confers no permission, human presence, MFA assurance, exact-request consent or composition attestation. Real custody, provider/discovery and human adapters, compatibility vectors, accepted assembly pins and attended QA remain separate gates. Development package version `0.0.0.dev0` allocates no release. Consumers pin the assembly root after reviewed leg merges; no leg is tagged.
