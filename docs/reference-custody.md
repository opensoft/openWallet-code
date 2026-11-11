# Isolated reference registry and custody

The registry stores current subject bindings in an operator-owned private
SQLite directory. Replacements require the expected prior revision and a
strict increase. Key reference, public bytes and custody ownership cannot
silently move between subjects. Revoked binding references stay tombstoned.
Administration is local; no HTTP register/revoke/export endpoint exists.

`openwallet_runtime.custody` provides explicit mutual-TLS clients with CA and
hostname verification, no proxy/redirect support and bounded I/O. The service
maps exact client-certificate fingerprints to actions and subjects. A
registry-only verifier cannot sign as an agent. The signing callback constructs
the entire expected possession preimage from current trusted metadata and
checks it before signing. Raw client public keys and arbitrary signing domains
are never accepted. Returned signatures are verified again by `create_proof`.

`python -m openwallet_runtime.reference_service --config <private-json>` starts
the isolated reference transport. Configuration names the registry/key
directories, CA/server certificate/key and exact peer policies. No service is
enabled by default. Test/run credentials are generated in private temporary
state, never committed or copied into an image. Signing keys are service-owned
mode-0600 files; this is software custody, not HSM non-exportability.

The existing `isolated_invocable` model applies: isolation contains the key
within the service boundary but evidences environment execution and confers
no unsupervised authority. Human consent and domain permission remain separate.
The Python standard HTTP server is an isolated reference transport, not a
production hosting recommendation. Public availability, hardening, real
workload attestation and live custody approval require separate acceptance.

Run the code-leg suite with `python -m pytest tests/ -q`. It uses real TLS
and crypto with ephemeral local keys. Cross-container source qualification
belongs to the paired openMFA assembly integration gate and records its exact
source bindings and cleanup separately from leg CI or product release.
