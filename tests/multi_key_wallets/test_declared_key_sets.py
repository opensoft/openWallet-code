"""wallet-v1.3: a wallet is identified by its declared KEY SET.

Realizes the openXwallet change `add-multi-key-wallets` (capability
`openxwallet`, ratified 2026-08-28 by Brett Heap's in-session ruling "rule
option 1 and build it") — Speckit feature `specs/015-multi-key-wallets/`.

Discipline copied from `tests/per_seat_register_entries/`: drive the script as a
SUBPROCESS so the exit codes the workflows act on are the ones under test, and
build every fixture tree under `tmp_path` so nothing here can touch the
repository or the packaged corpus.

WHY THE ASSERTIONS ARE WHAT THEY ARE. Two of this change's rules are BASIS
changes rather than new refusals — `custody-model-mismatch` now compares against
the presenting key's custody, and the presenting-key binding now resolves
against the declared set — and a basis change can fail in the one direction a
"no findings" assertion cannot see: by silently never firing. So every rule here
is probed in BOTH directions, and the single-key no-op cases are asserted as
hard as the multi-key ones. The alignment pass on this change's packet found
exactly that defect in the first draft, and this file is where it stays found.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
VALIDATOR = REPO_ROOT / "scripts" / "validate-openxwallet.py"
EXAMPLES = REPO_ROOT / "contracts" / "openxwallet" / "examples"

DECLARED_KEYS_NOTE = re.compile(
    r"^note  wallet '([^']+)': (\d+) declared key\(s\) adjudicated ", re.M)

# base58btc, the alphabet `public_key_multibase`'s pattern pins. Encoded here
# rather than imported from the validator: a test that borrows the code under
# test cannot catch that code being wrong.
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = _B58[rest] + out
    leading = 0
    for byte in raw:
        if byte:
            break
        leading += 1
    return _B58[0] * leading + out


def _keypair(label: str) -> tuple[str, str]:
    """A deterministic (public_key_multibase, key_fingerprint) pair.

    Deterministic so a failure is reproducible, and labelled so it is obvious
    nobody holds a private half. The 32 bytes go through `did:key`'s own
    encoding — `z` plus base58btc of the ed25519 multicodec prefix and the raw
    key — because that is what the validator decodes.
    """
    raw = hashlib.sha256(("openxwallet test / " + label).encode()).digest()
    return ("z" + _b58encode(b"\xed\x01" + raw),
            "sha256:" + hashlib.sha256(raw).hexdigest())


def _wallet(wallet_id: str, *, custody: str, keys: list | None = None,
            state: str = "active") -> dict:
    doc = {
        "schema_version": 1,
        "kind": "xfactory_wallet_record",
        "wallet_id": wallet_id,
        "holder": {"holder_id": f"agent:{wallet_id}", "holder_class": "agent"},
        "key_reference": {
            "did": f"did:web:xforge.us:wallets:{wallet_id}",
            "key_id": f"key-{wallet_id}-primary",
            "signature_algorithm": "ed25519",
        },
        "custody": {"model": custody, "registry_version": 1},
        "state": state,
    }
    if keys is not None:
        doc["keys"] = keys
    return doc


def _key(key_id: str, *, custody: str, with_public_half: bool = True,
         fingerprint: str | None = None, **over: object) -> dict:
    multibase, computed = _keypair(key_id)
    entry: dict = {
        "did": f"did:key:{multibase}",
        "key_id": key_id,
        "key_fingerprint": fingerprint or computed,
        "custody": {"model": custody, "registry_version": 1},
    }
    if with_public_half:
        entry["public_key_multibase"] = multibase
    entry.update(over)
    return entry


def _grant(grant_id: str, *, wallet_id: str, tier: str, act: str) -> dict:
    posture = {
        "hermes_approval_required_before_apply": tier != "act_unsupervised",
        "authority_agents_may_approve": False,
    }
    return {
        "schema_version": 1,
        "kind": "xfactory_wallet_grant",
        "grant_id": grant_id,
        "audience": {"wallet_ref": wallet_id, "holder_ref": f"agent:{wallet_id}"},
        "scope": {"acts": [act], "authority_tier": tier,
                  "approval_posture": posture},
        "expires_at": "2099-12-31T23:59:59Z",
        "issued_at": "2026-08-28T09:00:00Z",
        "issued_by": "opensoft",
        "state": "active",
    }


def _exercise(exercise_id: str, *, grant_id: str, wallet_id: str, key_id: str,
              act: str, custody_in_force: str, verified: bool = True,
              event_class: str = "authenticated",
              mode: str = "key_attributed",
              outcome: str = "permitted") -> dict:
    return {
        "schema_version": 1,
        "kind": "xfactory_wallet_grant_exercise",
        "exercise_id": exercise_id,
        "grant_ref": grant_id,
        "act": act,
        "occurred_at": "2026-08-28T10:00:00Z",
        "event_class": event_class,
        "proof_of_possession": {
            "presented": True,
            "verified": verified,
            "signature_algorithm": "ed25519",
            "signed_over": "request_digest",
            "presenting_key_ref": key_id,
        },
        "attribution": {
            "mode": mode,
            "presenting_key_ref": key_id,
            "wallet_ref": wallet_id,
            "holder_ref": f"agent:{wallet_id}",
        },
        "custody_model_in_force": custody_in_force,
        "revocation_check": {"performed_at_exercise": True, "result": "active"},
        "outcome": outcome,
    }


def _tree(root: Path, *docs: dict) -> Path:
    records = root / "governance" / "wallets"
    records.mkdir(parents=True)
    for index, doc in enumerate(docs):
        (records / f"doc-{index:02d}.yaml").write_text(
            yaml.safe_dump(doc), encoding="utf-8")
    return root


def _run(target: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(VALIDATOR), str(target), *args],
                          capture_output=True, text=True)


def _codes(out: str) -> set[str]:
    return set(re.findall(r"^ERROR \[([^]]+)]", out, re.M))


def _tree_codes(out: str) -> set[str]:
    """Codes from the SCANNED TREE only.

    The packaged corpus runs on every invocation, so a test that asserted over
    every code in the output would be asserting about the corpus too. Findings
    on packaged files carry a `contracts/openxwallet/` label, so they are
    excluded by line rather than by hope.
    """
    out = "\n".join(line for line in out.splitlines()
                    if "contracts/openxwallet" not in line)
    return _codes(out)


# ----------------------- the encoding, proven independently -----------------

def test_the_fixture_encoding_round_trips():
    """The 32 bytes, the multibase and the fingerprint are one key.

    Asserted without the validator: if this helper were wrong, every negative
    below would pass for the wrong reason.
    """
    multibase, fingerprint = _keypair("round-trip")
    assert multibase.startswith("z6Mk")
    number = 0
    for char in multibase[1:]:
        number = number * 58 + _B58.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    assert raw[:2] == b"\xed\x01"
    assert len(raw) == 34
    assert "sha256:" + hashlib.sha256(raw[2:]).hexdigest() == fingerprint


# --------------------------------- positives --------------------------------

def test_a_single_key_wallet_is_unchanged(tmp_path):
    """The backward-compatibility claim, asserted rather than argued.

    A record with no `keys:` declares a set of one and validates clean — and
    emits NO declared-key note, because the note exists for a consumer gate to
    assert a SET was adjudicated and a set of one is the old world.
    """
    wallet = _wallet("wal-single-0001", custody="holder_readable")
    grant = _grant("grant-single-0001", wallet_id="wal-single-0001",
                   tier="act", act="review_change")
    exercise = _exercise("exr-single-0001", grant_id="grant-single-0001",
                         wallet_id="wal-single-0001",
                         key_id="key-wal-single-0001-primary",
                         act="review_change",
                         custody_in_force="holder_readable")
    result = _run(_tree(tmp_path / "t", wallet, grant, exercise), "--strict")
    assert result.returncode == 0, result.stdout
    assert not _tree_codes(result.stdout)
    assert "wal-single-0001" not in result.stdout


def test_a_multi_key_wallet_validates_and_is_noted(tmp_path):
    """Several keys, mixed custody, and the count the gate can assert on."""
    keys = [_key("key-multi-seat-a", custody="holder_readable"),
            _key("key-multi-seat-b", custody="isolated_invocable",
                 with_public_half=False)]
    wallet = _wallet("wal-multi-0002",
                     custody="isolated_per_use_authorized", keys=keys)
    result = _run(_tree(tmp_path / "t", wallet), "--strict")
    assert result.returncode == 0, result.stdout
    noted = {m.group(1): int(m.group(2))
             for m in DECLARED_KEYS_NOTE.finditer(result.stdout)}
    assert noted["wal-multi-0002"] == 3


def test_an_additional_key_may_present_the_grant(tmp_path):
    """Rule (r) over the declared SET: a non-primary key binds to the audience,
    and the custody in force is THAT key's."""
    keys = [_key("key-present-seat", custody="holder_readable")]
    wallet = _wallet("wal-present-0003",
                     custody="isolated_per_use_authorized", keys=keys)
    grant = _grant("grant-present-0003", wallet_id="wal-present-0003",
                   tier="act", act="review_change")
    exercise = _exercise("exr-present-0003", grant_id="grant-present-0003",
                         wallet_id="wal-present-0003",
                         key_id="key-present-seat", act="review_change",
                         custody_in_force="holder_readable")
    result = _run(_tree(tmp_path / "t", wallet, grant, exercise), "--strict")
    assert result.returncode == 0, result.stdout
    assert not _tree_codes(result.stdout)


def test_a_weaker_key_is_admitted(tmp_path):
    """A key may be WEAKER than its wallet. The direction matters: capping the
    weak case at declaration would refuse the ordinary arrangement, so it is
    capped at USE instead."""
    keys = [_key("key-weak-seat", custody="holder_readable")]
    wallet = _wallet("wal-weak-0004",
                     custody="isolated_per_use_authorized", keys=keys)
    result = _run(_tree(tmp_path / "t", wallet), "--strict")
    assert result.returncode == 0, result.stdout


def test_a_truthful_refusal_over_the_key_ceiling_is_valid(tmp_path):
    """The outcome guard, which the alignment pass caught missing.

    The exercise contract closes a `custody_ceiling_exceeded` refusal code for
    exactly this event. A record that TRUTHFULLY documents the refusal must be
    representable, or the cap makes honesty unrecordable.
    """
    keys = [_key("key-refusal-seat", custody="holder_readable")]
    wallet = _wallet("wal-refusal-0005",
                     custody="isolated_per_use_authorized", keys=keys)
    grant = _grant("grant-refusal-0005", wallet_id="wal-refusal-0005",
                   tier="act_unsupervised", act="publish_release")
    exercise = _exercise("exr-refusal-0005", grant_id="grant-refusal-0005",
                         wallet_id="wal-refusal-0005",
                         key_id="key-refusal-seat", act="publish_release",
                         custody_in_force="holder_readable",
                         outcome="refused")
    exercise["refusal"] = {
        "code": "custody_ceiling_exceeded",
        "statement": "the presenting key's custody evidences the environment, "
                     "and this tier requires evidence the holder acted",
    }
    result = _run(_tree(tmp_path / "t", wallet, grant, exercise), "--strict")
    assert "presenting-key-evidence-cap" not in _tree_codes(result.stdout), \
        result.stdout


def test_retiring_one_key_leaves_the_others_working(tmp_path):
    """Rotation must not park a council. The retired key's declaration STAYS,
    the wallet's standing is untouched, and its sibling still presents."""
    keys = [_key("key-rot-live", custody="holder_readable"),
            _key("key-rot-dead", custody="holder_readable", state="revoked")]
    wallet = _wallet("wal-rot-0006", custody="holder_readable", keys=keys)
    grant = _grant("grant-rot-0006", wallet_id="wal-rot-0006",
                   tier="act", act="review_change")
    exercise = _exercise("exr-rot-0006", grant_id="grant-rot-0006",
                         wallet_id="wal-rot-0006", key_id="key-rot-live",
                         act="review_change",
                         custody_in_force="holder_readable")
    result = _run(_tree(tmp_path / "t", wallet, grant, exercise), "--strict")
    assert result.returncode == 0, result.stdout
    assert not _tree_codes(result.stdout)


def test_an_act_already_attributed_to_a_retired_key_stays_readable(tmp_path):
    """The reason a declaration is append-only rather than deleted.

    A committed exercise naming a retired key, recorded as anything other than
    `permitted`, must keep validating — the validator re-adjudicates every file
    in a scanned tree on every run, so a rotation that broke this would rewrite
    the verdict on history.
    """
    keys = [_key("key-hist-dead", custody="holder_readable", state="revoked")]
    wallet = _wallet("wal-hist-0007", custody="holder_readable", keys=keys)
    grant = _grant("grant-hist-0007", wallet_id="wal-hist-0007",
                   tier="act", act="review_change")
    exercise = _exercise("exr-hist-0007", grant_id="grant-hist-0007",
                         wallet_id="wal-hist-0007", key_id="key-hist-dead",
                         act="review_change",
                         custody_in_force="holder_readable",
                         outcome="refused")
    exercise["refusal"] = {
        "code": "grant_revoked",
        "statement": "the presenting key's declaration was retired before this "
                     "act reached apply",
    }
    result = _run(_tree(tmp_path / "t", wallet, grant, exercise), "--strict")
    assert not _tree_codes(result.stdout), result.stdout


# --------------------------------- refusals ---------------------------------

def test_a_presenting_key_outside_the_declared_set_is_refused(tmp_path):
    keys = [_key("key-set-seat-a", custody="holder_readable")]
    wallet = _wallet("wal-set-0008", custody="holder_readable", keys=keys)
    grant = _grant("grant-set-0008", wallet_id="wal-set-0008",
                   tier="act", act="review_change")
    exercise = _exercise("exr-set-0008", grant_id="grant-set-0008",
                         wallet_id="wal-set-0008", key_id="key-set-seat-b",
                         act="review_change",
                         custody_in_force="holder_readable")
    result = _run(_tree(tmp_path / "t", wallet, grant, exercise), "--strict")
    assert "presenting-key-unresolved" in _tree_codes(result.stdout)
    assert "DECLARED KEY SET" in result.stdout


def test_a_duplicated_key_identifier_is_refused(tmp_path):
    """Both spellings of the defect: two `keys:` entries, and a `keys:` entry
    repeating the primary. Declaration order must not pick the custody."""
    dup = [_key("key-dup-seat", custody="holder_readable"),
           _key("key-dup-seat", custody="isolated_invocable")]
    result = _run(_tree(tmp_path / "a",
                        _wallet("wal-dup-0009", custody="holder_readable",
                                keys=dup)), "--strict")
    assert "declared-key-duplicate" in _tree_codes(result.stdout)

    shadow = [_key("key-wal-dup2-0010-primary", custody="isolated_invocable")]
    result = _run(_tree(tmp_path / "b",
                        _wallet("wal-dup2-0010", custody="holder_readable",
                                keys=shadow)), "--strict")
    assert "declared-key-duplicate" in _tree_codes(result.stdout)


def test_a_key_may_not_outrank_its_wallet(tmp_path):
    keys = [_key("key-rank-strong", custody="isolated_per_use_authorized")]
    wallet = _wallet("wal-rank-0011", custody="holder_readable", keys=keys)
    result = _run(_tree(tmp_path / "t", wallet), "--strict")
    assert "declared-key-raises-authority" in _tree_codes(result.stdout)


def test_a_declared_key_custody_outside_the_closed_set_is_refused(tmp_path):
    """Rule (s) at the new depth, under the EXISTING code — one defect, one
    name. The message must name the key, or a multi-key record's refusal does
    not say which declaration failed."""
    keys = [_key("key-closed-seat", custody="hardware_hsm_fully_trusted")]
    wallet = _wallet("wal-closed-0012", custody="holder_readable", keys=keys)
    result = _run(_tree(tmp_path / "t", wallet), "--strict")
    assert "custody-model-unknown" in _tree_codes(result.stdout)
    assert "key-closed-seat" in result.stdout


def test_a_fingerprint_that_does_not_recompute_is_refused(tmp_path):
    """Legal shape, wrong key — the transcription slip a join token exists to
    catch. The refusal names BOTH values, or a reader cannot tell which of the
    two claims to fix."""
    _other_multibase, other_fingerprint = _keypair("somebody-else")
    keys = [_key("key-fp-seat", custody="holder_readable",
                 fingerprint=other_fingerprint)]
    wallet = _wallet("wal-fp-0013", custody="holder_readable", keys=keys)
    result = _run(_tree(tmp_path / "t", wallet), "--strict")
    assert "declared-key-fingerprint-mismatch" in _tree_codes(result.stdout)
    assert other_fingerprint in result.stdout
    assert _keypair("key-fp-seat")[1] in result.stdout


def test_a_public_half_that_does_not_decode_is_refused(tmp_path):
    """A malformed public half is refused rather than skipped: an unverifiable
    fingerprint is not a verified one."""
    keys = [_key("key-mb-seat", custody="holder_readable",
                 public_key_multibase="z" + "1" * 8)]
    wallet = _wallet("wal-mb-0014", custody="holder_readable", keys=keys)
    result = _run(_tree(tmp_path / "t", wallet), "--strict")
    assert "declared-key-fingerprint-mismatch" in _tree_codes(result.stdout)


def test_the_custody_in_force_is_the_presenting_keys(tmp_path):
    """The BASIS change, in the direction that matters: naming another key's
    custody — a model this wallet really does declare — is refused."""
    keys = [_key("key-basis-a", custody="holder_readable"),
            _key("key-basis-b", custody="isolated_invocable")]
    wallet = _wallet("wal-basis-0015",
                     custody="isolated_per_use_authorized", keys=keys)
    grant = _grant("grant-basis-0015", wallet_id="wal-basis-0015",
                   tier="act", act="review_change")
    exercise = _exercise("exr-basis-0015", grant_id="grant-basis-0015",
                         wallet_id="wal-basis-0015", key_id="key-basis-a",
                         act="review_change",
                         custody_in_force="isolated_invocable")
    result = _run(_tree(tmp_path / "t", wallet, grant, exercise), "--strict")
    assert "custody-model-mismatch" in _tree_codes(result.stdout)
    assert "presenting key 'key-basis-a'" in result.stdout


def test_the_single_key_basis_still_fires(tmp_path):
    """The regression the alignment pass caught: `key_reference` carries no
    custody block, so a basis lookup returning nothing for a primary key would
    delete this check silently for every record in the estate."""
    wallet = _wallet("wal-sbasis-0016",
                     custody="isolated_per_use_authorized")
    grant = _grant("grant-sbasis-0016", wallet_id="wal-sbasis-0016",
                   tier="act", act="review_change")
    exercise = _exercise("exr-sbasis-0016", grant_id="grant-sbasis-0016",
                         wallet_id="wal-sbasis-0016",
                         key_id="key-wal-sbasis-0016-primary",
                         act="review_change",
                         custody_in_force="holder_readable")
    result = _run(_tree(tmp_path / "t", wallet, grant, exercise), "--strict")
    assert "custody-model-mismatch" in _tree_codes(result.stdout)
    assert "wallet 'wal-sbasis-0016' declares" in result.stdout


def test_a_grant_above_the_presenting_keys_ceiling_is_refused(tmp_path):
    keys = [_key("key-cap-seat", custody="holder_readable")]
    wallet = _wallet("wal-cap-0017",
                     custody="isolated_per_use_authorized", keys=keys)
    grant = _grant("grant-cap-0017", wallet_id="wal-cap-0017",
                   tier="act_unsupervised", act="publish_release")
    exercise = _exercise("exr-cap-0017", grant_id="grant-cap-0017",
                         wallet_id="wal-cap-0017", key_id="key-cap-seat",
                         act="publish_release",
                         custody_in_force="holder_readable")
    result = _run(_tree(tmp_path / "t", wallet, grant, exercise), "--strict")
    assert "presenting-key-evidence-cap" in _tree_codes(result.stdout)


def test_an_exercise_under_a_retired_key_is_refused(tmp_path):
    keys = [_key("key-dead-seat", custody="holder_readable", state="revoked")]
    wallet = _wallet("wal-dead-0018", custody="holder_readable", keys=keys)
    grant = _grant("grant-dead-0018", wallet_id="wal-dead-0018",
                   tier="act", act="review_change")
    exercise = _exercise("exr-dead-0018", grant_id="grant-dead-0018",
                         wallet_id="wal-dead-0018", key_id="key-dead-seat",
                         act="review_change",
                         custody_in_force="holder_readable")
    result = _run(_tree(tmp_path / "t", wallet, grant, exercise), "--strict")
    assert "revoked-chain-exercised" in _tree_codes(result.stdout)
    assert "a retired key presents nothing" in result.stdout


def test_an_unverified_signature_does_not_establish_a_key(tmp_path):
    """The `verified is True` gate, which the alignment pass caught.

    `presenting_key` falls back to the record's own UNVERIFIED attribution
    block, so keying the custody basis or the evidence cap on it would measure
    an exercise against self-declared data. Here the record claims a verification
    failure AND names a key whose custody would trip both new checks; neither
    may fire, and the two codes that DO apply to an unverified record are the
    ones that fire instead.
    """
    keys = [_key("key-unver-seat", custody="holder_readable")]
    wallet = _wallet("wal-unver-0019",
                     custody="isolated_per_use_authorized", keys=keys)
    grant = _grant("grant-unver-0019", wallet_id="wal-unver-0019",
                   tier="act_unsupervised", act="publish_release")
    exercise = _exercise("exr-unver-0019", grant_id="grant-unver-0019",
                         wallet_id="wal-unver-0019", key_id="key-unver-seat",
                         act="publish_release",
                         custody_in_force="isolated_per_use_authorized",
                         verified=False,
                         event_class="verification_failure",
                         outcome="refused")
    exercise["refusal"] = {
        "code": "proof_verification_failed",
        "statement": "a signature was presented and did not verify",
    }
    codes = _tree_codes(_run(_tree(tmp_path / "t", wallet, grant, exercise),
                             "--strict").stdout)
    assert "presenting-key-evidence-cap" not in codes
    assert "custody-model-mismatch" not in codes


# ------------------------- the packaged corpus itself ------------------------

def test_the_packaged_multi_key_fixtures_are_present():
    """Named probes, asserted from OUTSIDE the validator too.

    Every invariant this change added attributes to a requirement other
    fixtures already cover, so the per-requirement closure inside the validator
    cannot notice one of these being deleted. The validator now names them; this
    is the second lock, in the suite the ruleset requires.
    """
    for name in ("wallet-declares-one-key-identifier-twice.yaml",
                 "wallet-declared-key-omits-its-custody.yaml",
                 "wallet-declared-key-outranks-its-wallet.yaml",
                 "wallet-declared-key-fingerprint-does-not-recompute.yaml",
                 "exercise-presenting-key-outside-the-declared-set.yaml",
                 "exercise-tier-above-the-presenting-key-ceiling.yaml",
                 "exercise-custody-of-another-key-of-the-same-wallet.yaml",
                 "exercise-permitted-under-a-retired-declared-key.yaml",
                 "exercise-single-key-custody-not-the-wallets.yaml"):
        assert (EXAMPLES / "negative" / name).is_file(), name
    for name in ("wallet-agent-council-multi-key.example.yaml",
                 "grant-council-act-tier.example.yaml",
                 "grant-council-unsupervised-tier.example.yaml",
                 "exercise-presented-by-an-additional-key.example.yaml"):
        assert (EXAMPLES / name).is_file(), name


def test_every_packaged_key_identifier_is_declared_by_one_wallet():
    """`key_id` is DID-scoped, so a reused identifier makes the index
    two-owner and refuses every exercise presenting it as AMBIGUOUS — turning
    shipped positives red for a reason unrelated to what they test. The
    multi-key fixtures widened the identifier surface, so this is asserted."""
    owners: dict[str, list[str]] = {}
    for path in sorted(EXAMPLES.glob("*.example.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or doc.get("kind") != "xfactory_wallet_record":
            continue
        wallet_id = doc["wallet_id"]
        ids = [doc["key_reference"]["key_id"]]
        ids += [entry["key_id"] for entry in doc.get("keys", [])]
        assert len(ids) == len(set(ids)), f"{wallet_id} declares a key twice"
        for key_id in ids:
            owners.setdefault(key_id, []).append(wallet_id)
    collisions = {k: v for k, v in owners.items() if len(v) > 1}
    assert not collisions, collisions
