"""wallet-v1.1's two behaviours, proven the way CI will see them.

Realizes P2b (group 4) of the ratified openxFactory change
`split-openxwallet-repo` — `design.md` D4 (the sweep prunes nested
repositories) and D3 (the register reader emits a durable happy-path NOTE) —
under `clarifications.md` N4. Speckit feature
`specs/013-nested-repo-prune-register-note/`.

Discipline copied from `tests/wallet_yaml_syntax_gate/test_gate.py`: drive the
script as a SUBPROCESS, not an in-process import, so the exit codes the
workflows act on are the ones under test, and build every fixture tree under
`tmp_path` so nothing here can touch the repository.

The prune's whole point is that a nested repository's YAML stops being
adjudicated as a live record of the scanned tree. So the assertions are on the
`repo scan:` note's VALIDATED COUNT — the one number that says how many records
the sweep actually took as real — rather than on the absence of some particular
finding, which a future rule change could make vacuously true.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
VALIDATOR = REPO_ROOT / "scripts" / "validate-openxwallet.py"

SCAN_NOTE = re.compile(
    r"^note  repo scan: (\d+) openxWallet artifact\(s\) validated, "
    r"(\d+) document\(s\) skipped as another kind$", re.M)
PRUNE_NOTE = re.compile(
    r"^note  nested repositories pruned \(not adjudicated\): (.+)$", re.M)
REGISTER_NOTE = re.compile(
    r"^note  intake register read: (\S+) \((\d+) row\(s\)\)$", re.M)
ABSENT_REGISTER_NOTE = "note  no intake register at this tree; nothing to read"
CORPUS_NOTE = ("note  corpus: 17 positive example(s), 36 negative "
               "confirmation(s) across 13/13 requirements")

# A minimal VALID wallet record, kept independent of the packaged corpus on
# purpose: a test that copies a corpus example is also a test of the corpus
# exclusion, and those are different questions (the exclusion has its own test
# below). Shaped on the validator's own S4 self-test probe wallet.
WALLET = {
    "schema_version": 1,
    "kind": "xfactory_wallet_record",
    "wallet_id": "wal-prune-probe-0001",
    "holder": {"holder_id": "agent:prune-probe", "holder_class": "agent"},
    "key_reference": {
        "did": "did:key:z6Mko2FefScUQg9opCriwQmjfcb3Qjnb5bN49hQsEVMo6gee",
        "key_id": "key-prune-0001",
        "signature_algorithm": "ed25519",
    },
    "custody": {"model": "holder_readable", "registry_version": 1},
    "state": "active",
}


# --------------------------------- helpers ---------------------------------

def _run(target: Path | str, *args: str,
         script: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Invoke the validator exactly as `wallet-validation` does."""
    cmd = [sys.executable, str(script or VALIDATOR), str(target), *args]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)


def _validated(out: str) -> int:
    """The number of records the sweep took as REAL. The assertion target."""
    m = SCAN_NOTE.search(out)
    assert m, f"no `repo scan:` note in output:\n{out}"
    return int(m.group(1))


def _pruned(out: str) -> list[str]:
    m = PRUNE_NOTE.search(out)
    return [p.strip() for p in m.group(1).split(",")] if m else []


def _nested_repo(path: Path, kind: str) -> Path:
    """Make `path` a nested repository, in one of the two real on-disk shapes.

    A submodule checkout (and a `git worktree`) carries a `.git` FILE holding a
    `gitdir:` line; a plain nested clone carries a `.git` DIRECTORY. Both mean
    the same thing for this rule, which is why the prune tests for the entry's
    EXISTENCE and never reads it.
    """
    path.mkdir(parents=True, exist_ok=True)
    if kind == "file":
        (path / ".git").write_text("gitdir: ../.git/modules/x\n", encoding="utf-8")
    elif kind == "dir":
        (path / ".git").mkdir()
    else:  # pragma: no cover - a typo in a test is not a test case
        raise ValueError(kind)
    return path


def _write_wallet(directory: Path, wallet_id: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / "live-record.yaml"
    dest.write_text(yaml.safe_dump(dict(WALLET, wallet_id=wallet_id)),
                    encoding="utf-8")
    return dest


# ------------------- US1: the sweep prunes nested repositories -------------

def test_nested_repo_with_a_dot_git_FILE_is_not_adjudicated(tmp_path):
    """A submodule's `.git` is a FILE — which is all `SKIP_DIR_NAMES` misses.

    This is the exact hole D4 closes: `set(path.parts) & SKIP_DIR_NAMES` can
    only match a path COMPONENT named `.git`, and a submodule checkout has no
    such component.
    """
    root = tmp_path / "root"
    root.mkdir()
    _write_wallet(_nested_repo(root / "pinned-product", "file"), "wal-nested-0001")

    r = _run(root)
    assert _validated(r.stdout) == 0, r.stdout
    assert _pruned(r.stdout) == ["pinned-product"], r.stdout


def test_nested_repo_with_a_dot_git_DIRECTORY_is_not_adjudicated(tmp_path):
    """The other real shape: a plain clone nested inside another tree."""
    root = tmp_path / "root"
    root.mkdir()
    _write_wallet(_nested_repo(root / "vendored-clone", "dir"), "wal-nested-0002")

    r = _run(root)
    assert _validated(r.stdout) == 0, r.stdout
    assert _pruned(r.stdout) == ["vendored-clone"], r.stdout


def test_the_control_same_record_outside_any_nested_repo_IS_adjudicated(tmp_path):
    """The prune is a nested-repository rule, not a blanket exclusion.

    Without this case the two above would pass just as well if the sweep had
    stopped adjudicating anything at all.
    """
    root = tmp_path / "root"
    _write_wallet(root / "tenants" / "acme", "wal-outside-0001")

    r = _run(root)
    assert _validated(r.stdout) == 1, r.stdout
    assert _pruned(r.stdout) == [], r.stdout


def test_one_tree_both_cases_at_once(tmp_path):
    """Three copies of one record; only the one outside is adjudicated."""
    root = tmp_path / "root"
    root.mkdir()
    _write_wallet(_nested_repo(root / "sub-as-file", "file"), "wal-a-0001")
    _write_wallet(_nested_repo(root / "sub-as-dir", "dir"), "wal-b-0001")
    _write_wallet(root / "own-records", "wal-c-0001")

    r = _run(root)
    assert _validated(r.stdout) == 1, r.stdout
    assert _pruned(r.stdout) == ["sub-as-dir", "sub-as-file"], r.stdout


def test_the_scan_root_is_never_pruned_by_its_own_dot_git(tmp_path):
    """The ordinary case: a repository scanning itself.

    A prune that keyed on `.git` without excepting the root would make the
    validator adjudicate nothing, everywhere — a silent vacuous pass in every
    real consumer.
    """
    root = tmp_path / "root"
    _nested_repo(root, "file")
    _write_wallet(root / "records", "wal-root-0001")

    r = _run(root)
    assert _validated(r.stdout) == 1, r.stdout
    assert _pruned(r.stdout) == [], r.stdout


def test_a_nested_repo_inside_a_pruned_one_is_not_reported_twice(tmp_path):
    """The outer prune already removed everything below it."""
    root = tmp_path / "root"
    root.mkdir()
    outer = _nested_repo(root / "outer", "file")
    _write_wallet(_nested_repo(outer / "inner", "dir"), "wal-inner-0001")

    r = _run(root)
    assert _validated(r.stdout) == 0, r.stdout
    assert _pruned(r.stdout) == ["outer"], r.stdout


def test_no_prune_note_when_there_is_nothing_to_prune(tmp_path):
    """A clean tree's output is unchanged from wallet-v1.0's."""
    root = tmp_path / "root"
    _write_wallet(root / "records", "wal-clean-0001")

    r = _run(root)
    assert PRUNE_NOTE.search(r.stdout) is None, r.stdout


def test_skip_dir_names_still_behaves_as_it_did(tmp_path):
    """`SKIP_DIR_NAMES` keeps its job: the prune is additive, not a rewrite."""
    root = tmp_path / "root"
    for skipped in (".venv", "node_modules", "__pycache__"):
        _write_wallet(root / skipped / "nested", f"wal-{skipped.strip('._')}-0001")
    _write_wallet(root / "records", "wal-kept-0001")

    r = _run(root)
    assert _validated(r.stdout) == 1, r.stdout


def test_the_packaged_corpus_exclusion_still_keys_on_path_parts(tmp_path):
    """S4.6: the corpus exclusion holds INSIDE a nested repository too.

    Both mechanisms firing on one path is not an error — and the exclusion is
    what keeps the 36 negatives from being re-adjudicated as live records when a
    consumer vendors the family. Asserted here because the real hazard the
    prune addresses is the NON-`examples/` YAML a carve brings along.
    """
    root = tmp_path / "root"
    # Corpus-shaped path OUTSIDE any nested repository: excluded by parts.
    corpus = root / "contracts" / "openxwallet" / "examples"
    _write_wallet(corpus, "wal-corpus-0001")
    # Corpus-shaped path INSIDE a nested repository: excluded twice over.
    nested = _nested_repo(root / "pinned", "file")
    _write_wallet(nested / "contracts" / "openxwallet" / "examples",
                  "wal-corpus-0002")

    r = _run(root)
    assert _validated(r.stdout) == 0, r.stdout
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_repository_itself_still_reports_its_own_corpus(tmp_path):
    """The 17 positives and 36 negatives, unchanged, over 13/13 requirements."""
    r = _run(REPO_ROOT)
    assert CORPUS_NOTE in r.stdout, r.stdout
    assert r.returncode == 0, r.stdout + r.stderr


# ------------------- US2: the durable register-read NOTE -------------------

FUTURE = "2099-06-30T23:59:59Z"
REVIEW_TOKEN = "review"
ROOT_ISSUER = "Brett.Heap@opensoft.one"

REGISTER_WALLET = dict(WALLET, wallet_id="wal-register-probe-0001",
                       holder={"holder_id": "agent:register-probe",
                               "holder_class": "agent"})
REGISTER_GRANT = {
    "schema_version": 1,
    "kind": "xfactory_wallet_grant",
    "grant_id": "grant-register-probe-0001",
    "audience": {"wallet_ref": "wal-register-probe-0001",
                 "holder_ref": "agent:register-probe"},
    "scope": {
        "acts": [REVIEW_TOKEN],
        "authority_tier": "act",
        "objects": ["opensoft/openxFactory"],
        "approval_posture": {
            "hermes_approval_required_before_apply": True,
            "authority_agents_may_approve": False,
            "human_escalation_required_for": ["irreversible_external_effect"],
        },
    },
    "expires_at": FUTURE,
    "issued_at": "2026-08-24T00:00:00Z",
    "state": "active",
    "issued_by": ROOT_ISSUER,
}
REGISTER_ROW = {
    "row_id": "row-register-probe-0001",
    "holder_ref": "agent:register-probe",
    "wallet_ref": "wal-register-probe-0001",
    "target_repo": "opensoft/openxFactory",
    "act": REVIEW_TOKEN,
    "authority_tier": "act",
    "grant_ref": "grant-register-probe-0001",
    "expires_at": FUTURE,
    "state": "active",
}
ATTESTATION = {
    "attestation_id": "attest-custody-wal-register-probe-0001",
    "subject_wallet_ref": "wal-register-probe-0001",
    "custody_model_attested": "holder_readable",
    "verified_by": {"name": "Brett Heap", "role": "responsible operator",
                    "standing": "Human Escalation Contract"},
    "verified_at": "2026-08-24T12:00:00Z",
    "verified_against": {"method": "operator-minted ed25519 keypair",
                         "isolation_claimed": False},
}


def _register_tree(root: Path, rows: list[dict] | None = None) -> Path:
    """A tree whose register reads CLEAN, end to end.

    Shaped on the validator's own S4 self-test fixtures (`_s4_tree`,
    `s4_row`, `s4_grant`, `s4_wallet`, `s4_attest`), which are local to
    `self_test()` and so cannot be imported — a subprocess-driven test needs
    them as FILES anyway.
    """
    records = root / "governance" / "wallets"
    records.mkdir(parents=True)
    (records / "wallet.yaml").write_text(
        yaml.safe_dump(REGISTER_WALLET), encoding="utf-8")
    (records / "grant.yaml").write_text(
        yaml.safe_dump(REGISTER_GRANT), encoding="utf-8")

    ra = root / "governance" / "review-authority"
    (ra / "attestations").mkdir(parents=True)
    (ra / "register.yaml").write_text(
        yaml.safe_dump({"register_version": 1,
                        "rows": rows if rows is not None else [REGISTER_ROW]}),
        encoding="utf-8")
    (ra / "attestations" / "custody-attest.yaml").write_text(
        yaml.safe_dump(ATTESTATION), encoding="utf-8")
    return root


def test_a_successful_register_read_says_so_exactly_once(tmp_path):
    """D3's durable positive line, and the whole reason it exists.

    Before this, `check_register` was SILENT on success: the only output naming
    the register was a failure finding, and the absent-register note named no
    path — so "the register was read" could only be inferred from a conjunction
    of absences.
    """
    r = _run(_register_tree(tmp_path / "consumer"))
    hits = REGISTER_NOTE.findall(r.stdout)
    assert len(hits) == 1, r.stdout
    path, rows = hits[0]
    assert path == "governance/review-authority/register.yaml", r.stdout
    assert rows == "1", r.stdout


def test_the_register_note_leaves_a_strict_run_green(tmp_path):
    """S4.5: an `f.note`, NEVER a warning.

    `report()` reds a `--strict` run on warnings and a live consumer runs
    `--strict`, so the CLASS of this line is a compatibility term, not a
    presentation choice.
    """
    root = _register_tree(tmp_path / "consumer")
    plain = _run(root)
    strict = _run(root, "--strict")
    assert plain.returncode == 0, plain.stdout + plain.stderr
    assert strict.returncode == 0, strict.stdout + strict.stderr
    assert REGISTER_NOTE.search(strict.stdout), strict.stdout
    assert "WARN" not in strict.stdout, strict.stdout


def test_the_register_path_is_relative_to_the_scan_root(tmp_path):
    """Relative, so the line is identical on a laptop and on a CI runner.

    The downstream consumer-gate test (D3, landing at P3) asserts on it; an
    absolute path would differ between checkouts and force a substring match.
    """
    root = _register_tree(tmp_path / "deeply" / "nested" / "consumer")
    r = _run(root)
    m = REGISTER_NOTE.search(r.stdout)
    assert m, r.stdout
    assert not Path(m.group(1)).is_absolute(), m.group(1)
    assert str(tmp_path) not in m.group(1), m.group(1)


def test_no_register_keeps_the_ratified_absent_behaviour(tmp_path):
    """Unchanged: absent register + no review grants is a legitimate posture."""
    root = tmp_path / "root"
    _write_wallet(root / "records", "wal-noreg-0001")

    r = _run(root, "--strict")
    assert ABSENT_REGISTER_NOTE in r.stdout, r.stdout
    assert REGISTER_NOTE.search(r.stdout) is None, r.stdout
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_register_inside_a_nested_repo_is_not_read(tmp_path):
    """Both behaviours meeting: the register is resolved from the SCAN ROOT.

    A consumer that pointed the validator at the nested product instead of its
    own root would read the product's register, not its own — which is why
    D4 refused "narrow the scan scope" as the prune's mechanism.
    """
    root = tmp_path / "root"
    root.mkdir()
    _register_tree(_nested_repo(root / "pinned-product", "file"))

    r = _run(root)
    assert REGISTER_NOTE.search(r.stdout) is None, r.stdout
    assert ABSENT_REGISTER_NOTE in r.stdout, r.stdout
    assert _pruned(r.stdout) == ["pinned-product"], r.stdout


# ------------------- US3: nothing a live consumer keys on moves -------------

def test_the_command_line_surface_is_unchanged(tmp_path):
    """S4.3: no `--exclude`. An exclusion the caller supplies can be omitted.

    Both R6's zero-refactor proof and D3's pinned-invocation test key on this
    signature, so it is asserted rather than remembered.
    """
    r = subprocess.run([sys.executable, str(VALIDATOR), "--help"],
                       capture_output=True, text=True, cwd=REPO_ROOT)
    assert r.returncode == 0, r.stderr
    options = set(re.findall(r"(?<![\w-])(--[a-z][a-z-]*)", r.stdout))
    assert options == {"--strict", "--help"}, sorted(options)
    assert "path" in r.stdout


def test_this_repository_adjudicates_with_no_error_and_no_warning(tmp_path):
    """The durable half of the corpus-identity proof, runnable anywhere.

    The self-test adjudicates all 17 positives and all 36 negatives on every
    invocation and asserts each negative fails with its EXPECTED code, so a
    clean summary line over this repository IS the corpus identity statement —
    and unlike the git-based half below, it needs no history.
    """
    r = _run(REPO_ROOT, "--strict")
    assert "validate-openxwallet: 0 error(s), 0 warning(s)" in r.stdout, r.stdout
    assert r.returncode == 0, r.stdout + r.stderr


def _baseline_script(tmp_path: Path) -> Path | None:
    """The PREVIOUS version of the validator, recovered from git history.

    Never by stashing or checking out: this repository's working tree is not
    this test's to mutate. The copy is written into a scratch `scripts/`
    directory whose sibling `contracts/` is a symlink to the real one, because
    the script derives `ROOT` from its own location.
    """
    current = VALIDATOR.read_text(encoding="utf-8")
    for ref in ("origin/main", "main", "HEAD^1", "HEAD^"):
        got = subprocess.run(
            ["git", "show", f"{ref}:scripts/validate-openxwallet.py"],
            capture_output=True, text=True, cwd=REPO_ROOT)
        if got.returncode != 0 or not got.stdout:
            continue
        # NEVER fall back to a blob equal to the working copy. A candidate list
        # ending at `HEAD` would compare this version against ITSELF wherever
        # the base ref is unreachable -- a depth-1 CI checkout of a merge ref,
        # say -- and pass vacuously. Vacuous passes are the exact failure class
        # this wave refuses, so an identical blob is treated as no baseline at
        # all and the test SKIPS with its reason.
        if got.stdout == current:
            continue
        shadow = tmp_path / "baseline"
        (shadow / "scripts").mkdir(parents=True)
        dest = shadow / "scripts" / "validate-openxwallet.py"
        dest.write_text(got.stdout, encoding="utf-8")
        os.symlink(REPO_ROOT / "contracts", shadow / "contracts")
        return dest
    return None


def test_the_previous_version_adjudicates_the_corpus_identically(tmp_path):
    """FR-009: the finding set does not move. Notes do, by design.

    Skipped LOUDLY, with a reason, when git history is unavailable (a tarball
    export, or a depth-1 CI checkout of a merge ref whose parents were never
    fetched). A skip that says why is honest; a silent pass is the
    vacuous-pass class this whole wave refuses.
    """
    baseline = _baseline_script(tmp_path)
    if baseline is None:
        pytest.skip("no git blob for a DIFFERENT, previous "
                    "scripts/validate-openxwallet.py is reachable from this "
                    "checkout, so there is nothing to compare against")

    def findings(out: str) -> set[str]:
        return {ln for ln in out.splitlines()
                if ln.startswith(("ERROR [", "WARN  ["))}

    before = _run(REPO_ROOT, script=baseline)
    after = _run(REPO_ROOT)
    if before.returncode == 2:  # pragma: no cover
        pytest.skip(f"the recovered baseline could not run: {before.stderr}")

    assert findings(before.stdout) == findings(after.stdout), (
        f"finding set moved.\nBEFORE:\n{before.stdout}\nAFTER:\n{after.stdout}")
    assert before.returncode == after.returncode == 0
