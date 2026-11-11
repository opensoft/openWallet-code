from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from openwallet_runtime import ProofError, TrustedKeyBinding
from openwallet_runtime.registry import BindingRegistry, binding_from_record, binding_record


def sample():
    return TrustedKeyBinding("binding:a", "wallet:a", "key:a", "subject:a", "custody:a",
                             Ed25519PrivateKey.generate().public_key().public_bytes_raw(), 1, 900, 2000)


def test_durable_binding_and_wire_round_trip(tmp_path):
    registry = BindingRegistry(tmp_path / "state")
    binding = sample()
    registry.register(binding, expected_revision=None)
    assert BindingRegistry(registry.directory).resolve("subject:a", now=1000) == binding
    assert binding_from_record(binding_record(binding)) == binding
    assert os.stat(registry.directory).st_mode & 0o077 == 0
    assert os.stat(registry.path).st_mode & 0o077 == 0


def test_cas_revision_race_has_one_winner(tmp_path):
    registry = BindingRegistry(tmp_path / "state")
    binding = sample()
    registry.register(binding, expected_revision=None)

    def update(revision):
        try:
            registry.register(replace(binding, revision=revision), expected_revision=1)
            return revision
        except ProofError as error:
            assert error.code == "revision-conflict"
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(update, (2, 3)))
    assert len([result for result in results if result is not None]) == 1
    assert registry.resolve("subject:a", now=1000).revision == next(result for result in results if result)


@pytest.mark.parametrize("revision,expected", [(1, 1), (0, 1), (2, None), (2, True), (2, 0)])
def test_rollback_and_wrong_expected_revision_refuse(tmp_path, revision, expected):
    registry = BindingRegistry(tmp_path / "state")
    binding = sample()
    registry.register(binding, expected_revision=None)
    with pytest.raises(ProofError, match="revision-conflict"):
        registry.register(replace(binding, revision=revision), expected_revision=expected)
    assert registry.resolve("subject:a", now=1000) == binding


def test_persistent_tombstone_cannot_be_reactivated_by_revision(tmp_path):
    registry = BindingRegistry(tmp_path / "state")
    binding = sample()
    registry.register(binding, expected_revision=None)
    registry.revoke(binding.binding_ref)
    registry = BindingRegistry(registry.directory)
    with pytest.raises(ProofError, match="revoked-binding"):
        registry.resolve("subject:a", now=1000)
    with pytest.raises(ProofError, match="revoked-binding"):
        registry.register(replace(binding, revision=2), expected_revision=1)


@pytest.mark.parametrize("change", [
    {"custody_ref": "custody:other"}, {"subject_ref": "subject:other", "binding_ref": "binding:other"},
    {"public_key": b"z" * 32},
])
def test_key_ownership_is_immutable_and_failed_update_preserves_binding(tmp_path, change):
    registry = BindingRegistry(tmp_path / "state")
    binding = sample()
    registry.register(binding, expected_revision=None)
    with pytest.raises(ProofError, match="key-owner-conflict"):
        registry.register(replace(binding, revision=2, **change),
                          expected_revision=None if "subject_ref" in change else 1)
    assert registry.resolve("subject:a", now=1000) == binding


@pytest.mark.parametrize("now", [899, 2000, True, -1])
def test_inactive_binding_and_invalid_clock_refuse(tmp_path, now):
    registry = BindingRegistry(tmp_path / "state")
    registry.register(sample(), expected_revision=None)
    with pytest.raises(ProofError):
        registry.resolve("subject:a", now=now)


def test_unsafe_state_and_database_links_refuse_without_touching_target(tmp_path):
    target = tmp_path / "target"
    target.write_text("preserve")
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "registry.sqlite").symlink_to(target)
    with pytest.raises(ProofError, match="unsafe-registry-file"):
        BindingRegistry(state)
    assert target.read_text() == "preserve"
    alias = tmp_path / "alias"
    alias.symlink_to(state, target_is_directory=True)
    with pytest.raises(ProofError, match="unsafe-state-directory"):
        BindingRegistry(alias)
