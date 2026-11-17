"""The canonical filename preserves the entire accepted wheel closure."""
import hashlib
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[2]
# Complete reviewed bytes from openWallet-code@b7c8ca1e0f9b:requirements-ci.lock.
APPROVED_CLOSURE_SHA256 = "b68e19651565f26d7762e5bc8626cb71b5844cd4cbb168d42182a3539e35d65f"


def test_canonical_wheel_closure_retains_all_reviewed_versions_and_hashes():
    data = (ROOT / "requirements.txt").read_bytes()
    assert hashlib.sha256(data).hexdigest() == APPROVED_CLOSURE_SHA256
    entries = [line for line in data.decode().splitlines() if line and not line.startswith("#")]
    assert len(entries) == 18
    assert all("==" in line and " --hash=sha256:" in line for line in entries)
    pinned = {line.split(" --hash=", 1)[0].lower() for line in entries}
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert set(value.lower() for value in project["dependencies"]) <= pinned


def test_legacy_lock_includes_the_canonical_closure_without_a_second_copy():
    entries = [line for line in (ROOT / "requirements-ci.lock").read_text().splitlines()
               if line and not line.startswith("#")]
    assert entries == ["-r requirements.txt"]


def test_both_ci_jobs_keep_real_hash_and_binary_enforcement_on_canonical_input():
    for name in ("pytest-suite.yml", "wallet-validation.yml"):
        body = (ROOT / ".github/workflows" / name).read_text()
        assert "pip install --only-binary :all: --require-hashes -r requirements.txt" in body
        assert "pip install -e" not in body
