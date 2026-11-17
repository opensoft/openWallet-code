"""Actual operator-config admission and refusal-before-side-effects."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest
from openwallet_runtime import reference_service as service
from openwallet_runtime.proof import ProofError


def config(path, value=None):
    path.write_text(json.dumps({"registry_directory": "../registry"} if value is None else value))
    path.chmod(0o600)
    return path


def test_relative_operator_config_keeps_json_path_semantics(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENWALLET_REFERENCE_CONFIG_ROOT", raising=False)
    config(tmp_path / "service.json")
    assert service.read_service_config("service.json") == {"registry_directory": "../registry"}


def test_absolute_config_inside_separately_selected_root_is_admitted(tmp_path, monkeypatch):
    root = tmp_path / "operator"
    root.mkdir()
    selected = config(root / "service.json")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("OPENWALLET_REFERENCE_CONFIG_ROOT", str(root))
    selected.chmod(0o644)  # Readability does not confer permission to alter policy.
    assert service.read_service_config(selected) == {"registry_directory": "../registry"}


@pytest.mark.parametrize("mode", ["traversal", "absolute", "prefix-sibling", "leaf-link",
                                  "parent-link", "directory", "fifo", "hard-link",
                                  "writable", "oversized"])
def test_config_refuses_escapes_links_nonregular_and_untrusted_input(tmp_path, monkeypatch, mode):
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "allowed-other"
    outside.mkdir()
    target = config(outside / "service.json")
    monkeypatch.chdir(root)
    monkeypatch.setenv("OPENWALLET_REFERENCE_CONFIG_ROOT", str(root))
    if mode == "traversal":
        selected = "../allowed-other/service.json"
    elif mode in ("absolute", "prefix-sibling"):
        selected = target
    elif mode == "leaf-link":
        selected = root / "service.json"
        selected.symlink_to(target)
    elif mode == "parent-link":
        parent = root / "linked"
        parent.symlink_to(outside, target_is_directory=True)
        selected = parent / "service.json"
    elif mode == "directory":
        selected = root / "directory"
        selected.mkdir()
    elif mode == "fifo":
        selected = root / "pipe"
        os.mkfifo(selected)
    elif mode == "hard-link":
        selected = root / "service.json"
        os.link(target, selected)
    elif mode == "writable":
        selected = config(root / "service.json")
        selected.chmod(0o666)
    else:
        selected = root / "service.json"
        selected.write_bytes(b" " * (service.MAX_BODY + 1))
        selected.chmod(0o600)
    before = len(tuple(Path("/proc/self/fd").iterdir()))
    with pytest.raises(ProofError, match="invalid-service-data"):
        service.read_service_config(selected)
    assert len(tuple(Path("/proc/self/fd").iterdir())) == before


@pytest.mark.parametrize("selection", ["", " ", "/", "missing", "file"])
def test_config_root_is_independently_validated(tmp_path, monkeypatch, selection):
    monkeypatch.chdir(tmp_path)
    selected = config(tmp_path / "service.json")
    (tmp_path / "file").write_text("not a root")
    value = selection if selection in ("", " ", "/") else str(tmp_path / selection)
    monkeypatch.setenv("OPENWALLET_REFERENCE_CONFIG_ROOT", value)
    with pytest.raises(ProofError, match="invalid-service-data"):
        service.read_service_config(selected)


def test_other_owner_is_not_an_operator_config(tmp_path, monkeypatch):
    selected = config(tmp_path / "service.json")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENWALLET_REFERENCE_CONFIG_ROOT", raising=False)
    original = os.fstat
    def other_owner(fd):
        row = list(original(fd))
        row[stat.ST_UID] = 123456
        return os.stat_result(row)
    monkeypatch.setattr(service.os, "fstat", other_owner)
    with pytest.raises(ProofError, match="invalid-service-data"):
        service.read_service_config(selected)


def test_refusal_precedes_registry_tls_and_listener(tmp_path, monkeypatch, capsys):
    root = tmp_path / "allowed"
    root.mkdir()
    outside = config(tmp_path / "outside.json")
    monkeypatch.chdir(root)
    monkeypatch.delenv("OPENWALLET_REFERENCE_CONFIG_ROOT", raising=False)
    def forbidden(*args, **kwargs):
        raise AssertionError("refused config reached a service side effect")
    for name in ("BindingRegistry", "CustodyApplication", "server_context", "ReferenceServer"):
        monkeypatch.setattr(service, name, forbidden)
    with pytest.raises(SystemExit) as error:
        service.main(["--config", str(outside)])
    assert error.value.code == 2
    assert capsys.readouterr().err == "reference-service: invalid-service-data\n"


def test_successful_main_keeps_existing_operator_fields_and_arguments(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENWALLET_REFERENCE_CONFIG_ROOT", raising=False)
    value = {"registry_directory": "../registry", "key_directory": "../keys", "policies": {},
             "ca_file": "ca.pem", "certificate": "service.pem", "private_key": "service-key.pem"}
    selected = config(tmp_path / "service.json", value)
    seen = []
    monkeypatch.setattr(service, "BindingRegistry", lambda path: ("registry", path))
    def application(registry, **kwargs):
        seen.append((registry, kwargs))
        return "application"
    monkeypatch.setattr(service, "CustodyApplication", application)
    monkeypatch.setattr(service, "server_context", lambda **kwargs: ("tls", kwargs))
    class Server:
        def __init__(self, address, **kwargs):
            seen.append((address, kwargs))
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def serve_forever(self):
            seen.append("served")
    monkeypatch.setattr(service, "ReferenceServer", Server)
    assert service.main(["--config", str(selected), "--port", "9443"]) is None
    assert seen == [
        (("registry", "../registry"), {"key_directory": "../keys", "policies": {}}),
        (("127.0.0.1", 9443), {"context": ("tls", {"ca_file": "ca.pem",
          "certificate": "service.pem", "private_key": "service-key.pem"}), "application": "application"}),
        "served",
    ]


def test_optimized_python_still_refuses_escaped_config_before_state_creation(tmp_path):
    root = tmp_path / "allowed"
    root.mkdir()
    state = tmp_path / "must-not-be-created"
    outside = config(tmp_path / "outside.json", {
        "registry_directory": str(state), "key_directory": "missing-keys", "policies": {},
        "ca_file": "missing-ca", "certificate": "missing-cert", "private_key": "missing-key",
    })
    environment = dict(os.environ, PYTHONPATH=str(Path(service.__file__).resolve().parents[1]))
    environment.pop("OPENWALLET_REFERENCE_CONFIG_ROOT", None)
    result = subprocess.run([sys.executable, "-O", "-m", "openwallet_runtime.reference_service",
                             "--config", str(outside)], cwd=root, env=environment,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert result.stderr == "reference-service: invalid-service-data\n"
    assert not state.exists()


def test_config_root_ancestor_swap_refuses_before_reading_outside_file(tmp_path, monkeypatch):
    ancestor = tmp_path / "selected"
    root = ancestor / "root"
    root.mkdir(parents=True)
    selected = config(root / "service.json", {"origin": "inside"})
    outside = tmp_path / "outside"
    (outside / "root").mkdir(parents=True)
    config(outside / "root" / "service.json", {"origin": "outside"})
    monkeypatch.setenv("OPENWALLET_REFERENCE_CONFIG_ROOT", str(root))
    original = os.open
    swapped = False
    def race(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and "dir_fd" not in kwargs and flags & os.O_DIRECTORY:
            swapped = True
            ancestor.rename(tmp_path / "original-selected")
            ancestor.symlink_to(outside, target_is_directory=True)
        return original(path, flags, *args, **kwargs)
    def forbidden(payload):
        raise AssertionError("root replacement reached configuration bytes")
    monkeypatch.setattr(service.os, "open", race)
    monkeypatch.setattr(service, "decode_object", forbidden)
    before = len(tuple(Path("/proc/self/fd").iterdir()))
    with pytest.raises(ProofError, match="invalid-service-data"):
        service.read_service_config(selected)
    assert swapped
    assert len(tuple(Path("/proc/self/fd").iterdir())) == before
