"""Operator-owned current bindings. No network administration or authority grants."""
from contextlib import closing, contextmanager
from dataclasses import asdict
import json
import os
from pathlib import Path
import sqlite3
import stat

from .proof import ProofError, TrustedKeyBinding, _check_binding, _integer, _reference


def private_directory(directory):
    path = Path(directory).absolute()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise ProofError("unsafe-state-directory")
    return path


def binding_record(binding):
    value = asdict(binding)
    value["public_key"] = binding.public_key.hex()
    return value


def binding_from_record(value):
    fields = set(TrustedKeyBinding.__dataclass_fields__)
    if type(value) is not dict or set(value) != fields:
        raise ProofError("invalid-binding")
    encoded = value["public_key"]
    if type(encoded) is not str or len(encoded) != 64:
        raise ProofError("invalid-binding")
    try:
        public = bytes.fromhex(encoded)
    except ValueError:
        raise ProofError("invalid-binding") from None
    if public.hex() != encoded:
        raise ProofError("invalid-binding")
    return TrustedKeyBinding(**{**value, "public_key": public})


class BindingRegistry:
    """Local trusted administration; network clients can only resolve records."""

    def __init__(self, directory):
        self.directory = private_directory(directory)
        self.path = self.directory / "registry.sqlite"
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            info = self.path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
                raise ProofError("unsafe-registry-file") from None
        else:
            os.close(fd)
        with self._connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS bindings(
                    subject TEXT PRIMARY KEY, revision INTEGER NOT NULL,
                    binding_ref TEXT UNIQUE NOT NULL, record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS key_owners(
                    key_ref TEXT PRIMARY KEY, subject TEXT NOT NULL,
                    public_key TEXT NOT NULL, custody_ref TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS revoked_refs(binding_ref TEXT PRIMARY KEY);
            """)

    @contextmanager
    def _connection(self, *, write=False):
        try:
            with closing(sqlite3.connect(self.path, timeout=3, isolation_level=None)) as db:
                db.row_factory = sqlite3.Row
                if write:
                    db.execute("BEGIN IMMEDIATE")
                try:
                    yield db
                    if write:
                        db.commit()
                except BaseException:
                    if write:
                        db.rollback()
                    raise
        except sqlite3.Error:
            raise ProofError("registry-unavailable") from None

    def register(self, binding, *, expected_revision):
        """CAS replacement; revisions and key ownership never silently reset."""
        if not isinstance(binding, TrustedKeyBinding):
            raise ProofError("invalid-binding")
        _check_binding(binding, binding.not_before)
        if expected_revision is not None and not _integer(expected_revision):
            raise ProofError("revision-conflict")
        record = binding_record(binding)
        with self._connection(write=True) as db:
            current = db.execute("SELECT * FROM bindings WHERE subject=?", (binding.subject_ref,)).fetchone()
            actual = current["revision"] if current else None
            if expected_revision != actual or (actual is not None and binding.revision <= actual):
                raise ProofError("revision-conflict")
            if db.execute("SELECT 1 FROM revoked_refs WHERE binding_ref=?", (binding.binding_ref,)).fetchone():
                raise ProofError("revoked-binding")
            other = db.execute("SELECT subject FROM bindings WHERE binding_ref=?", (binding.binding_ref,)).fetchone()
            if other and other["subject"] != binding.subject_ref:
                raise ProofError("binding-owner-conflict")
            owner = db.execute("SELECT * FROM key_owners WHERE key_ref=?", (binding.key_ref,)).fetchone()
            if owner and (owner["subject"], owner["public_key"], owner["custody_ref"]) != (
                    binding.subject_ref, record["public_key"], binding.custody_ref):
                raise ProofError("key-owner-conflict")
            db.execute("INSERT OR IGNORE INTO key_owners VALUES(?,?,?,?)", (
                binding.key_ref, binding.subject_ref, record["public_key"], binding.custody_ref))
            db.execute("INSERT INTO bindings VALUES(?,?,?,?) ON CONFLICT(subject) DO UPDATE SET "
                       "revision=excluded.revision,binding_ref=excluded.binding_ref,record=excluded.record", (
                           binding.subject_ref, binding.revision, binding.binding_ref,
                           json.dumps(record, sort_keys=True, separators=(",", ":"))))

    def resolve(self, subject_ref, *, now):
        if not _reference(subject_ref) or not _integer(now):
            raise ProofError("invalid-binding")
        with self._connection() as db:
            row = db.execute("SELECT record FROM bindings WHERE subject=?", (subject_ref,)).fetchone()
            if row is None:
                raise ProofError("binding-unavailable")
            try:
                binding = binding_from_record(json.loads(row["record"]))
            except (ValueError, TypeError):
                raise ProofError("invalid-binding") from None
            if db.execute("SELECT 1 FROM revoked_refs WHERE binding_ref=?", (binding.binding_ref,)).fetchone():
                raise ProofError("revoked-binding")
            if binding.subject_ref != subject_ref:
                raise ProofError("invalid-binding")
            _check_binding(binding, now)
            return binding

    def revoke(self, binding_ref):
        if not _reference(binding_ref):
            raise ProofError("invalid-binding")
        with self._connection(write=True) as db:
            db.execute("INSERT OR IGNORE INTO revoked_refs VALUES(?)", (binding_ref,))
