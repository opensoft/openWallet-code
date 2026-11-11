"""Isolated reference transport, not a hardened public hosting service."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import ssl
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import rfc8785

from .custody import MAX_BODY, decode_object
from .proof import ProofError, _CONTEXT, _reference, create_proof
from .registry import BindingRegistry, binding_record, private_directory


def provision_key(directory, key_ref):
    """Trusted local administration only. Return public bytes, never private bytes."""
    if not _reference(key_ref):
        raise ProofError("invalid-binding")
    directory = private_directory(directory)
    filename = directory / (hashlib.sha256(key_ref.encode()).hexdigest() + ".pem")
    key = Ed25519PrivateKey.generate()
    fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return key.public_key().public_bytes_raw()


def load_key(directory, key_ref):
    directory = private_directory(directory)
    filename = directory / (hashlib.sha256(key_ref.encode()).hexdigest() + ".pem")
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 4096):
            raise ProofError("unsafe-key-file")
        key = serialization.load_pem_private_key(stream.read(4097), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ProofError("invalid-custody-key")
    return key


class CustodyApplication:
    def __init__(self, registry, *, key_directory, policies, clock=None):
        if type(policies) is not dict or not policies:
            raise ProofError("invalid-peer-policy")
        for fingerprint, policy in policies.items():
            if (type(fingerprint) is not str or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
                    or type(policy) is not dict or set(policy) != {"actions", "subjects"}
                    or type(policy["actions"]) is not list or not policy["actions"]
                    or any(action not in ("resolve", "sign") for action in policy["actions"])
                    or type(policy["subjects"]) is not list or not policy["subjects"]
                    or not all(_reference(subject) for subject in policy["subjects"])):
                raise ProofError("invalid-peer-policy")
        self.registry, self.key_directory = registry, private_directory(key_directory)
        self.policies = policies
        self.clock = clock or (lambda: int(time.time()))

    def dispatch(self, fingerprint, path, payload):
        policy = self.policies.get(fingerprint)
        action = {"/v0/resolve": "resolve", "/v0/sign": "sign"}.get(path)
        if policy is None or action is None or action not in policy["actions"]:
            raise ProofError("service-refused")
        expected = {"subject_ref"} if action == "resolve" else {"subject_ref", "message"}
        if set(payload) != expected or payload["subject_ref"] not in policy["subjects"]:
            raise ProofError("service-refused")
        binding = self.registry.resolve(payload["subject_ref"], now=self.clock())
        if action == "resolve":
            return binding_record(binding)
        if type(payload["message"]) is not str or len(payload["message"]) > MAX_BODY:
            raise ProofError("invalid-service-data")
        try:
            message = base64.b64decode(payload["message"], altchars=b"-_", validate=True)
        except ValueError:
            raise ProofError("invalid-service-data") from None
        if base64.urlsafe_b64encode(message).decode() != payload["message"] or not message.startswith(_CONTEXT):
            raise ProofError("invalid-signing-context")
        unsigned = decode_object(message[len(_CONTEXT):])
        key = load_key(self.key_directory, binding.key_ref)

        class RestrictedSigner:
            def sign(self, expected_message):
                if message != expected_message:
                    raise ProofError("invalid-signing-context")
                if app.registry.resolve(binding.subject_ref, now=app.clock()) != binding:
                    raise ProofError("binding-changed")
                return key.sign(expected_message)

        # This uses the owning primitive to construct ALL trusted preimage fields.
        # The callback signs only when the submitted canonical message matches it.
        app = self
        proof = create_proof(unsigned.get("challenge_digest"), binding, RestrictedSigner(), now=self.clock())
        if self.registry.resolve(binding.subject_ref, now=self.clock()) != binding:
            raise ProofError("binding-changed")
        signature = base64.urlsafe_b64decode(proof["signature"] + "==")
        return {"signature": base64.urlsafe_b64encode(signature).decode()}


class ReferenceServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, *, context, application):
        if context.verify_mode != ssl.CERT_REQUIRED:
            raise ProofError("mutual-tls-required")
        self.context, self.application = context, application
        super().__init__(address, ReferenceHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        try:
            return self.context.wrap_socket(connection, server_side=True), address
        except BaseException:
            connection.close()
            raise

    def handle_error(self, request, client_address):
        # Do not log request bodies, certificate material or backend exceptions.
        pass


class ReferenceHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        self.close_connection = True
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if (len(lengths) != 1 or self.headers.get("Transfer-Encoding") is not None
                    or not lengths[0].isascii() or not lengths[0].isdigit()
                    or not 0 < int(lengths[0]) <= MAX_BODY
                    or self.headers.get("Content-Type") != "application/json"):
                raise ProofError("invalid-service-data")
            payload = decode_object(self.rfile.read(int(lengths[0])))
            certificate = self.connection.getpeercert(binary_form=True)
            if not certificate:
                raise ProofError("service-refused")
            value = self.server.application.dispatch(hashlib.sha256(certificate).hexdigest(), self.path, payload)
            body, status = rfc8785.dumps(value), 200
        except Exception:
            body, status = b'{"error":"service-refused"}', 403
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def server_context(*, ca_file, certificate, private_key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(ca_file))
    context.load_cert_chain(str(certificate), str(private_key))
    return context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    config = decode_object(Path(args.config).read_bytes())
    app = CustodyApplication(BindingRegistry(config["registry_directory"]),
                            key_directory=config["key_directory"], policies=config["policies"])
    context = server_context(ca_file=config["ca_file"], certificate=config["certificate"], private_key=config["private_key"])
    with ReferenceServer((args.listen, args.port), context=context, application=app) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
