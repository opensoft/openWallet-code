"""Explicit mutual-TLS transport; no proxy, redirect or unverified TLS route."""
import base64
import http.client
import json
import ssl
from urllib.parse import urlsplit

import rfc8785

from .proof import ProofError, _check_binding, _reference
from .registry import binding_from_record

MAX_BODY = 8192


def decode_object(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("constant")

    if type(raw) is not bytes or len(raw) > MAX_BODY:
        raise ProofError("invalid-service-data")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ProofError("invalid-service-data") from None
    if type(value) is not dict:
        raise ProofError("invalid-service-data")
    return value


class TLSClient:
    def __init__(self, endpoint, *, ca_file, certificate, private_key, timeout=3):
        try:
            address = urlsplit(endpoint)
            if (address.scheme != "https" or not address.hostname or address.username is not None
                    or address.password is not None or address.path not in ("", "/")
                    or address.query or address.fragment or not 0 < timeout <= 10):
                raise ValueError("endpoint")
            self.host, self.port = address.hostname, address.port or 443
            self.timeout = timeout
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_verify_locations(cafile=str(ca_file))
            context.load_cert_chain(str(certificate), str(private_key))
            self.context = context
        except (ValueError, TypeError, OSError):
            raise ProofError("invalid-service-configuration") from None

    def _post(self, path, payload):
        try:
            encoded = rfc8785.dumps(payload)
            if len(encoded) > MAX_BODY:
                raise ProofError("invalid-service-data")
            connection = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=self.timeout)
            try:
                connection.request("POST", path, body=encoded, headers={"Content-Type": "application/json", "Connection": "close"})
                response = connection.getresponse()
                body = response.read(MAX_BODY + 1)
                if response.status != 200:
                    raise ProofError("service-refused")
                if response.getheader("Content-Type") != "application/json":
                    raise ProofError("invalid-service-data")
                return decode_object(body)
            finally:
                connection.close()
        except ProofError:
            raise
        except (OSError, http.client.HTTPException, ValueError, TypeError, rfc8785.CanonicalizationError):
            raise ProofError("service-unavailable") from None


class RemoteRegistry:
    def __init__(self, client):
        self.client = client

    def resolve(self, subject_ref, *, now):
        if not _reference(subject_ref):
            raise ProofError("invalid-binding")
        value = self.client._post("/v0/resolve", {"subject_ref": subject_ref})
        binding = binding_from_record(value)
        if binding.subject_ref != subject_ref:
            raise ProofError("invalid-binding")
        _check_binding(binding, now)
        return binding


class RemoteSigner:
    """Opaque sign-only interface; response is checked again by create_proof."""
    def __init__(self, client, *, subject_ref):
        if not _reference(subject_ref):
            raise ProofError("invalid-binding")
        self.client, self.subject_ref = client, subject_ref

    def sign(self, message):
        if type(message) is not bytes or len(message) > MAX_BODY:
            raise ProofError("invalid-service-data")
        value = self.client._post("/v0/sign", {
            "subject_ref": self.subject_ref, "message": base64.urlsafe_b64encode(message).decode()})
        if set(value) != {"signature"} or type(value["signature"]) is not str:
            raise ProofError("invalid-service-data")
        try:
            raw = base64.b64decode(value["signature"], altchars=b"-_", validate=True)
        except ValueError:
            raise ProofError("invalid-service-data") from None
        if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode() != value["signature"]:
            raise ProofError("invalid-service-data")
        return raw
