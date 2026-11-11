import base64
import http.client
import json
import ssl
from dataclasses import replace

import pytest
import rfc8785

from openwallet_runtime import ProofError, create_proof, verify_proof
from openwallet_runtime.custody import RemoteRegistry, RemoteSigner, TLSClient, decode_object
from openwallet_runtime.reference_service import CustodyApplication, ReferenceServer, provision_key

DIGEST = "sha256:" + "a" * 64


def signing_message(binding):
    class Capture:
        def sign(self, message):
            self.message = message
            raise ValueError("captured")

    capture = Capture()
    with pytest.raises(ProofError, match="signer-unavailable"):
        create_proof(DIGEST, binding, capture, now=1000)
    return capture.message


def assert_peer_refused(service, actor, action, subject):
    registry, binding, app, _, client, *_ = service
    if subject != binding.subject_ref:
        binding = replace(binding, binding_ref="binding:other", wallet_ref="wallet:other",
                          key_ref="key:other", subject_ref=subject,
                          public_key=provision_key(app.key_directory, "key:other"))
        registry.register(binding, expected_revision=None)
    payload = {"subject_ref": subject}
    if action == "sign":
        payload["message"] = base64.urlsafe_b64encode(signing_message(binding)).decode()
    with pytest.raises(ProofError, match="service-refused"):
        client(actor)._post("/v0/" + action, payload)


def test_actual_mutual_tls_registry_and_opaque_signing(service):
    _, binding, _, _, client, *_ = service
    assert RemoteRegistry(client("agent")).resolve("subject:a", now=1000) == binding
    proof = create_proof(DIGEST, binding, RemoteSigner(client("agent"), subject_ref="subject:a"), now=1000)
    result = verify_proof(proof, expected_digest=DIGEST,
                          binding=RemoteRegistry(client("verifier")).resolve("subject:a", now=1000), now=1000)
    assert result.subject_ref == "subject:a"
    assert set(proof) == {"profile", "alg", "challenge_digest", "binding_ref", "binding_revision",
                          "wallet_ref", "key_ref", "subject_ref", "custody_ref", "signature"}


@pytest.mark.parametrize("actor,action,subject", [
    ("unknown", "resolve", "subject:a"), ("verifier", "sign", "subject:a"),
    ("agent", "resolve", "subject:other"), ("agent", "sign", "subject:other"),
])
def test_peer_action_and_subject_isolation(service, actor, action, subject):
    assert_peer_refused(service, actor, action, subject)


@pytest.mark.parametrize("actor,action,subject", [
    ("verifier", "sign", "subject:a"),
    ("agent", "resolve", "subject:other"), ("agent", "sign", "subject:other"),
])
def test_isolation_probe_detects_accidental_policy_grant(service, actor, action, subject):
    _, _, app, _, _, _, certs = service
    policy = app.policies[certs[actor][2]]
    if action not in policy["actions"]:
        policy["actions"].append(action)
    if subject not in policy["subjects"]:
        policy["subjects"].append(subject)
    with pytest.raises(pytest.fail.Exception, match="DID NOT RAISE"):
        assert_peer_refused(service, actor, action, subject)


def test_current_registry_revocation_blocks_resolve_and_sign(service):
    registry, binding, _, _, client, *_ = service
    signer = RemoteSigner(client("agent"), subject_ref="subject:a")
    create_proof(DIGEST, binding, signer, now=1000)
    registry.revoke(binding.binding_ref)
    with pytest.raises(ProofError, match="service-refused"):
        RemoteRegistry(client("agent")).resolve("subject:a", now=1000)
    with pytest.raises(ProofError, match="signer-unavailable"):
        create_proof(DIGEST, binding, signer, now=1000)


@pytest.mark.parametrize("change", ["domain", "noncanonical", "binding", "extra"])
def test_signing_cannot_be_used_for_another_domain_or_preimage(service, change):
    _, binding, _, _, client, *_ = service

    class Capture:
        def sign(self, message):
            self.message = message
            raise ValueError("captured")

    capture = Capture()
    with pytest.raises(ProofError):
        create_proof(DIGEST, binding, capture, now=1000)
    message = capture.message
    prefix, body = message.split(b"\0", 1)
    if change == "domain":
        message = b"other\0" + body
    elif change == "noncanonical":
        message = prefix + b"\0" + json.dumps(json.loads(body)).encode()
    else:
        payload = json.loads(body)
        payload["binding_ref" if change == "binding" else "verified"] = "changed"
        message = prefix + b"\0" + rfc8785.dumps(payload)
    with pytest.raises(ProofError, match="service-refused"):
        client("agent")._post("/v0/sign", {"subject_ref": "subject:a", "message": base64.urlsafe_b64encode(message).decode()})


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'\xff', b' ' * 8193])
def test_strict_transport_json_refuses_ambiguous_or_oversized_objects(raw):
    with pytest.raises(ProofError, match="invalid-service-data"):
        decode_object(raw)


def test_missing_client_certificate_cannot_complete_authenticated_request(service):
    _, _, _, server, _, directory, _ = service
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(directory / "ca.pem"))
    connection = http.client.HTTPSConnection("localhost", server.server_port, context=context, timeout=3)
    try:
        with pytest.raises((ssl.SSLError, OSError, http.client.HTTPException)):
            connection.request("POST", "/v0/resolve", body=b'{"subject_ref":"subject:a"}')
            connection.getresponse()
    finally:
        connection.close()


def test_plaintext_configuration_and_non_mutual_tls_server_refuse(service):
    _, _, app, _, _, directory, certs = service
    with pytest.raises(ProofError, match="invalid-service-configuration"):
        TLSClient("http://localhost", ca_file=directory / "ca.pem", certificate=certs["agent"][0], private_key=certs["agent"][1])
    with pytest.raises(ProofError, match="mutual-tls-required"):
        ReferenceServer(("127.0.0.1", 0), context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), application=app)


def test_export_and_admin_routes_and_bad_policy_refuse(service):
    registry, binding, app, _, client, *_ = service
    for route in ("export", "revoke", "register"):
        with pytest.raises(ProofError, match="service-refused"):
            client("agent")._post("/v0/" + route, {"subject_ref": binding.subject_ref})
    with pytest.raises(ProofError, match="invalid-peer-policy"):
        CustodyApplication(registry, key_directory=app.key_directory,
                           policies={"a" * 64: {"actions": "sign", "subjects": "subject:a"}})


def test_untrusted_server_ca_refuses(service):
    _, _, _, server, _, directory, certs = service
    untrusted = TLSClient("https://localhost:" + str(server.server_port),
                          ca_file=certs["unknown"][0], certificate=certs["agent"][0],
                          private_key=certs["agent"][1])
    with pytest.raises(ProofError, match="service-unavailable"):
        RemoteRegistry(untrusted).resolve("subject:a", now=1000)


def test_server_hostname_is_checked_even_when_tcp_reaches_the_right_service(service, monkeypatch):
    import socket
    _, _, _, server, _, directory, certs = service
    original = socket.create_connection

    def connect_to_fixture(address, *args, **kwargs):
        return original(("127.0.0.1", server.server_port), *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", connect_to_fixture)
    wrong_name = TLSClient("https://wrong.example.invalid:" + str(server.server_port),
                           ca_file=directory / "ca.pem", certificate=certs["agent"][0],
                           private_key=certs["agent"][1])
    with pytest.raises(ProofError, match="service-unavailable"):
        RemoteRegistry(wrong_name).resolve("subject:a", now=1000)
