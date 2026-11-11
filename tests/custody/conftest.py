from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
from threading import Thread

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from openwallet_runtime import TrustedKeyBinding
from openwallet_runtime.custody import TLSClient
from openwallet_runtime.reference_service import CustodyApplication, ReferenceServer, provision_key, server_context
from openwallet_runtime.registry import BindingRegistry


def certificates(directory):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ephemeral-test-ca")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256()))
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    result = {}
    for name in ("server", "agent", "verifier", "unknown"):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                   .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(minutes=20))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if name == "server"
                                                       else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True))
        if name == "server":
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.DNSName("custody"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        certificate, private = directory / (name + ".pem"), directory / (name + ".key")
        certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
        private.chmod(0o600)
        result[name] = (certificate, private, hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())
    return result


@pytest.fixture
def service(tmp_path):
    certs = certificates(tmp_path)
    registry = BindingRegistry(tmp_path / "registry")
    key_directory = tmp_path / "keys"
    public = provision_key(key_directory, "key:a")
    binding = TrustedKeyBinding("binding:a", "wallet:a", "key:a", "subject:a", "custody:a", public, 1, 900, 2000)
    registry.register(binding, expected_revision=None)
    policies = {certs[name][2]: {"actions": actions, "subjects": ["subject:a"]}
                for name, actions in (("agent", ["resolve", "sign"]), ("verifier", ["resolve"]))}
    app = CustodyApplication(registry, key_directory=key_directory, policies=policies, clock=lambda: 1000)
    context = server_context(ca_file=tmp_path / "ca.pem", certificate=certs["server"][0], private_key=certs["server"][1])
    server = ReferenceServer(("127.0.0.1", 0), context=context, application=app)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = "https://localhost:" + str(server.server_port)

    def client(name):
        return TLSClient(endpoint, ca_file=tmp_path / "ca.pem", certificate=certs[name][0], private_key=certs[name][1])

    try:
        yield registry, binding, app, server, client, tmp_path, certs
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()
