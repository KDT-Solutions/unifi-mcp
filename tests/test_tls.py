"""TLS-Pinning gegen einen lokalen HTTPS-Server mit selbstsigniertem Zertifikat."""

import datetime
import http.server
import ssl
import threading

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from unifi_mcp import transport
from unifi_mcp.errors import ApiError


def self_signed(tmp_path, name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / f"{name}.pem", tmp_path / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert, cert_path, key_path


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *args):
        pass


@pytest.fixture
def https_server(tmp_path):
    cert, cert_path, key_path = self_signed(tmp_path, "server")
    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"https://127.0.0.1:{httpd.server_address[1]}", cert
    httpd.shutdown()


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


async def test_pinned_context_accepts_exact_certificate(https_server):
    url, cert = https_server
    ctx = transport.build_pinned_context(url, transport.fingerprint(der(cert)))
    async with httpx.AsyncClient(verify=ctx) as client:
        resp = await client.get(url + "/proxy/network/integration/v1/info")
    assert resp.json() == {"ok": True}


def test_wrong_fingerprint_aborts_before_request(https_server):
    url, _ = https_server
    with pytest.raises(ApiError, match="stimmt nicht"):
        transport.build_pinned_context(url, "00" * 32)


async def test_pinned_context_rejects_other_certificate(https_server, tmp_path):
    url, _ = https_server
    other, _, _ = self_signed(tmp_path, "other")
    ctx = transport.pinned_context(der(other))
    async with httpx.AsyncClient(verify=ctx) as client:
        with pytest.raises(httpx.ConnectError):
            await client.get(url)


async def test_default_verification_rejects_self_signed(https_server):
    url, _ = https_server
    async with httpx.AsyncClient(verify=True) as client:
        with pytest.raises(httpx.ConnectError):
            await client.get(url)
