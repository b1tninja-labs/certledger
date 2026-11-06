"""A local HTTPS server, a private CA, and anchor files - so the controls are tested for real.

These fixtures exist because the phase-0 claims cannot be made against mocks:

- "the environment is ignored" is only demonstrated if there is a server that *would* verify
  against an ambient anchor, and the fetch still refuses;
- "the peer address is asserted" is only demonstrated if a real socket reports a real peer;
- "no proxy is read" is only demonstrated if something is listening where a proxy would go.

Everything here is localhost-only, so the suite runs with no network and cannot become the thing
that quietly depends on a log operator's uptime.

The certificates are generated per session with `cryptography` and written as PEM files, which also
means `AnchorSet.load` reads real files from a real manifest instead of a hand-built dataclass.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

LOG_HOST = "ct.test.local"
BODY = b'{"tree_size": 1000, "timestamp": 1700000000000}'


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _not_before_after() -> tuple[datetime.datetime, datetime.datetime]:
    now = datetime.datetime.now(datetime.UTC)
    return now - datetime.timedelta(days=1), now + datetime.timedelta(days=365)


def make_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """A throwaway self-signed CA. Test material; nothing here is trusted anywhere."""
    key = _key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "certledger test CA")])
    low, high = _not_before_after()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(low)
        .not_valid_after(high)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(
    ca_key: ec.EllipticCurvePrivateKey, ca_cert: x509.Certificate, host: str = LOG_HOST
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = _key()
    low, high = _not_before_after()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(low)
        .not_valid_after(high)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def pem_of(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


@dataclass
class LogServer:
    """A live TLS server on 127.0.0.1, plus the CA its certificate chains to."""

    port: int
    host: str
    ca_pem: bytes
    leaf_der: bytes
    leaf_pem: bytes
    key_pem: bytes
    served: list[str] = field(default_factory=list)

    @property
    def address(self) -> str:
        return "127.0.0.1"


@dataclass
class ProxySink:
    """A listener standing in for a corporate proxy. Any connection to it is the failure."""

    port: int
    connections: list[str]
    _socket: socket.socket
    _stop: threading.Event
    _thread: threading.Thread

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._socket.close()


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.server.served.append(self.path)  # type: ignore[attr-defined]
        self.send_response(200, "OK")
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)


@pytest.fixture(scope="session")
def log_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LogServer]:
    ca_key, ca_cert = make_ca()
    server_key, server_cert = make_leaf(ca_key, ca_cert)

    directory = tmp_path_factory.mktemp("tls")
    ca_path = directory / "ca.pem"
    cert_path = directory / "server.pem"
    key_path = directory / "server-key.pem"
    ca_path.write_bytes(pem_of(ca_cert))
    cert_path.write_bytes(pem_of(server_cert))
    key_path.write_bytes(key_pem(server_key))

    holder = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server = LogServer(
        port=holder.server_address[1],
        host=LOG_HOST,
        ca_pem=ca_path.read_bytes(),
        leaf_der=server_cert.public_bytes(serialization.Encoding.DER),
        leaf_pem=cert_path.read_bytes(),
        key_pem=key_path.read_bytes(),
    )
    holder.served = server.served  # type: ignore[attr-defined]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    holder.socket = context.wrap_socket(holder.socket, server_side=True)

    thread = threading.Thread(target=holder.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        holder.shutdown()
        thread.join(timeout=5)
        server.served.clear()


def log_url(server: LogServer, target: str = "/ct/v1/get-sth") -> str:
    return f"https://{server.host}:{server.port}{target}"


@pytest.fixture
def log_endpoint(log_server: LogServer) -> str:
    return log_url(log_server)


@pytest.fixture
def resolver() -> object:
    """The path's own resolution call, answering the loopback address the server listens on."""

    def resolve(host: str) -> str:
        assert host == log_server_host(), f"the path asked us about {host}"
        return "127.0.0.1"

    return resolve


def log_server_host() -> str:
    return LOG_HOST


@pytest.fixture
def wrong_address_resolver() -> object:
    """A resolver that lies, for the refusal tests: name to 127.0.0.2, where nothing listens."""

    def resolve(host: str) -> str:
        return "127.0.0.2"

    return resolve


@pytest.fixture
def leaf_der() -> bytes:
    """A self-signed EC certificate, as canonical DER, for the I3 fidelity tests."""
    key, cert = make_ca()
    del key
    return cert.public_bytes(serialization.Encoding.DER)


def _write_anchor_set(
    directory: Path, *, anchor_id: str, host: str, pem: bytes, reason: str
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{anchor_id}.pem").write_bytes(pem)
    (directory / "anchors.toml").write_text(
        "[[anchor]]\n"
        f'id = "{anchor_id}"\n'
        f'origin = "{host}"\n'
        "added = 2026-11-05\n"
        f'reason = "{reason}"\n'
        f'file = "{anchor_id}.pem"\n',
        encoding="utf-8",
    )
    return directory


@pytest.fixture
def anchor_dir(tmp_path: Path, log_server: LogServer) -> Path:
    """A manifest pinning the CA that the test log actually presents (I1: dated, reasoned)."""
    return _write_anchor_set(
        tmp_path / "anchors",
        anchor_id="test-ca",
        host=log_server.host,
        pem=log_server.ca_pem,
        reason="generated by tests/conftest.py for the localhost TLS fixture",
    )


@pytest.fixture
def unrelated_dir(tmp_path: Path, log_server: LogServer) -> Path:
    """A second, valid anchor set whose CA must never verify the log server."""
    _, ca_cert = make_ca()
    return _write_anchor_set(
        tmp_path / "unrelated",
        anchor_id="other-ca",
        host=log_server.host,
        pem=pem_of(ca_cert),
        reason="a CA that must never verify the test log",
    )


@pytest.fixture
def ambient_ca_file(tmp_path: Path, log_server: LogServer) -> Path:
    """The log's own CA, sitting in a file `SSL_CERT_FILE` could point at.

    This is the interesting direction: the ambient anchor is *correct* for this server, so if the
    environment were honoured the handshake would succeed. A test that only pointed the variable at
    garbage would pass even for an implementation that read it.
    """
    path = tmp_path / "ambient-ca.pem"
    path.write_bytes(log_server.ca_pem)
    return path


@pytest.fixture
def alias_tls_port(tmp_path: Path, log_server: LogServer) -> Iterator[int]:
    """A second TLS endpoint, speaking the log's own certificate, on 127.0.0.2 only.

    Two different guards have to be provable, and both need a connection that genuinely succeeds:

    - `DirectTransport.connect` checks the peer before the handshake, so any listener will do;
    - `_PinnedConnection.connect` checks it *after* a successful handshake, which needs a listener
      whose certificate this process will actually accept. Without that second case the transport's
      check could be deleted and nothing would notice, which is exactly how a layered control rots
      into one layer with a comment claiming the other exists.

    Binding the alias address rather than 0.0.0.0 keeps it unreachable off this machine.
    """
    cert_path = tmp_path / "alias.pem"
    key_path = tmp_path / "alias-key.pem"
    cert_path.write_bytes(log_server.leaf_pem)
    key_path.write_bytes(log_server.key_pem)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    listening = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening.bind(("127.0.0.2", 0))
    listening.listen(4)
    stop = threading.Event()

    def accept_loop() -> None:
        listening.settimeout(0.2)
        while not stop.is_set():
            try:
                client, _ = listening.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                wrapped = server_context.wrap_socket(client, server_side=True)
            except (OSError, ssl.SSLError):
                continue
            wrapped.close()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    try:
        yield listening.getsockname()[1]
    finally:
        stop.set()
        thread.join(timeout=2)
        listening.close()


@pytest.fixture
def proxy_sink() -> Iterator[ProxySink]:
    listening = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening.bind(("127.0.0.1", 0))
    listening.listen(4)
    connections: list[str] = []
    stop = threading.Event()

    def accept_loop() -> None:
        listening.settimeout(0.2)
        while not stop.is_set():
            try:
                client, peer = listening.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            connections.append(f"{peer[0]}:{peer[1]}")
            client.close()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    sink = ProxySink(
        port=listening.getsockname()[1],
        connections=connections,
        _socket=listening,
        _stop=stop,
        _thread=thread,
    )
    try:
        yield sink
    finally:
        sink.close()
