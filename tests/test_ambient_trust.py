"""`cl.ambient-trust` (trust model I1): the environment is not an input to a trust decision.

The adversary here is A2, who needs a writable environment and nothing else - no access to this
code, no compromise of a log. The wave-1 exit test is explicit: *set `HTTPS_PROXY` and
`SSL_CERT_FILE` and prove they are ignored*, which is the first test in the file; the rest hold the
pieces it leans on apart.

One test is deliberately pointed the awkward way. `SSL_CERT_FILE` is set to the CA that **would**
verify the test server. Pointing it at garbage would also pass for an implementation that honoured
it - the handshake would merely fail for the wrong reason - so the fixture supplies a genuinely
valid ambient anchor and asserts we still refuse to be helped.
"""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest
from _support import make_path as a_path
from asn1core import spki_sha256
from conftest import LogServer

from certledger import AnchorSet, FetchFailure
from certledger.anchors import pem_to_der
from certledger.context import FORBIDDEN, build_client_context
from certledger.errors import AnchorSetProblem
from certledger.transport import Resolver

PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")


def test_environment_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
    log_endpoint: str,
    resolver: Resolver,
    anchor_dir: Path,
    ambient_ca_file: Path,
    proxy_sink: object,
) -> None:
    """The named exit test for `cl.ambient-trust`, over live loopback sockets."""
    for name in PROXY_VARS:
        monkeypatch.setenv(name, proxy_sink.url)  # type: ignore[attr-defined]
    monkeypatch.setenv("SSL_CERT_FILE", str(ambient_ca_file))
    monkeypatch.setenv("SSL_CERT_DIR", str(ambient_ca_file.parent))

    exchange = a_path(AnchorSet.load(anchor_dir), resolver).fetch(log_endpoint)

    assert exchange.status == 200
    assert exchange.receipt.error is None
    assert proxy_sink.connections == []  # type: ignore[attr-defined]
    assert exchange.receipt.peer_address == "127.0.0.1"
    assert exchange.receipt.peer_spki_sha256


def test_the_system_store_is_never_consulted(
    monkeypatch: pytest.MonkeyPatch, anchor_dir: Path
) -> None:
    """The two calls that import the OS store are patched to explode, and nothing explodes.

    On Windows `load_default_certs()` reads the machine store - the same store the published
    mitigation for the 2026 compromised intermediates writes into, so an auditor using it would
    have its view of the PKI changed by the incident it was measuring (trust model L1). Measured
    here rather than asserted: constructing a client context calls neither one.
    """

    def forbidden(self: ssl.SSLContext, *args: object, **kwargs: object) -> None:
        raise AssertionError("ambient trust: the system store must not be loaded")

    for name in FORBIDDEN:
        monkeypatch.setattr(ssl.SSLContext, name, forbidden)
    context = build_client_context(AnchorSet.load(anchor_dir), "ct.test.local")
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_ssl_cert_file_that_would_verify_is_still_refused(
    monkeypatch: pytest.MonkeyPatch,
    log_endpoint: str,
    resolver: Resolver,
    unrelated_dir: Path,
    ambient_ca_file: Path,
) -> None:
    """The environment offers an anchor that would work; our set does not contain it, so we fail."""
    monkeypatch.setenv("SSL_CERT_FILE", str(ambient_ca_file))
    with pytest.raises(FetchFailure) as caught:
        a_path(AnchorSet.load(unrelated_dir), resolver).fetch(log_endpoint)
    assert caught.value.receipt.error is not None
    assert "certificate verify failed" in caught.value.receipt.error
    assert caught.value.receipt.peer_address == "127.0.0.1"


def test_an_unpinned_host_is_refused_before_anything_is_asked(
    log_endpoint: str, proxy_sink: object
) -> None:
    """No resolution, no SYN: a name nobody pinned is refused at configuration time."""
    calls: list[str] = []

    def resolver(host: str) -> str:
        calls.append(host)
        raise AssertionError("the resolver must not run for a host with no pinned anchor")

    with pytest.raises(FetchFailure) as caught:
        a_path(AnchorSet.empty(), resolver).fetch(log_endpoint)
    assert calls == []
    assert isinstance(caught.value.cause, AnchorSetProblem)
    assert proxy_sink.connections == []  # type: ignore[attr-defined]
    assert caught.value.receipt.peer_address is None, "unknown, not zero (I8)"


def test_the_context_trusts_exactly_the_pinned_anchor(
    monkeypatch: pytest.MonkeyPatch, anchor_dir: Path, ambient_ca_file: Path
) -> None:
    """Exactly one trusted certificate in the store, and the environment cannot add a second."""
    monkeypatch.setenv("SSL_CERT_FILE", str(ambient_ca_file))
    context = build_client_context(AnchorSet.load(anchor_dir), "ct.test.local")
    assert context.cert_store_stats()["x509"] == 1, "one pinned anchor and nothing else"


def test_an_anchor_without_a_date_or_a_reason_is_refused(tmp_path: Path, anchor_dir: Path) -> None:
    """I1: an entry with no `added` or no `reason` is a bug, not a default."""
    pem = (anchor_dir / "test-ca.pem").read_bytes()
    bodies = {
        "no-date": 'id = "x"\norigin = "h"\nreason = "r"\nfile = "test-ca.pem"\n',
        "no-reason": 'id = "x"\norigin = "h"\nadded = 2026-11-05\nfile = "test-ca.pem"\n',
    }
    for label, body in bodies.items():
        directory = tmp_path / label
        directory.mkdir()
        (directory / "test-ca.pem").write_bytes(pem)
        (directory / "anchors.toml").write_text(f"[[anchor]]\n{body}", encoding="utf-8")
        with pytest.raises(AnchorSetProblem, match="date and a reason"):
            AnchorSet.load(directory)


def test_an_anchor_naming_an_absent_file_is_refused(tmp_path: Path) -> None:
    directory = tmp_path / "dangling"
    directory.mkdir()
    (directory / "anchors.toml").write_text(
        "[[anchor]]\n"
        'id = "x"\norigin = "h"\nadded = 2026-11-05\nreason = "r"\nfile = "absent.pem"\n',
        encoding="utf-8",
    )
    with pytest.raises(AnchorSetProblem, match="absent"):
        AnchorSet.load(directory)


def test_anchor_entries_that_cannot_be_reviewed_are_refused(
    tmp_path: Path, anchor_dir: Path
) -> None:
    """Each of these would otherwise load as a trusted anchor with no way to audit the decision."""
    pem = (anchor_dir / "test-ca.pem").read_bytes()
    bodies = {
        "duplicate": (
            "[[anchor]]\n"
            'id = "x"\norigin = "h"\nadded = 2026-11-05\nreason = "r"\nfile = "test-ca.pem"\n'
            "[[anchor]]\n"
            'id = "x"\norigin = "h2"\nadded = 2026-11-05\nreason = "r"\nfile = "test-ca.pem"\n'
        ),
        "text-date": (
            "[[anchor]]\n"
            'id = "x"\norigin = "h"\nadded = "2026-11-05"\nreason = "r"\nfile = "test-ca.pem"\n'
        ),
        "blank-reason": (
            "[[anchor]]\n"
            'id = "x"\norigin = "h"\nadded = 2026-11-05\nreason = "   "\nfile = "test-ca.pem"\n'
        ),
        "not-a-table": 'anchor = "trust me"\n',
    }
    for label, body in bodies.items():
        directory = tmp_path / label
        directory.mkdir()
        (directory / "test-ca.pem").write_bytes(pem)
        (directory / "anchors.toml").write_text(body, encoding="utf-8")
        with pytest.raises(AnchorSetProblem):
            AnchorSet.load(directory)


def test_a_malformed_manifest_is_not_read_as_an_empty_one(tmp_path: Path) -> None:
    """Malformed means somebody edited the file; empty means nothing is trusted. I8 apart."""
    directory = tmp_path / "broken"
    directory.mkdir()
    (directory / "anchors.toml").write_text("[[anchor]\nid = x", encoding="utf-8")
    with pytest.raises(AnchorSetProblem, match="cannot be read"):
        AnchorSet.load(directory)
    (directory / "anchors.toml").write_text("", encoding="utf-8")
    assert AnchorSet.load(directory).anchors == (), "an explicitly empty set is a real answer"


def test_the_shipped_anchor_set_loads_and_is_empty() -> None:
    """Phase 0 ships no pins. Phase 1's `cl.key-pins` is where a dated decision appears."""
    shipped = Path(__file__).resolve().parents[1] / "anchors"
    assert AnchorSet.load(shipped).anchors == ()


def test_plain_http_is_refused_rather_than_upgraded(resolver: Resolver, anchor_dir: Path) -> None:
    with pytest.raises(ValueError, match="https"):
        a_path(AnchorSet.load(anchor_dir), resolver).fetch("http://ct.test.local/ct/v1/get-sth")


def test_pem_parsing_refuses_a_private_key() -> None:
    armor = "-----BEGIN CERTIFICATE-----\n-----END PRIVATE KEY-----\n"
    with pytest.raises(AnchorSetProblem, match="one PEM certificate"):
        pem_to_der(armor.encode(), source="test")


def test_peer_spki_is_recorded_from_the_negotiation_not_the_anchor(
    log_endpoint: str, resolver: Resolver, anchor_dir: Path, log_server: LogServer
) -> None:
    """The receipt records the key that answered, so an interceptor appears as a difference.

    The pinned anchor is the CA and the peer presents the leaf, so these two hashes *must* differ.
    Recording the anchor instead - which is the tempting shortcut, and what a receipt built from
    configuration rather than from the socket would do - would make every receipt look correct by
    construction and hide the one event worth seeing.
    """

    exchange = a_path(AnchorSet.load(anchor_dir), resolver).fetch(log_endpoint)
    pinned = AnchorSet.load(anchor_dir).for_host("ct.test.local")[0]
    assert exchange.receipt.peer_spki_sha256 == spki_sha256(log_server.leaf_der)
    assert exchange.receipt.peer_spki_sha256 != pinned.spki_sha256()
