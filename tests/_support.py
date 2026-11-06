"""Shared test scaffolding that is not a pytest fixture.

Kept out of `conftest.py` so the test modules import it by name rather than reaching into a file
pytest loads implicitly, and prefixed with an underscore so pytest never tries to collect it.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from ctspy.sth import SignedTreeHeadV1

from certledger import AnchorSet, FetchPath, Receipt, TrustClass, Vantage
from certledger.transport import Resolver, Transport


def ephemeral_log() -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    """A throwaway log key: (private key, DER SPKI, log_id). Test material only."""
    private = ec.generate_private_key(ec.SECP256R1())
    spki = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, spki, hashlib.sha256(spki).digest()


def sign_v1_head(
    private: ec.EllipticCurvePrivateKey, timestamp: int, tree_size: int, root_hash: bytes
) -> SignedTreeHeadV1:
    """A v1 STH signed the way a log signs one, by a key this test generated.

    The transcript comes from `ctspy` rather than being rebuilt here, which would only prove the
    builder agrees with itself. The transcript's *shape* is pinned elsewhere - against STHs published
    by production logs, in ctspy/tests/test_sth.py - so what these tests exercise is the monotonicity
    and proof rules layered on top of a signature that OpenSSL made.
    """
    unsigned = SignedTreeHeadV1(
        timestamp=timestamp,
        tree_size=tree_size,
        root_hash=root_hash,
        signature=b"\x00",
    )
    signature = private.sign(unsigned.transcript(), ec.ECDSA(hashes.SHA256()))
    return replace(unsigned, signature=signature)


def write_pins(directory: Path, entries: list[tuple[str, str, bytes]]) -> Path:
    """Write a pin file for test logs. `entries` is (description, origin, spki_der)."""
    directory.mkdir(parents=True, exist_ok=True)
    blocks = []
    for description, origin, spki in entries:
        blocks.append(
            "[[log]]\n"
            f'log_id = "{base64.b64encode(hashlib.sha256(spki).digest()).decode()}"\n'
            f'description = "{description}"\n'
            f'origin = "{origin}"\n'
            f'key = "{base64.b64encode(spki).decode()}"\n'
            "added = 2026-11-05\n"
            'source = "written by tests/_support.py"\n'
            'decided_by = "test"\n'
            'reviewed_by = "test"\n'
        )
    path = directory / "pins.toml"
    path.write_text("\n".join(blocks), encoding="utf-8")
    return path


def a_receipt(path_id: str = "p-test") -> Receipt:
    return Receipt(
        path_id=path_id,
        vantage="local:test:loopback:unknown-as",
        trust_class="local",
        request_target="GET /ct/v1/get-sth",
        started_utc=datetime.datetime.now(datetime.UTC).isoformat(),
        duration_ms=12,
        peer_address="127.0.0.1",
        peer_port=443,
        peer_spki_sha256="0" * 64,
        status=200,
        response_sha256="1" * 64,
        response_bytes=241,
    )


VANTAGE = Vantage(
    provider="test", region="loopback", autonomous_system=None, trust_class=TrustClass.LOCAL
)

HOSTED_VANTAGE = Vantage(
    provider="elsewhere",
    region="another-as",
    autonomous_system=64512,
    trust_class=TrustClass.HOSTED,
)


def make_path(
    anchors: AnchorSet,
    resolver: Resolver,
    transport: Transport | None = None,
    *,
    path_id: str = "p-loopback",
    vantage: Vantage = VANTAGE,
) -> FetchPath:
    return FetchPath(
        path_id=path_id,
        vantage=vantage,
        anchors=anchors,
        resolver=resolver,
        transport=transport,
        timeout=5.0,
    )
