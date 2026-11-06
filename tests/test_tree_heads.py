"""Monotonic tree heads, consistency on growth, and inclusion against an accepted head.

Phase 1's exit test is the negative one: *injected fixtures for a stale tree, a bad proof and a wrong
key must all be rejected.* Every test here feeds the store something a log could plausibly send and
checks whether believing it would have been wrong.

The heads are signed by throwaway keys (`_support.ephemeral_log`) rather than by a production log,
because a monotonicity test needs two heads of one tree lineage and no log publishes those on demand.
The signature path is pinned against real artifacts in `test_key_pins.py` and in ctspy's own suite, so
what is under test here is the ordering and proof rules, not the arithmetic.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from _support import a_receipt, ephemeral_log, sign_v1_head, write_pins
from cryptography.hazmat.primitives.asymmetric import ec
from ctspy import merkle
from ctspy.errors import VerificationError
from ctspy.sth import SignedTreeHeadV1

from certledger.heads import (
    BadConsistencyProof,
    HeadDivergence,
    HeadRecord,
    HeadStore,
    MissingConsistencyProof,
    TreeShrank,
    UnacceptedHead,
    UnknownHead,
)
from certledger.keys import KeyRing

ORIGIN = "https://log.test/"
LogFixture = tuple[ec.EllipticCurvePrivateKey, KeyRing, bytes]


@pytest.fixture
def log(tmp_path: Path) -> LogFixture:
    private, spki, log_id = ephemeral_log()
    ring = KeyRing.load(write_pins(tmp_path, [("Test Log", ORIGIN, spki)]))
    return private, ring, log_id


def entries(count: int) -> list[bytes]:
    return [f"leaf {index}".encode() for index in range(count)]


def head(private: ec.EllipticCurvePrivateKey, tree: list[bytes], size: int) -> SignedTreeHeadV1:
    return sign_v1_head(private, 1700000000000 + size, size, merkle.tree_hash(tree[:size]))


def test_sth_signature_round_trip(log: LogFixture) -> None:
    """The roadmap's named test for `cl.sth-verify`: sign, parse, verify, and reject a forgery."""
    private, ring, log_id = log
    tree = entries(5)
    store = HeadStore()
    record = store.accept(head(private, tree, 5), ring, origin=ORIGIN, receipt=a_receipt())
    assert record.tree_size == 5
    assert record.root_hash == merkle.tree_hash(tree)
    assert record.log_id == log_id
    assert record.bootstrap is True, "a first head is a baseline, not a proven history"

    again = store.accept(head(private, tree, 5), ring, origin=ORIGIN, receipt=a_receipt("p-again"))
    assert again.tree_size == 5
    assert len(store.history(log_id)) == 2, "staleness is recorded, not swallowed"

    forged = SignedTreeHeadV1(
        timestamp=1700000000005,
        tree_size=6,
        root_hash=merkle.tree_hash(entries(6)),
        signature=head(private, tree, 5).signature,
    )
    with pytest.raises(VerificationError, match="does not verify"):
        store.accept(forged, ring, origin=ORIGIN, receipt=a_receipt("p-forged"))


def test_smaller_tree_is_rejected(log: LogFixture) -> None:
    """A decrease is an incident, not a data error (I4): raised, never clamped or retried."""
    private, ring, log_id = log
    tree = entries(9)
    store = HeadStore()
    store.accept(head(private, tree, 9), ring, origin=ORIGIN, receipt=a_receipt())
    with pytest.raises(TreeShrank, match="went backwards"):
        store.accept(head(private, tree, 8), ring, origin=ORIGIN, receipt=a_receipt("p-8"))
    assert store.current(log_id).tree_size == 9, "the store must not move backwards"

    diverging = sign_v1_head(private, 1700000000009, 9, hashlib.sha256(b"other history").digest())
    with pytest.raises(HeadDivergence, match="two roots"):
        store.accept(diverging, ring, origin=ORIGIN, receipt=a_receipt("p-div"))
    assert store.current(log_id).root_hash == merkle.tree_hash(tree)


def test_mstc_rejects_bad_proof(log: LogFixture) -> None:
    """Growth is only believed with a consistency proof that verifies (RFC 9162 section 2.1.4)."""
    private, ring, log_id = log
    tree = entries(9)
    store = HeadStore()
    store.accept(head(private, tree, 5), ring, origin=ORIGIN, receipt=a_receipt("p-5"))

    with pytest.raises(MissingConsistencyProof, match="needs a consistency proof"):
        store.accept(head(private, tree, 9), ring, origin=ORIGIN, receipt=a_receipt("p-none"))

    honest = merkle.consistency_path(5, tree)
    unrelated = merkle.tree_hash(entries(7))
    with pytest.raises(BadConsistencyProof, match="does not verify"):
        store.accept(
            head(private, tree, 9),
            ring,
            origin=ORIGIN,
            receipt=a_receipt("p-bad"),
            consistency=(*honest[:-1], unrelated),
        )
    assert store.current(log_id).tree_size == 5, "a rejected growth leaves the head where it was"

    accepted = store.accept(
        head(private, tree, 9),
        ring,
        origin=ORIGIN,
        receipt=a_receipt("p-good"),
        consistency=honest,
    )
    assert accepted.tree_size == 9
    assert accepted.bootstrap is False


def test_mth_and_audit_path(log: LogFixture) -> None:
    """MTH is the tree hash; an audit path proves a leaf against a head this store accepted."""
    private, ring, log_id = log
    tree = entries(9)
    store = HeadStore()
    store.accept(head(private, tree, 9), ring, origin=ORIGIN, receipt=a_receipt("p-9"))

    leaf = merkle.leaf_hash(tree[3])
    assert leaf == hashlib.sha256(b"\x00" + tree[3]).digest(), "a leaf hash is 0x00 || MTL"
    assert store.verify_inclusion(log_id, leaf, 3, merkle.inclusion_path(3, tree)) is True

    assert (
        store.verify_inclusion(
            log_id, merkle.leaf_hash(b"never logged"), 3, merkle.inclusion_path(3, tree)
        )
        is False
    )
    with pytest.raises(UnacceptedHead, match="unaccepted root"):
        store.verify_inclusion(log_id, leaf, 3, merkle.inclusion_path(3, tree), tree_size=7)
    with pytest.raises(UnknownHead, match="beyond the head"):
        store.verify_inclusion(log_id, leaf, 3, (), tree_size=10)
    with pytest.raises(UnknownHead, match="no head accepted"):
        store.verify_inclusion(bytes(32), leaf, 3, ())


def test_every_object_has_a_receipt(log: LogFixture) -> None:
    """Nothing leaves the verification layer without provenance (I6), and the type enforces it."""
    private, ring, _ = log
    tree = entries(4)
    store = HeadStore()
    record = store.accept(head(private, tree, 4), ring, origin=ORIGIN, receipt=a_receipt("p-4"))
    assert record.receipt.path_id == "p-4"
    assert record.receipt.peer_address == "127.0.0.1"
    assert "p-4" in record.summary()

    with pytest.raises(TypeError):
        HeadRecord(  # type: ignore[call-arg]
            log_id=bytes(32),
            tree_size=1,
            root_hash=bytes(32),
            timestamp=0,
            accepted_utc="2026-11-05T00:00:00+00:00",
            bootstrap=False,
        )
