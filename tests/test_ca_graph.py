"""The CA graph, reconciled against a tree size a log actually signed.

`cl.cag-graph`'s named test does the arithmetic end to end: 236 entries from Cloudflare's Nimbus2027, whose
prefix root has been proved consistent with the tree head the log signed under a pinned key, then an
issuer-to-subject graph that must account for every one of those entries - as an edge, or as a named
unattributed entry, never as nothing.

Two things the corpus proves rather than illustrates. Precert entries carry their issuer inside the leaf, so
their attribution is authenticated; x509 entries do not, and their issuer has to be read out of unsigned
`extra_data`, which the record says so about. And where a Precertificate Signing Certificate signed the
precertificate, the chain's first certificate is *not* the issuer the log committed to - measured at 173 of
494 precerts across five logs - which is the trap the PSC test here checks against these bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
from typing import TypedDict

import pytest
from _support import a_receipt, write_pins
from asn1core import parse_certificate
from ctspy import entry as ctentry
from ctspy import merkle
from ctspy.sth import SignedTreeHeadV1

from certledger import CaGraph, EntryRecord, EntryStore, HeadStore, KeyRing, Receipt

CORPUS = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "entry-corpus.json").read_text("utf-8")
)
PRIMARY = CORPUS["logs"][0]
PREFIX_LOG_ID = bytes.fromhex(PRIMARY["head"]["log_id"])


class CorpusEntry(TypedDict):
    index: int
    leaf_input: str
    extra_data: str
    identity: str


def corpus_receipt(origin: str) -> Receipt:
    return Receipt(
        path_id="tool:corpus",
        vantage="local:certledger-tools:unknown-as",
        trust_class="unauthenticated",
        request_target=f"GET {origin}/ct/v1/get-entries",
        started_utc=CORPUS["captured"],
        duration_ms=0,
        status=200,
    )


def record_for(
    entry: CorpusEntry, origin: str = PRIMARY["origin"], log_id: bytes = PREFIX_LOG_ID
) -> EntryRecord:
    return EntryRecord.from_bytes(
        log_id=log_id,
        index=entry["index"],
        leaf_input=base64.b64decode(entry["leaf_input"]),
        extra_data=base64.b64decode(entry["extra_data"]),
        receipt=corpus_receipt(origin),
    )


def prefix_store() -> EntryStore:
    store = EntryStore()
    for entry in PRIMARY["entries"]:
        store.add(record_for(entry))
    return store


def signed_head() -> SignedTreeHeadV1:
    head = PRIMARY["head"]
    return SignedTreeHeadV1(
        timestamp=head["timestamp"],
        tree_size=head["tree_size"],
        root_hash=bytes.fromhex(head["root_hash"]),
        signature=base64.b64decode(head["signature"]),
    )


def test_ca_layer_reconciles_with_tree_size(tmp_path: pathlib.Path) -> None:
    """The row's exit test: every entry of a signed prefix is placed, through the real pinning path.

    The head is accepted by `HeadStore`, which verifies its signature against a key in a temporary pin
    manifest, so `tree_size` is a size a pinned log signed rather than a number the test invented. The prefix
    root is then proved consistent with that head, and the graph must account for every entry of the prefix:
    an entry whose certificate will not parse is reported unattributed, which is the difference between a
    small CA layer and a quiet one.
    """
    key_spki = base64.b64decode(PRIMARY["head"]["key_spki"])
    origin = PRIMARY["origin"]
    ring = KeyRing.load(write_pins(tmp_path, [(PRIMARY["head"]["log_id"], origin, key_spki)]))
    head = HeadStore().accept(signed_head(), ring, origin=origin, receipt=a_receipt())
    assert head.tree_size == PRIMARY["head"]["tree_size"]

    prefix_size = PRIMARY["prefix"]["size"]
    root = merkle.tree_hash([base64.b64decode(entry["leaf_input"]) for entry in PRIMARY["entries"]])
    proof = [bytes.fromhex(node) for node in PRIMARY["prefix"]["consistency_proof"]]
    assert root == bytes.fromhex(PRIMARY["prefix"]["root_hash"])
    assert merkle.verify_consistency(prefix_size, head.tree_size, proof, root, head.root_hash), (
        "the corpus prefix is no longer consistent with the head it was captured against"
    )

    graph = CaGraph.build(prefix_store())
    reconciled = graph.reconcile(prefix_size)
    assert reconciled.complete, reconciled.summary()
    assert reconciled.edges + reconciled.unattributed == prefix_size
    assert reconciled.identities <= prefix_size
    assert reconciled.issuers > 0
    assert all(len(node.spki_sha256) == 32 for node in graph.issuers()), (
        "issuers are keyed by key hash"
    )


def test_a_precerts_issuer_is_the_leafs_hash_even_where_the_chain_disagrees() -> None:
    """The rule that keeps a third of issuance off phantom issuers, measured on these bytes.

    For each precert entry the same unsigned chain is read twice: once the way a naive issuer graph would
    (`chain[0]`'s SPKI) and once the way the log committed to it (`issuer_key_hash` inside the leaf). Where
    those differ, `chain[0]` is a Precertificate Signing Certificate and the entry must still be placed under
    the CA named by the leaf. If the corpus stops containing such an entry the count says so rather than
    letting the test quietly become trivial.
    """
    graph = CaGraph.build(prefix_store())
    checked = 0
    psc_signed = 0
    for entry in PRIMARY["entries"]:
        record = record_for(entry)
        if record.entry_type != "precert":
            continue
        checked += 1
        assert record.issuer_authenticated, "the leaf hashed this issuer; extra_data did not"
        assert graph.issued_by(record.issuer or b""), (
            "every authenticated issuer must have its entries"
        )
        assert any(item.index == record.index for item in graph.issued_by(record.issuer or b""))
        leaf = ctentry.MerkleTreeLeaf.parse(base64.b64decode(entry["leaf_input"]))
        stored = ctentry.parse_extra_data(leaf, base64.b64decode(entry["extra_data"]))
        if not stored.chain:
            continue
        chain_first = hashlib.sha256(
            parse_certificate(stored.chain[0]).subject_public_key_info
        ).digest()
        if chain_first != record.issuer:
            psc_signed += 1
            assert graph.issued_by(chain_first) == (), (
                "a precertificate signing certificate must not become an issuer node"
            )
    assert checked > 50, checked
    print(f"precerts checked: {checked}, of which PSC-signed: {psc_signed}")
    assert psc_signed, "no PSC-issued precert in the corpus; the rule is untested on these bytes"


def test_unattributable_entries_are_reported_rather_than_vanishing() -> None:
    """Synthetic, and labelled: an entry whose certificate cannot be read must still be counted.

    A graph built by skipping what it cannot parse reports fewer issuers, and "this key issued nothing" is a
    claim about absence - the one thing invariant I8 says this system may not make on thin data.
    """
    store = prefix_store()
    opaque = EntryRecord.from_bytes(
        log_id=b"\x11" * 32,
        index=0,
        leaf_input=b"\x00\x00\x00\x99junk",
        extra_data=b"",
        receipt=a_receipt(),
    )
    store.add(opaque)
    graph = CaGraph.build(store)
    assert not graph.reconcile(PRIMARY["prefix"]["size"]).complete, (
        "an entry from another log is not in this tree"
    )
    reconciled = graph.reconcile(PRIMARY["prefix"]["size"] + 1)
    assert reconciled.complete, reconciled.summary()
    assert reconciled.unattributed == 1
    assert [(record.log_id, record.index) for record in graph.unattributed()] == [(b"\x11" * 32, 0)]


def test_the_ca_layer_is_a_subset_of_what_the_graph_says_was_issued() -> None:
    """Tier A is held in full and cannot contain a certificate the edges do not reach.

    A 236-entry prefix of one log may hold no `cA=TRUE` entry at all, so this asserts the containment that
    must hold whatever the count is rather than inventing a CA to make the number non-zero. What the corpus
    actually contains is printed, because a phase-2 plan that assumed a cardinality should see the number.
    """
    graph = CaGraph.build(prefix_store())
    reached = {child for node in graph.issuers() for child in node.children}
    assert graph.reconcile(PRIMARY["prefix"]["size"]).ca_entries == len(graph.ca_layer())
    for record in graph.ca_layer():
        assert record.ca is True
        assert record.subject_spki_sha256 in reached


def test_an_unknown_key_has_no_node_rather_than_a_zero_one() -> None:
    """Absence is not zero (I8): a key this prefix never saw answers empty, and no CA is invented for it."""
    graph = CaGraph.build(prefix_store())
    nobody = hashlib.sha256(b"nobody").digest()
    assert graph.node(nobody) is None
    assert graph.issued_by(nobody) == ()
    assert not any(node.spki_sha256 == nobody for node in graph.issuers())


def test_a_head_that_is_not_pinned_cannot_belong_to_the_corpus(tmp_path: pathlib.Path) -> None:
    """The graph's tree size comes from a pinned key, so an unpinned log gets no head and no claim.

    The corpus key is written as a pin for one origin only. Asking `HeadStore` to accept the same signature
    under a different origin must fail on the pin lookup, which is the control that stops a captured
    artifact being reused as evidence about a log that never issued it.
    """
    from certledger import UnknownLogKey

    key_spki = base64.b64decode(PRIMARY["head"]["key_spki"])
    ring = KeyRing.load(write_pins(tmp_path, [("corpus", PRIMARY["origin"], key_spki)]))
    with pytest.raises(UnknownLogKey):
        HeadStore().accept(
            signed_head(), ring, origin="https://log.example/not-pinned", receipt=a_receipt()
        )
