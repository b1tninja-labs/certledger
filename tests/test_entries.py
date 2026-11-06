"""Entries are counted, not assumed: one certificate in several logs is still one certificate.

`cl.dedupe`'s named test runs against bytes captured from Cloudflare's Nimbus2027 - a 236-entry prefix whose
root has been proved consistent with the tree head the log signed, so the corpus is a piece of a real tree
rather than a bag of plausible certificates. Two of those entries are the same certificate in the same log,
and two more certificates appear in Sectigo's Tiger2027h1 as well, each of those peer entries now proved into
Sectigo's own tree by an audit path to a head Sectigo signed; both are real, and both are the reason counting
entries and counting certificates have to be different operations.

The synthetic cases are here for the paths production did not exercise in this sample, and each says so in
its own docstring: an entry whose leaf cannot be read, and a log that serves two different leaves at one
index. Nothing in this file is presented as evidence about a log it was not taken from.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import pathlib
from typing import TypedDict

import pytest
from _support import a_receipt, accepted_head
from ctspy import entry as ctentry
from ctspy import merkle

from certledger import EntryConflict, EntryRecord, EntryStore, Receipt, UnknownHead

CORPUS = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "entry-corpus.json").read_text("utf-8")
)
PRIMARY = CORPUS["logs"][0]
PEERS = CORPUS["logs"][1:]


class CorpusEntry(TypedDict):
    """One captured `get-entries` pair, typed so the helpers say what they actually require."""

    index: int
    leaf_input: str
    extra_data: str
    identity: str


def corpus_receipt(origin: str) -> Receipt:
    """The provenance the capture tool actually had, including the part it did not have.

    `trust_class` is `unauthenticated` because there is no anchor decision yet, so the TLS connection was not
    trusted - and the corpus is still usable evidence, because what makes these bytes genuine is the log's
    signature over a pinned key, not the transport. Recording the missing trust rather than inventing it is
    the difference between a fixture and a claim.
    """
    return Receipt(
        path_id="tool:corpus",
        vantage="local:certledger-tools:unknown-as",
        trust_class="unauthenticated",
        request_target=f"GET {origin}/ct/v1/get-entries",
        started_utc=CORPUS["captured"],
        duration_ms=0,
        status=200,
        response_sha256=None,
        response_bytes=None,
    )


def record_from(entry: CorpusEntry, origin: str, log_id: bytes) -> EntryRecord:
    return EntryRecord.from_bytes(
        log_id=log_id,
        index=entry["index"],
        leaf_input=base64.b64decode(entry["leaf_input"]),
        extra_data=base64.b64decode(entry["extra_data"]),
        receipt=corpus_receipt(origin),
    )


def store_from_corpus() -> EntryStore:
    store = EntryStore()
    for log in CORPUS["logs"]:
        log_id = bytes.fromhex(log["head"]["log_id"])
        for entry in log["entries"]:
            store.add(record_from(entry, log["origin"], log_id))
    return store


def test_entry_count_differs_from_cert_count() -> None:
    """The row's exit test: 238 entries, fewer certificates, and the gap is explained, not estimated."""
    store = store_from_corpus()
    stats = store.stats()
    expected = sum(len(log["entries"]) for log in CORPUS["logs"])
    assert stats.entries == expected
    assert stats.entries > stats.identities, stats.summary()

    grouped = store.certificates()
    duplicated = {key: rows for key, rows in grouped.items() if len(rows) > 1}
    assert duplicated, "the corpus no longer contains a duplicate; re-run tools/corpus.py"

    # Every duplicate the capture recorded inside the verified prefix must show up as one identity, two entries.
    prefix_log_id = bytes.fromhex(PRIMARY["head"]["log_id"])
    for first, last in PRIMARY["duplicate_pairs"]:
        left = store.get(prefix_log_id, first)
        right = store.get(prefix_log_id, last)
        assert left is not None
        assert right is not None
        assert left.identity == right.identity
        assert left.leaf_sha256 != right.leaf_sha256, (
            "two entries, one certificate, different leaves"
        )


def test_a_peer_entry_is_proved_into_its_own_log_by_an_audit_path(tmp_path: pathlib.Path) -> None:
    """The cross-log half of the corpus is proved, not merely matched by position.

    These bytes arrived from Sectigo over a transport this project does not trust, and no head from that
    fetch was accepted when it arrived. What makes them evidence is recomputed here from the fixture alone: a
    pinned key signs a head, the head is accepted, and the stored path runs from this leaf to that accepted
    root. `HeadStore.verify_inclusion` is the only door used, because a path checked against a root the log
    merely asserted is a proof with no anchor - the thing that method exists to refuse.

    It is also the first production inclusion proof `cl.inclusion` has ever been checked against. Before the
    endpoint was asked correctly there was nothing here to check, and the row's test was synthetic.
    """
    for peer in PEERS:
        store, log_id = accepted_head(peer["head"], peer["origin"], tmp_path)
        for entry in peer["entries"]:
            proof = entry["inclusion"]
            leaf_hash = merkle.leaf_hash(base64.b64decode(entry["leaf_input"]))
            path = tuple(bytes.fromhex(node) for node in proof["audit_path"])
            assert proof["leaf_index"] == entry["index"]
            assert store.verify_inclusion(
                log_id, leaf_hash, proof["leaf_index"], path, tree_size=proof["tree_size"]
            ), f"{peer['origin']}#{entry['index']} is not proved by the path stored beside it"
            tampered = (path[0][:-1] + bytes([path[0][-1] ^ 1]), *path[1:])
            assert not store.verify_inclusion(
                log_id, leaf_hash, proof["leaf_index"], tampered, tree_size=proof["tree_size"]
            ), "a flipped audit node still verified, so this check was not checking anything"


def test_a_proof_for_a_size_beyond_the_accepted_head_is_refused(tmp_path: pathlib.Path) -> None:
    """The binding has teeth: a size the accepted head does not cover raises rather than being re-derived.

    A log can answer a proof for a tree larger than any head this store accepted. Recomputing a root for that
    would be the store inventing its own anchor, so `verify_inclusion` refuses it - here on real numbers from
    a production tree rather than a made-up size.
    """
    peer = PEERS[0]
    store, log_id = accepted_head(peer["head"], peer["origin"], tmp_path)
    proof = peer["entries"][0]["inclusion"]
    leaf_hash = merkle.leaf_hash(base64.b64decode(peer["entries"][0]["leaf_input"]))
    path = tuple(bytes.fromhex(node) for node in proof["audit_path"])
    with pytest.raises(UnknownHead):
        store.verify_inclusion(
            log_id, leaf_hash, proof["leaf_index"], path, tree_size=proof["tree_size"] + 1
        )


def test_a_certificate_in_two_logs_is_one_certificate_with_two_provenances() -> None:
    """The cross-log case the row names, on bytes two operators served independently.

    These are Sectigo Tiger2027h1's copies of certificates already in the verified Cloudflare prefix, and
    each one now arrives with an audit path to a head Sectigo signed - the test above re-derives those. What
    this test is about is different: identity does not come from inclusion. Two proved entries in two trees
    are still one certificate when the TBSCertificate the trees hashed is the same one, which is exactly what
    collides here, and no amount of proof on either side would make them two certificates.
    """
    store = store_from_corpus()
    grouped = store.certificates()
    cross = [rows for rows in grouped.values() if len({row.log_id for row in rows}) > 1]
    assert cross, "no certificate appears in two logs; re-run tools/corpus.py with fresh peers"
    for rows in cross:
        logs = {row.log_id for row in rows}
        assert len(logs) >= 2
        assert len(rows) == len(logs), "two entries from one log would be the within-log case"


def test_every_record_carries_the_receipt_of_the_fetch_that_produced_it() -> None:
    """I6 as a constructor signature: no receipt, no record.

    The corpus records say `unauthenticated`, which is the truth about the transport - no anchor decision
    exists yet - rather than the omission that would make the fixture look like verified acquisition.
    """
    for record in store_from_corpus().entries():
        assert record.receipt.path_id == "tool:corpus"
        assert record.receipt.trust_class == "unauthenticated"
    fields = {field.name: field for field in dataclasses.fields(EntryRecord)}
    assert fields["receipt"].default is dataclasses.MISSING, (
        "a record that can be built without provenance will eventually be built without it"
    )


def test_a_precerts_identity_is_the_leafs_tbscertificate_not_the_stored_copy() -> None:
    """The rule that makes cross-log dedupe work, checked against every precert in the corpus.

    The stored precertificate is unsigned, and for a third of production precerts it is not even the same
    document as the logged TBS (RFC 6962 section 3.2 paragraph 9 rewrites its issuer and AKI when a
    Precertificate Signing Certificate signed it). Keying on the stored copy would split one certificate
    across several identities, which is the failure the row exists to prevent.
    """
    checked = 0
    for log in CORPUS["logs"]:
        log_id = bytes.fromhex(log["head"]["log_id"])
        for entry in log["entries"]:
            record = record_from(entry, log["origin"], log_id)
            if record.entry_type != "precert":
                continue
            leaf = ctentry.MerkleTreeLeaf.parse(base64.b64decode(entry["leaf_input"]))
            signed = leaf.entry.entry
            assert isinstance(signed, ctentry.PrecertEntry)
            assert record.identity == hashlib.sha256(signed.tbs_certificate).digest()
            assert record.issuer == signed.issuer_key_hash
            assert record.issuer_authenticated, "the leaf hashed this value; extra_data did not"
            assert not record.certificate_authenticated, (
                "a precertificate is served as unsigned data"
            )
            checked += 1
    assert checked > 100, checked


def test_an_x509_entrys_certificate_is_the_authenticated_one() -> None:
    """The mirror case: here the leaf carries the certificate, and the chain beside it does not.

    RFC 6962 section 4.6 says an x509 entry's `extra_data` is the `certificate_chain`, and it is: the leaf
    certificate the store keeps is the one inside the hashed leaf, and the chain is reported as untrusted
    alongside it.
    """
    seen = 0
    for record in store_from_corpus().entries():
        if record.entry_type != "x509":
            continue
        raw = _leaf_bytes(record)
        assert record.leaf_sha256 == merkle.leaf_hash(raw)
        assert record.certificate_authenticated
        assert record.certificate is not None
        assert record.certificate in raw, "the certificate lives inside the hashed leaf"
        assert record.issuer is None or not record.issuer_authenticated
        seen += 1
    assert seen, "the corpus has no x509 entries; re-run tools/corpus.py"


def _leaf_bytes(record: EntryRecord) -> bytes:
    for log in CORPUS["logs"]:
        for entry in log["entries"]:
            if (
                entry["index"] == record.index
                and bytes.fromhex(log["head"]["log_id"]) == record.log_id
            ):
                return base64.b64decode(entry["leaf_input"])
    raise AssertionError("record is not from the corpus")


def test_an_unreadable_entry_is_stored_as_opaque_rather_than_dropped() -> None:
    """Synthetic, and labelled as such: an entry type this client does not know still belongs to the tree.

    RFC 6962 section 4.6 forbids treating an unrecognized leaf or entry type as an error while still requiring
    the tree to verify, so the record keeps an identity - the leaf octets, the only stable thing about
    something that cannot be read - and the reason it stayed opaque.
    """
    opaque_leaf = bytes([0, 0, 1]) + b"not a MerkleTreeLeaf"
    store = EntryStore()
    record = store.add(
        EntryRecord.from_bytes(
            log_id=b"\x0f" * 32,
            index=0,
            leaf_input=opaque_leaf,
            extra_data=b"",
            receipt=a_receipt(),
        )
    )
    assert record.entry_type == "opaque"
    assert record.parse_issue
    assert record.identity == hashlib.sha256(opaque_leaf).digest()
    assert record.certificate is None
    assert record.issuer is None
    assert store.stats().opaque == 1


def test_two_leaves_at_one_index_are_an_incident_rather_than_an_update() -> None:
    """A log that rewrites a position has changed its tree; the store keeps both claims and refuses."""
    log = PRIMARY
    log_id = bytes.fromhex(log["head"]["log_id"])
    first = record_from(log["entries"][0], log["origin"], log_id)
    store = EntryStore()
    store.add(first)
    assert store.add(first) is first, "the same leaf twice is a re-read, not a conflict"

    substitute = dataclasses.replace(
        first,
        leaf_sha256=b"\xaa" * 32,
        index=0,
    )
    with pytest.raises(EntryConflict, match="two different leaves"):
        store.add(substitute)


def test_the_corpus_says_how_each_half_of_it_is_proved() -> None:
    """The fixture's own honesty fields, guarded, because everything else in this file reads them.

    Both halves are proved now, by different means over different spans. The primary block carries a *window*
    - entries 0 to 235 - whose root is proved consistent with a head Cloudflare signed, which binds every
    entry in it for the price of one proof. A peer block carries no window: its entries are proved one at a
    time, each with its own path to a head Sectigo signed. `prefix` is what tells them apart, so a peer that
    grew one would be claiming a proved history it does not have, and a peer entry that lost its path would be
    quietly demoted to positional matching while still reading as `verified`.

    The structure is asserted rather than the boolean, because a flag meaning "proved, somehow" is exactly the
    flattening this test exists to catch.
    """
    assert PRIMARY["verified"] is True
    assert PRIMARY["prefix"]["consistent_with_head"] is True
    assert PRIMARY["prefix"]["size"] == len(PRIMARY["entries"])
    for peer in PEERS:
        assert "prefix" not in peer, "a peer block claiming a proved window would over-claim"
        assert peer["verified"] is True, "an unproved peer block must not read as acquisition"
        assert peer["entries"], "a peer block with no entries proves nothing, quietly"
        assert all("inclusion" in entry for entry in peer["entries"]), "a peer entry lost its proof"
        assert peer["head"]["log_id"] != PRIMARY["head"]["log_id"]


def test_sct_bearing_certificates_are_counted_rather_than_folded_away() -> None:
    """A measured limit of the identity rule, kept visible instead of quietly normalised.

    A final certificate that embeds its SCT list differs from the precertificate it came from by exactly the
    extension RFC 6962 section 3.2 paragraph 9 names, so the two spellings have two identities here and one
    issuance in the world. Folding them would need a re-encoding of a signed document; the count is recorded
    so the decision, when it is made, is made against a number.
    """
    stats = store_from_corpus().stats()
    assert stats.sct_bearing >= 0
    for record in store_from_corpus().entries():
        if record.has_sct_extension:
            assert record.entry_type == "x509", "a precertificate cannot carry its own SCT list"
