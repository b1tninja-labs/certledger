"""What the middle of a tree says, which a prefix cannot.

`tests/fixtures/midwindow-corpus.json` holds 64 entries from index 375,256,870 of Google's Xenon2027h1 - the
midpoint of the tree as it stood when the head beside them was signed - and each entry arrives with an audit
path to that head. Nothing here is trusted because the file says so: every path is re-derived below against a
head accepted through the pinned key, the same door `cl.inclusion` uses.

Why the file exists is a number. The prefix corpus (`entry-corpus.json`, positions 0 to 235 of a Cloudflare
log) reports 8 `cA=TRUE` entries drawing edges from 4 distinct issuers. The middle of a tree reports 0 CA
entries drawing from **20** issuers in 64 entries. Read together they say that a CA layer measured at the
start of a log is a measurement of beginnings, not of the population - which matters because the CA layer is
where `certledger`'s whole "one issuer, many certificates" argument lives.

What that comparison does *not* establish is written in the test that uses it: the two samples differ in log
and operator as well as in position, so the difference is confounded and neither number describes "the" CA
layer of anything. The middle window also carries the corpus's only SCT-bearing entries - 10 of them, all
x509 - and still does not exhibit two spellings of one issuance, so folding stays untested on production
bytes rather than tested-and-passing.
"""

from __future__ import annotations

import base64
import json
import pathlib
from typing import Any, TypedDict

import pytest
from _support import a_receipt, accepted_head
from ctspy import merkle

from certledger import CaGraph, EntryRecord, EntryStore, UnknownHead

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
MID = json.loads((FIXTURES / "midwindow-corpus.json").read_text("utf-8"))
PREFIX = json.loads((FIXTURES / "entry-corpus.json").read_text("utf-8"))["logs"][0]
ORIGIN = MID["log"]["origin"]
LOG_ID = bytes.fromhex(MID["log"]["head"]["log_id"])


class WindowEntry(TypedDict):
    index: int
    leaf_input: str
    extra_data: str
    identity: str
    inclusion: dict[str, Any]


def record_for(entry: WindowEntry) -> EntryRecord:
    return EntryRecord.from_bytes(
        log_id=LOG_ID,
        index=entry["index"],
        leaf_input=base64.b64decode(entry["leaf_input"]),
        extra_data=base64.b64decode(entry["extra_data"]),
        receipt=a_receipt("tool:corpus-window"),
    )


def store_for(entries: list[Any], log_id: bytes, path_id: str) -> EntryStore:
    store = EntryStore()
    for entry in entries:
        store.add(
            EntryRecord.from_bytes(
                log_id=log_id,
                index=entry["index"],
                leaf_input=base64.b64decode(entry["leaf_input"]),
                extra_data=base64.b64decode(entry["extra_data"]),
                receipt=a_receipt(path_id),
            )
        )
    return store


def issuers_in(entries: list[Any], log_id: bytes, path_id: str) -> int:
    return len(list(CaGraph.build(store_for(entries, log_id, path_id)).issuers()))


def test_every_entry_in_the_window_is_proved_into_a_signed_tree(tmp_path: pathlib.Path) -> None:
    """64 paths, each checked against a head Google signed and this store accepted.

    The negative control is the part that keeps the test honest: a flipped node has to fail, otherwise the
    positive assertion is checking the shape of the fixture rather than the arithmetic of the tree.
    """
    store, log_id = accepted_head(MID["log"]["head"], ORIGIN, tmp_path)
    for entry in MID["entries"]:
        proof = entry["inclusion"]
        leaf_hash = merkle.leaf_hash(base64.b64decode(entry["leaf_input"]))
        path = tuple(bytes.fromhex(node) for node in proof["audit_path"])
        assert proof["leaf_index"] == entry["index"]
        assert store.verify_inclusion(
            log_id, leaf_hash, proof["leaf_index"], path, tree_size=proof["tree_size"]
        ), f"{ORIGIN}#{entry['index']} is not proved by the path stored beside it"
        tampered = (path[0][:-1] + bytes([path[0][-1] ^ 1]), *path[1:])
        assert not store.verify_inclusion(
            log_id, leaf_hash, proof["leaf_index"], tampered, tree_size=proof["tree_size"]
        ), "a flipped audit node still verified, so this check was not checking anything"


def test_the_window_is_the_middle_of_a_tree_and_not_another_prefix() -> None:
    """The claim of this file is its position, so the position is asserted rather than remembered.

    `chosen_by` says the start came from the tree size at capture, and the indices have to run from there with
    no gap: a window with a hole in it would be a set of proved bytes, which is a weaker claim than the one
    this module's docstring makes.
    """
    size = int(MID["log"]["head"]["tree_size"])
    start = int(MID["window"]["start"])
    assert MID["window"]["chosen_by"] == "tree_size // 2"
    assert start == size // 2, "the recorded start is not the midpoint it claims to be"
    assert start > 0, (
        "a window that starts at 0 is a prefix, which is the claim this file is not making"
    )
    assert size - start > len(MID["entries"]), (
        "the window runs to the end of the tree, so it is not mid"
    )
    indices = [entry["index"] for entry in MID["entries"]]
    assert indices == list(range(start, start + len(indices))), "the window has a hole in it"


def test_the_middle_of_a_tree_names_more_issuers_than_its_beginning() -> None:
    """The measurement this fixture was captured for, stated as a direction rather than a rate.

    64 entries mid-tree draw edges from 20 distinct issuers; 236 entries at the start of a different log draw
    from 4. So the CA-layer cardinality `cl.cag-graph` reports for the prefix is a fact about position 0, and
    the hedge the documentation used for it - "a ratio, not an estimate" - was doing less work than it looked.

    The confounding is part of the result rather than a footnote to it: the samples differ in log and operator
    as well as position, so nothing here says the average certificate has 20 issuers behind it. A recapture
    that reversed the order would be news about a changing deployment, which is why the message says to
    re-measure the claim instead of deleting the test.
    """
    middle = issuers_in(MID["entries"], LOG_ID, "tool:corpus-window")
    beginning = issuers_in(
        PREFIX["entries"], bytes.fromhex(PREFIX["head"]["log_id"]), "tool:corpus"
    )
    assert middle > beginning, (
        f"mid-window issuers {middle} no longer exceeds prefix issuers {beginning}; the "
        "position-dependence claim in this file's docstring needs re-measuring, not deleting"
    )
    assert middle >= 8, f"the window collapsed to {middle} issuers; it is no longer a sample"


def test_the_window_holds_sct_bearing_entries_and_still_not_the_folding_case() -> None:
    """Production bytes with an SCT list exist now; one issuance in two spellings still does not.

    Every SCT-bearing entry in either corpus is in this window: 10 of 64, all x509, where the prefix has none.
    That retires the sentence saying the corpus contains no SCT-bearing bytes. It does not retire the harder
    one - folding matters only when one certificate is logged twice under different `TBSCertificate` spellings,
    which needs two entries sharing an identity, and all 64 here are distinct. So `has_sct_extension` is now
    exercised on real bytes while the fold remains untested on them, and asserting the identity count is what
    stops those two statements from merging into one that is too good.
    """
    records = [record_for(entry) for entry in MID["entries"]]
    bearing = [record for record in records if record.has_sct_extension]
    assert bearing, "the window lost the SCT-bearing entries that justified capturing it"
    assert all(record.entry_type == "x509" for record in bearing), (
        "a precert carries its chain rather than an SCT list, so this is not the case being claimed"
    )
    prefix_bearing = store_for(
        PREFIX["entries"], bytes.fromhex(PREFIX["head"]["log_id"]), "tool:corpus"
    )
    assert prefix_bearing.stats().sct_bearing == 0, (
        "the prefix now carries SCTs too, so 'the window is the only source' is no longer true"
    )
    assert store_for(MID["entries"], LOG_ID, "tool:corpus-window").stats().identities == len(
        MID["entries"]
    ), "two entries now share an identity: the folding case may finally be exhibit-able here"


def test_a_window_proof_beyond_the_captured_head_is_refused(tmp_path: pathlib.Path) -> None:
    """The anchor is the captured head, not the log's current one, and the store enforces the difference.

    The tree has grown since capture, which is precisely why this fixture cannot be regenerated: asking for a
    size past the recorded head has to raise rather than have a root quietly recomputed from a newer tree.
    """
    store, log_id = accepted_head(MID["log"]["head"], ORIGIN, tmp_path)
    entry = MID["entries"][0]
    proof = entry["inclusion"]
    leaf_hash = merkle.leaf_hash(base64.b64decode(entry["leaf_input"]))
    path = tuple(bytes.fromhex(node) for node in proof["audit_path"])
    assert proof["tree_size"] == int(MID["log"]["head"]["tree_size"])
    with pytest.raises(UnknownHead):
        store.verify_inclusion(
            log_id, leaf_hash, proof["leaf_index"], path, tree_size=proof["tree_size"] + 1
        )
