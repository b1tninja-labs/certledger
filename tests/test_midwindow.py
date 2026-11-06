"""Two proved windows from the middle of trees, and the number they were captured for.

`tests/fixtures/midwindow-corpus.json` holds slices from the midpoint of two logs - each entry arriving with
an audit path to the head signed beside it - and nothing below is trusted because the file says so: every path
is re-derived against a head accepted through its own pinned key, the same door `cl.inclusion` uses.

The reason to capture a window at all is that the prefix corpus could not answer a question it was being used
to answer. Positions 0 to 235 of Cloudflare's Nimbus2027 contain 8 `cA=TRUE` entries drawing edges from 4
distinct issuers, a figure this repository recorded as "a ratio, not an estimate". The middle of **the same
log** - same operator, same issuance policy, same moment in the ecosystem, differing only in position - holds
64 entries drawing from **17** issuers and no CA entries at all. So the prefix figure was a measurement of how
a log begins, and the hedge on it was carrying far less than it appeared to.

The second window is Google's Xenon2027h1, which agrees on direction (20 issuers) but is not the clean
comparison: it differs from the prefix in operator as well as position. Both numbers are recorded because a
single log's midpoint is one sample, not a population; what is *not* claimed anywhere below is a rate.

The windows also carry something the prefix does not: SCT lists. At both depths **every logged final
certificate embeds one** - 30 of 30 x509 entries at 25%, 23 of 23 at 50%, 10 of 10 in the Google log - while
none of the 116 x509 entries in the prefix of the same log does. So this is a step that happens somewhere
between position 235 and 25% depth, not a drift with depth, and the third window is what distinguishes those
two shapes. *Why* is not established here; only the shape is. What remains absent is the case folding needs -
one issuance logged twice under different `TBSCertificate` spellings - which no sample here exhibits.

Issuer cardinality, by contrast, does ramp: 4 distinct issuers at the start of Nimbus2027, 6 at 25%, 17 at
50%. Three points on one log, so it is a description rather than a model - but it is the same log and the same
operator at each point, which is the whole reason the second and third windows were captured.
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
WINDOWS: list[dict[str, Any]] = MID["windows"]
PREFIX = json.loads((FIXTURES / "entry-corpus.json").read_text("utf-8"))["logs"][0]
PREFIX_ORIGIN = PREFIX["origin"]


class Entry(TypedDict):
    index: int
    leaf_input: str
    extra_data: str
    identity: str
    inclusion: dict[str, Any]


def head_of(block: dict[str, Any]) -> dict[str, Any]:
    """The head block for either fixture shape: windows nest it under `log`, the prefix corpus does not.

    Two files written by two versions of the same tool, so the difference is stated here rather than smoothed
    away with `block.get("log", {}).get("head")`, which would read a missing head as an empty one and fail
    somewhere far away as a KeyError on `log_id`.
    """
    head: dict[str, Any] = block["log"]["head"] if "log" in block else block["head"]
    return head


def store_of(window_or_prefix: dict[str, Any], path_id: str) -> EntryStore:
    """An entry store over one block's bytes, keyed by that block's own log id."""
    log_id = bytes.fromhex(head_of(window_or_prefix)["log_id"])
    store = EntryStore()
    for entry in window_or_prefix["entries"]:
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


def records_of(block: dict[str, Any]) -> list[EntryRecord]:
    return list(store_of(block, "tool:corpus-window").entries())


def issuer_count(block: dict[str, Any], path_id: str) -> int:
    return len(list(CaGraph.build(store_of(block, path_id)).issuers()))


def same_log_windows() -> list[dict[str, Any]]:
    """Every window taken from the prefix's own log, shallowest first.

    Three depths of one log is the controlled experiment: operator, log and issuance population are held
    fixed, so anything that varies between them varies with position.
    """
    return sorted(
        (w for w in WINDOWS if w["log"]["origin"] == PREFIX_ORIGIN),
        key=lambda w: int(w["window"]["start"]),
    )


def same_log_window() -> dict[str, Any]:
    """The midpoint window from the prefix's own log, which is the cleanest single comparison.

    A lookup rather than an index: the comparison's validity depends on it being the *same* log, and a future
    recapture that drops that window should fail here loudly instead of quietly leaving the confounded
    cross-operator comparison as the only one.
    """
    for window in same_log_windows():
        if window["window"]["chosen_by"] == "tree_size // 2":
            return window
    raise AssertionError(
        f"no midpoint window from {PREFIX_ORIGIN}; the position claim needs the same log sampled twice, "
        "so re-run tools/corpus.py --window against it rather than leaning on the other operator"
    )


def other_log_windows() -> list[dict[str, Any]]:
    return [w for w in WINDOWS if w["log"]["origin"] != PREFIX_ORIGIN]


def test_every_window_entry_is_proved_into_a_head_that_log_signed(tmp_path: pathlib.Path) -> None:
    """Each window's paths run to the head stored in that window, accepted through its own pinned key.

    The negative control is the part that keeps this a test rather than a read: a flipped audit node has to
    fail, or the positive half is only checking the shape of the file.
    """
    for window in WINDOWS:
        origin = window["log"]["origin"]
        store, log_id = accepted_head(head_of(window), origin, tmp_path)
        for entry in window["entries"]:
            proof = entry["inclusion"]
            leaf_hash = merkle.leaf_hash(base64.b64decode(entry["leaf_input"]))
            path = tuple(bytes.fromhex(node) for node in proof["audit_path"])
            assert proof["leaf_index"] == entry["index"]
            assert store.verify_inclusion(
                log_id, leaf_hash, proof["leaf_index"], path, tree_size=proof["tree_size"]
            ), f"{origin}#{entry['index']} is not proved by the path stored beside it"
        first = window["entries"][0]
        path = tuple(bytes.fromhex(node) for node in first["inclusion"]["audit_path"])
        tampered = (path[0][:-1] + bytes([path[0][-1] ^ 1]), *path[1:])
        assert not store.verify_inclusion(
            log_id,
            merkle.leaf_hash(base64.b64decode(first["leaf_input"])),
            first["inclusion"]["leaf_index"],
            tampered,
            tree_size=first["inclusion"]["tree_size"],
        ), f"{origin}: a flipped audit node still verified, so nothing was being checked"


def test_each_window_starts_where_its_provenance_says_and_is_not_a_prefix() -> None:
    """Each window's recorded start must match the rule its own `chosen_by` claims.

    The field exists so a reader does not have to trust a bare number, so the two are compared: a midpoint
    window sits at size // 2, an explicit-start window matches the start it says it was given. Every window
    must also run contiguously and stop short of the tip, or "somewhere in the middle of a tree" is false.
    """
    for window in WINDOWS:
        size = int(head_of(window)["tree_size"])
        meta = window["window"]
        start = int(meta["start"])
        rule = str(meta["chosen_by"])
        if rule == "tree_size // 2":
            assert start == size // 2, (
                f"{window['log']['origin']}: claims a midpoint, starts at {start}"
            )
        else:
            assert rule == f"--start {start}", f"provenance {rule!r} does not match start {start}"
        assert start > 0, "a window starting at 0 is a prefix, which is the claim being contrasted"
        assert size - start > len(window["entries"]), "the window runs to the tip of the tree"
        indices = [entry["index"] for entry in window["entries"]]
        assert indices == list(range(start, start + len(indices))), "the window has a hole in it"


def test_the_same_log_measured_at_its_middle_has_more_issuers_than_at_its_start() -> None:
    """The clean version of the claim: one log, one operator, two positions.

    236 entries at the start of Nimbus2027 draw edges from 4 distinct issuers; 64 entries at its midpoint draw
    from 17. Nothing else about the two samples differs - same operator, same log, same issuance population -
    so the CA-layer cardinality the prefix reports is a fact about position 0 and cannot be quoted as the size
    of the CA layer.

    Asserted as a direction, not a rate: these are 64 and 236 entries out of hundreds of millions. A recapture
    that narrowed the gap would be news about the deployment, so the message says to re-measure the claim
    rather than delete the test holding it.
    """
    middle = issuer_count(same_log_window(), "tool:corpus-window")
    beginning = issuer_count(PREFIX, "tool:corpus")
    assert middle > beginning, (
        f"midpoint issuers {middle} no longer exceeds prefix issuers {beginning} in the same log; "
        "the position-dependence claim needs re-measuring, not deleting"
    )
    assert middle >= 2 * beginning, (
        f"the gap narrowed to {beginning} vs {middle}; 'a ratio about beginnings' is losing its force"
    )


def test_issuer_count_ramps_with_depth_on_one_log() -> None:
    """Three depths of the same log: 4 issuers at the start, 6 at 25% depth, 17 at 50%.

    The SCT finding is a step and this one is not. Issuer cardinality keeps climbing with depth on the same
    log and operator, which is why the third window was worth 64 more proofs: with only the prefix and the
    midpoint it looked like one jump, and it is not. Three points describe a direction and nothing further -
    no slope is fitted and no rate is claimed - but the ordering is what the CA-graph row needs, because it
    says the prefix's 4 is the *lowest* value this log shows rather than a typical one.
    """
    depths = same_log_windows()
    assert len(depths) >= 2, "the ramp claim needs at least two depths of the prefix's own log"
    counts = [issuer_count(window, "tool:corpus-window") for window in depths]
    beginning = issuer_count(PREFIX, "tool:corpus")
    assert counts == sorted(counts), f"issuer counts are out of depth order: {counts}"
    assert counts[0] > beginning, (
        f"shallowest window {counts[0]} is not above the prefix {beginning}"
    )
    assert counts[-1] > counts[0], f"depth added no issuers at all: {counts}"


def test_a_second_operator_window_agrees_on_the_direction_without_cleaning_it_up() -> None:
    """Corroboration from another operator, labelled for what it is: not a controlled comparison.

    Google's Xenon2027h1 midpoint also shows far more issuers than the Cloudflare prefix. That widens the
    sample but drops the control - operator, log and position all change together - so it stays in its own test
    rather than pooled with the clean one, where a confounded number could pass as evidence.
    """
    others = other_log_windows()
    assert others, "no second-operator window; this test exists to keep the confound visible"
    beginning = issuer_count(PREFIX, "tool:corpus")
    for window in others:
        middle = issuer_count(window, "tool:corpus-window")
        assert middle > beginning, f"{window['log']['origin']}: {middle} vs {beginning}"


def test_the_windows_hold_the_sct_bearing_bytes_and_still_not_the_folding_case() -> None:
    """SCT lists exist deep in a tree and not at its start - and one issuance in two spellings is absent.

    23 of 64 entries in the Cloudflare window and 10 of 64 in the Google window carry an SCT list, while none
    of the 236 prefix entries *from the same log as the first window* do. That retires the sentence saying this
    repository holds no SCT-bearing production bytes, and it says where to look for them. It declines to
    explain the ordering: why a mid-tree final certificate embeds SCTs when an early one does not is measured
    here and not established.

    The case folding needs still does not appear. It requires one certificate logged twice under different
    `TBSCertificate` spellings - two entries sharing an identity - and every window's identity count equals its
    entry count. Asserting that is what stops "we have SCTs now" from quietly becoming "we test folding".
    """
    prefix_records = records_of(PREFIX)
    assert sum(1 for r in prefix_records if r.has_sct_extension) == 0, (
        "the prefix now carries SCTs too, so 'the windows are the only source' is no longer the finding"
    )
    assert any(r.entry_type == "x509" for r in prefix_records), (
        "the prefix holds no logged certificates at all, so 'none of them embed SCTs' would prove nothing"
    )
    for block in WINDOWS:
        records = records_of(block)
        bearing = [r for r in records if r.has_sct_extension]
        assert bearing, f"{block['log']['origin']}: window lost the SCT-bearing entries"
        assert all(r.entry_type == "x509" for r in bearing), (
            "a precert carries its chain rather than an embedded SCT list, so this is not the case claimed"
        )
        logged = [r for r in records if r.entry_type == "x509"]
        assert logged, (
            f"{block['log']['origin']}: window holds no logged certificates, so the ratio is vacuous"
        )
        assert all(r.has_sct_extension for r in logged), (
            f"{block['log']['origin']}: {len(bearing)} of {len(logged)} logged certificates embed SCTs, so "
            "the step described above is no longer a step - re-measure before restating it"
        )
        assert len({r.identity for r in records}) == len(records), (
            f"{block['log']['origin']}: two entries share an identity, so the folding case may now be "
            "exhibit-able on production bytes"
        )


def test_a_window_proof_beyond_its_captured_head_is_refused(tmp_path: pathlib.Path) -> None:
    """The anchor is the captured head, not the log's current one, and the store enforces the difference.

    Both trees have grown since capture, which is exactly why these windows cannot be regenerated: asking for a
    size past the recorded head has to raise rather than have a root quietly recomputed from a newer tree.
    """
    for window in WINDOWS:
        store, log_id = accepted_head(head_of(window), window["log"]["origin"], tmp_path)
        entry = window["entries"][0]
        proof = entry["inclusion"]
        assert proof["tree_size"] == int(head_of(window)["tree_size"])
        with pytest.raises(UnknownHead):
            store.verify_inclusion(
                log_id,
                merkle.leaf_hash(base64.b64decode(entry["leaf_input"])),
                proof["leaf_index"],
                tuple(bytes.fromhex(node) for node in proof["audit_path"]),
                tree_size=proof["tree_size"] + 1,
            )
