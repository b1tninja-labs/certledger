"""A budgeted walk, and the discipline that a gap is about the fetch rather than the tree.

`cl.walk-budget`'s named test injects a failure into one range of a walk over **real entries** - the captured
Cloudflare Nimbus2027 prefix - and checks three things at once: that the walk resumed past the gap, that the
gap kept the receipt that proves it was attempted, and that nothing in the report lets an unread range be
read as an empty one.

The heads are signed by throwaway keys (`_support.ephemeral_log`), because a walk needs a head whose root
equals the tree its leaves hash to, and no log will sign an arbitrary prefix on demand. The *leaves* are
production bytes, which is the part the completeness arithmetic is actually about: a root hash over invented
leaves would only prove the code agrees with itself.

Two facts measured in this workspace shape the loop and are asserted here rather than assumed: Google answers
32 entries however many are asked for, and a log's own `get-entries` may return a partial range (RFC 6962
section 4.6). Both look like the end of a tree to a loop that treats a short response as exhaustion.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import pathlib
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from _support import a_receipt, ephemeral_log, sign_v1_head, write_pins
from ctspy import merkle

from certledger import (
    EntryStore,
    FetchFailure,
    GapState,
    HeadStore,
    KeyRing,
    LogWalk,
    WalkBudget,
)
from certledger.path import Exchange

CORPUS = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "entry-corpus.json").read_text("utf-8")
)
PRIMARY = CORPUS["logs"][0]
ORIGIN = PRIMARY["origin"]
ENTRIES: list[dict[str, Any]] = [
    {"leaf_input": entry["leaf_input"], "extra_data": entry["extra_data"]}
    for entry in PRIMARY["entries"]
]


class ReplayFetcher:
    """Serves `get-entries` from stored bytes, with failures injected at chosen start indices."""

    def __init__(
        self,
        entries: list[dict[str, Any]],
        *,
        answer: int | None = None,
        fail_at: tuple[int, ...] = (),
        garbage_at: tuple[int, ...] = (),
        empty_at: tuple[int, ...] = (),
        mutate_at: dict[int, int] | None = None,
        raw_at: dict[int, bytes] | None = None,
        path_id: str = "p-replay",
    ) -> None:
        self.entries = entries
        self.answer = answer
        self.fail_at = fail_at
        self.garbage_at = garbage_at
        self.empty_at = empty_at
        self.mutate_at = mutate_at or {}
        self.raw_at = raw_at or {}
        self.path_id = path_id
        self.requests: list[tuple[int, int]] = []

    def fetch(self, url: str, *, method: str = "GET", body: bytes | None = None) -> Exchange:
        query = parse_qs(urlsplit(url).query)
        start, end = int(query["start"][0]), int(query["end"][0])
        self.requests.append((start, end))
        receipt = dataclasses.replace(
            a_receipt(), path_id=self.path_id, request_target=f"GET {url}"
        )
        if start in self.fail_at:
            raise FetchFailure(f"{self.path_id}: replay refused {start}", receipt=receipt)
        if start in self.raw_at:
            return Exchange(
                status=200, reason="OK", headers=(), body=self.raw_at[start], receipt=receipt
            )
        if start in self.garbage_at:
            payload = b"<html>rate limited, try later</html>"
            return Exchange(
                status=429, reason="Too Many Requests", headers=(), body=payload, receipt=receipt
            )
        if start in self.empty_at:
            return self._ok({"entries": []}, receipt)
        window = self.entries[start : end + 1]
        if self.answer is not None:
            window = window[: self.answer]
        window = [self._mutated(item, start + offset) for offset, item in enumerate(window)]
        return self._ok({"entries": window}, receipt)

    def _mutated(self, item: dict[str, Any], index: int) -> dict[str, Any]:
        """Change one leaf octet at `index`, so the tree hash moves while the entry stays parseable-ish."""
        if index not in self.mutate_at:
            return item
        raw = bytearray(base64.b64decode(item["leaf_input"]))
        position = self.mutate_at[index]
        raw[position] = (raw[position] + 1) % 256
        return {**item, "leaf_input": base64.b64encode(bytes(raw)).decode()}

    def _ok(self, document: dict[str, Any], receipt: Any) -> Exchange:
        payload = json.dumps(document).encode()
        return Exchange(status=200, reason="OK", headers=(), body=payload, receipt=receipt)


def accepted_head(
    tmp_path: pathlib.Path,
    leaves: list[bytes],
    *,
    tree_size: int | None = None,
    origin: str = ORIGIN,
) -> tuple[Any, bytes]:
    """A head this store accepted, signed by a throwaway key over `leaves`."""
    private, spki, log_id = ephemeral_log()
    size = len(leaves) if tree_size is None else tree_size
    sth = sign_v1_head(private, 1_700_000_000_000, size, merkle.tree_hash(leaves))
    ring = KeyRing.load(write_pins(tmp_path, [("walk test", origin, spki)]))
    return HeadStore().accept(sth, ring, origin=origin, receipt=a_receipt()), log_id


def leaves_of(count: int) -> list[bytes]:
    return [base64.b64decode(entry["leaf_input"]) for entry in ENTRIES[:count]]


def test_gap_is_recorded_as_unreachable(tmp_path: pathlib.Path) -> None:
    """The row's exit test: one refused range becomes a gap, and the gap is about the fetch.

    Three separate claims are checked, because a walk can satisfy any one of them while failing the others.
    It must **resume** past the gap (a walk that stopped there would report the rest of the tree as missing);
    it must **keep the receipt** (I6 - months later, "we could not reach it" and "it was not there" are
    different facts and only a receipt tells them apart); and it must **refuse absence** for the unread
    range, which is I5's rule that a single path never supports a not-in-the-log claim.
    """
    head, log_id = accepted_head(tmp_path, leaves_of(96))
    fetcher = ReplayFetcher(ENTRIES, answer=32, fail_at=(32,))
    report = LogWalk(
        origin=ORIGIN, log_id=log_id, fetcher=fetcher, store=EntryStore(), head=head
    ).run()

    assert len(report.gaps) == 1
    gap = report.gaps[0]
    assert gap.state is GapState.UNREACHABLE
    assert (gap.start, gap.end) == (32, 64)
    assert gap.count == 32

    # Resumed: the window after the failure was still fetched, so 64 entries are held, not 32.
    assert report.entries == 64
    assert report.covers(64)
    assert report.covers(10)
    assert not report.covers(40), "the unread range must not read as read"

    # The receipt survived into the gap: the failure is attributable to a path and a target.
    assert gap.receipt is not None
    assert gap.receipt.path_id == "p-replay"
    assert "start=32" in gap.receipt.request_target
    assert "replay refused 32" in gap.reason

    # Absence is not available for anything, because the walk did not complete.
    assert not report.complete
    assert not report.may_claim_absent(40)
    assert not report.may_claim_absent(10)
    assert report.root_hash is None, "0..31 plus 64..95 is not a tree, so no root may be quoted"


def test_a_short_page_is_a_cap_and_not_the_end_of_the_tree(tmp_path: pathlib.Path) -> None:
    """Google answers 32 however many are asked for. A loop that reads short as exhausted reports a
    32-entry tree for a log with three billion entries, and the report would look complete.

    The walk learns the observed cap, keeps going from the first index it did not receive, and only
    terminates on the signed tree size - which is the head's number, not the response's.
    """
    head, log_id = accepted_head(tmp_path, leaves_of(96))
    fetcher = ReplayFetcher(ENTRIES, answer=32)
    report = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=fetcher,
        store=EntryStore(),
        head=head,
        budget=WalkBudget(page=256),
    ).run()

    assert report.page_cap == 32, "the cap should be learned from the first short answer"
    assert report.entries == 96
    assert not report.gaps, report.summary()
    assert fetcher.requests[0] == (0, 95), "the window is clipped to the tree size, not to the page"
    assert fetcher.requests[1] == (32, 63), (
        "after a 32-entry answer the walk should ask for 32, not 256"
    )
    assert report.complete, report.summary()
    assert report.may_claim_absent(50), (
        "a completed walk over a matching root supports the claim (I5)"
    )


def test_no_entries_inside_the_signed_tree_size_is_an_anomaly(tmp_path: pathlib.Path) -> None:
    """A log that answers with nothing while its head promises entries has a problem, not a finished tree.

    Section 4.6 lets a log answer partially, so "empty" is not evidence of absence; the signed head is. The
    state is `EMPTY_WITHIN_TREE` rather than `UNREACHABLE` because the fetch *succeeded* - the disagreement
    is between two things the log said, which is a finding about the log.
    """
    head, log_id = accepted_head(tmp_path, leaves_of(96))
    fetcher = ReplayFetcher(ENTRIES, answer=32, empty_at=(32,))
    report = LogWalk(
        origin=ORIGIN, log_id=log_id, fetcher=fetcher, store=EntryStore(), head=head
    ).run()

    assert [gap.state for gap in report.gaps] == [GapState.EMPTY_WITHIN_TREE]
    assert str(head.tree_size) in report.gaps[0].reason
    assert report.entries == 64
    assert not report.complete


def test_a_body_that_is_not_json_is_a_failed_fetch_not_an_empty_tree(
    tmp_path: pathlib.Path,
) -> None:
    """The conflation this module exists to prevent, tested directly.

    A rate limiter that answers 429 with an HTML body is a *successful* HTTP exchange from `http.client`'s
    point of view. Reading its body as JSON would either raise or, with a `.get("entries", [])`, produce an
    empty list that looks exactly like a log with no entries there. The walk calls that `UNREACHABLE` and
    says what the body was.
    """
    head, log_id = accepted_head(tmp_path, leaves_of(64))
    fetcher = ReplayFetcher(ENTRIES, answer=32, garbage_at=(0,))
    report = LogWalk(
        origin=ORIGIN, log_id=log_id, fetcher=fetcher, store=EntryStore(), head=head
    ).run()

    assert [gap.state for gap in report.gaps] == [GapState.UNREACHABLE]
    assert "not JSON" in report.gaps[0].reason
    assert (report.gaps[0].start, report.gaps[0].end) == (0, 64)
    assert report.entries == 0
    assert report.requests == 1, (
        "one bad page gaps its own window; the walk does not retry inside a pass"
    )


def test_request_budget_stops_the_walk_and_records_the_rest_as_unreached(
    tmp_path: pathlib.Path,
) -> None:
    """A budget stop is not a finished tree, and the gap has no receipt because no request was made.

    The distinction matters for the completeness record: an `UNREACHABLE` gap says a path was tried and
    refused, which is a fact about the network that another pass might fix. A `BUDGET` gap says this process
    stopped by choice, which is a fact about the plan. Recording a receipt for a request that never happened
    would attribute the gap to the log.
    """
    head, log_id = accepted_head(tmp_path, leaves_of(96))
    report = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES, answer=32),
        store=EntryStore(),
        head=head,
        budget=WalkBudget(requests=2, page=256),
    ).run()

    assert report.entries == 64
    assert [(gap.state, gap.start, gap.end) for gap in report.gaps] == [(GapState.BUDGET, 64, 96)]
    assert report.gaps[0].receipt is None, "no request, so no receipt to cite"
    assert not report.complete
    assert not report.may_claim_absent(80)


def test_response_byte_budget_stops_the_walk_midflight(tmp_path: pathlib.Path) -> None:
    """Bytes are the other budget, and this gap does have a receipt - it followed a real fetch."""
    head, log_id = accepted_head(tmp_path, leaves_of(96))
    report = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES),
        store=EntryStore(),
        head=head,
        budget=WalkBudget(page=32, response_bytes=1),
    ).run()

    assert report.entries == 32
    assert report.gaps[0].state is GapState.BUDGET
    assert report.gaps[0].receipt is not None, "the gap follows a real fetch, so it cites one"
    assert not report.complete


def test_counting_entries_alone_never_declares_a_walk_complete(tmp_path: pathlib.Path) -> None:
    """The walk holds the right number of entries in the right positions and is still not complete.

    One leaf octet comes back changed. Every counter in the report is satisfied - 64 entries, no gaps, no
    failures - and only the root hash disagrees with the signed head. If completeness were bookkeeping this
    walk would pass, and it is precisely the walk that must not: a log serving a tree it did not sign is the
    thing CT exists to catch, and an absence claim resting on that tree would be the monitor's own false
    accusation.
    """
    head, log_id = accepted_head(tmp_path, leaves_of(64))
    report = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES, mutate_at={10: 40}),
        store=EntryStore(),
        head=head,
        budget=WalkBudget(page=32),
    ).run()

    assert report.entries == 64
    assert report.gaps == ()
    assert report.root_hash is not None
    assert report.root_hash != report.head_root
    assert not report.complete
    assert not report.may_claim_absent(10)
    assert not report.may_claim_absent(0)


def test_re_serving_one_position_differently_stops_the_walk_as_a_conflict(
    tmp_path: pathlib.Path,
) -> None:
    """A position that comes back with different bytes means the tree moved; the walk stops and records it.

    `EntryStore.add` raises rather than overwriting, for the same reason `HeadStore` refuses a smaller head:
    the two versions are evidence, and the second one is the finding. The walk turns that refusal into a
    `CONFLICT` gap and halts, rather than carrying on to report a tree assembled from two histories.
    """
    store = EntryStore()
    head, log_id = accepted_head(tmp_path, leaves_of(64))
    LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES),
        store=store,
        head=head,
        budget=WalkBudget(page=32),
    ).run()

    report = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES, mutate_at={5: 41}),
        store=store,
        head=head,
        budget=WalkBudget(page=32),
    ).run(start=5)

    assert [gap.state for gap in report.gaps] == [GapState.CONFLICT]
    assert report.requests == 1, "the walk must halt on the conflict rather than fetch past it"
    assert report.conflicted
    assert not report.complete, (
        "a store holding a whole tree still may not certify one it saw disputed"
    )
    assert not report.may_claim_absent(0)


def test_a_resume_fills_an_earlier_gap_without_rewriting_it(tmp_path: pathlib.Path) -> None:
    """Two passes over one store: the second reads what the first could not, and the root becomes honest.

    The first pass's report keeps its gap - a record is not edited afterwards to look better - while the
    second pass reports completeness, because by then the leaves really are a contiguous run whose hash
    matches the head. That separation is the point: the incompleteness happened, and the store's final state
    is provably whole.
    """
    store = EntryStore()
    head, log_id = accepted_head(tmp_path, leaves_of(96))
    first = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES, answer=32, fail_at=(32,)),
        store=store,
        head=head,
    ).run()
    assert first.entries == 64
    assert not first.complete
    assert first.root_hash is None, (
        "a run with a hole in it has no tree hash, and none should be claimed"
    )

    second = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES, answer=32),
        store=store,
        head=head,
    ).run(start=32)
    assert second.gaps == ()
    assert second.entries == 96
    assert second.complete, second.summary()


def test_a_head_from_another_log_is_refused(tmp_path: pathlib.Path) -> None:
    """A walk sized by someone else's tree would call a short tree complete."""
    head, _ = accepted_head(tmp_path, leaves_of(32))
    with pytest.raises(ValueError, match="another log"):
        LogWalk(
            origin=ORIGIN,
            log_id=b"\x01" * 32,
            fetcher=ReplayFetcher(ENTRIES),
            store=EntryStore(),
            head=head,
        )


def test_no_absence_claim_survives_a_real_tree_size(tmp_path: pathlib.Path) -> None:
    """The scale, stated honestly: against Nimbus2027's real head, one sampled prefix supports nothing.

    The head here is the log's own - signature verified over the pinned key, accepted by `HeadStore` - so
    `tree_size` is production's number rather than a test's. Two pages of real entries, then the budget
    stops, and the report refuses an absence claim anywhere in the unread bulk of the tree. This is what
    `cl.walk-budget` actually costs: a completed walk over hundreds of millions of entries, or nothing.
    """
    from ctspy.sth import SignedTreeHeadV1

    key_spki = base64.b64decode(PRIMARY["head"]["key_spki"])
    document = PRIMARY["head"]
    sth = SignedTreeHeadV1(
        timestamp=document["timestamp"],
        tree_size=document["tree_size"],
        root_hash=bytes.fromhex(document["root_hash"]),
        signature=base64.b64decode(document["signature"]),
    )
    ring = KeyRing.load(write_pins(tmp_path, [("corpus", ORIGIN, key_spki)]))
    head = HeadStore().accept(sth, ring, origin=ORIGIN, receipt=a_receipt())
    assert head.tree_size > 100_000_000, head.tree_size

    report = LogWalk(
        origin=ORIGIN,
        log_id=bytes.fromhex(document["log_id"]),
        fetcher=ReplayFetcher(ENTRIES, answer=32),
        store=EntryStore(),
        head=head,
        budget=WalkBudget(requests=2, page=256),
    ).run()

    assert report.entries == 64
    assert report.gaps[0].state is GapState.BUDGET
    assert report.gaps[0].end == head.tree_size
    assert not report.covers(150_000_000)
    assert not report.may_claim_absent(150_000_000)
    assert report.missing() == head.tree_size - 64


def test_one_undecodable_entry_costs_one_position_and_not_the_whole_log(
    tmp_path: pathlib.Path,
) -> None:
    """A malformed entry is a bad response, not a changed tree, and the two must not cost the same.

    The page that comes back with garbage base64 at position 0 yields exactly one gap - position 0 - and the
    walk carries on to read the rest. Treating it as a `CONFLICT` would freeze a healthy log over one bad
    field; ignoring it and continuing would leave a hole that the counters do not show. The hole *is* shown:
    position 0 is missing, so `root_hash` stays None and completeness is unavailable even though 63 of 64
    entries are held.
    """
    head, log_id = accepted_head(tmp_path, leaves_of(64))
    broken = json.dumps(
        {"entries": [{"leaf_input": "not base64 at all", "extra_data": ""}]}
    ).encode()
    report = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES, raw_at={0: broken}),
        store=EntryStore(),
        head=head,
        budget=WalkBudget(page=32),
    ).run()

    assert [(gap.state, gap.start, gap.end) for gap in report.gaps] == [
        (GapState.UNREACHABLE, 0, 1)
    ]
    assert "undecodable" in report.gaps[0].reason
    assert report.entries == 63, "everything after the bad position should still have been read"
    assert not report.covers(0)
    assert report.covers(30)
    assert report.root_hash is None, "63 of 64 leaves hash to a number about nothing"
    assert not report.complete
    assert not report.may_claim_absent(30)


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        (b'{"nope": 1}', "no entries array"),
        (b'[{"entries": []}]', "not an object"),
        (b'{"entries": "sorry"}', "not an array"),
    ],
)
def test_json_that_is_not_an_entries_array_is_a_failed_fetch(
    tmp_path: pathlib.Path, body: bytes, fragment: str
) -> None:
    """Well-formed JSON is not a valid response, and each shape that fails says how it failed.

    All three would satisfy a careless reader: `.get("entries", [])` returns `[]` for the first two and
    iterates a string into nothing for the third. Each becomes an `UNREACHABLE` gap naming the shape,
    because the next pass needs to know whether to retry the range or file a complaint about the log.
    """
    head, log_id = accepted_head(tmp_path, leaves_of(32))
    report = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES, raw_at={0: body}),
        store=EntryStore(),
        head=head,
        budget=WalkBudget(page=32),
    ).run()

    assert report.entries == 0
    assert [gap.state for gap in report.gaps] == [GapState.UNREACHABLE]
    assert fragment in report.gaps[0].reason


def test_the_report_says_in_words_what_it_found(tmp_path: pathlib.Path) -> None:
    """The summaries are the part a human reads at 3am, so they have to carry the two decisive facts.

    For a gap: whether a request was even made - a budget stop was our decision, a refusal was the log's.
    For a walk: whether the root matched, spelled out rather than left to be inferred from a boolean.
    """
    head, log_id = accepted_head(tmp_path, leaves_of(96))
    stopped = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES, answer=32),
        store=EntryStore(),
        head=head,
        budget=WalkBudget(requests=2, page=256),
    ).run()
    gap = stopped.gaps[0]
    assert "no request was made" in gap.summary()
    assert GapState.BUDGET.value in gap.summary()
    assert stopped.gaps_at(80) == (gap,)
    assert "does not match" in stopped.summary()

    walked = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES, answer=32),
        store=EntryStore(),
        head=head,
        budget=WalkBudget(page=32),
    ).run()
    assert "MATCHES" in walked.summary()
