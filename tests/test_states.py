"""The state table as code: what a pass over a log is allowed to claim, and what stops it.

`cl.states`'s named test shows one log at one tree size with two roots, which is the case the whole
architecture exists to catch, and checks the consequence in four places at once: the state, the publication
gate, the freeze that outlives it, and the absence claim that dies with it.

Heads here are built directly rather than accepted through `HeadStore`, because a store *refuses* the second
root at a size it has already seen - so a divergent pair cannot both come from one store's history. A
`HeadRecord` in these tests means "a path showed this", which is exactly what `assess` weighs; whether the
store accepted it is `HeadStore`'s decision, and a refused head arrives as an `incident` on a path outcome.
"""

from __future__ import annotations

import datetime
import pathlib
from typing import Any

import pytest
from _support import a_receipt, ephemeral_log

from certledger import (
    EntryStore,
    Gap,
    GapState,
    HumanDecision,
    LogWalk,
    PathOutcome,
    PublicationRefused,
    State,
    TrustClass,
    WalkReport,
    assess,
)
from certledger.heads import HeadRecord

ORIGIN = "https://log.example.test"
NOW = datetime.datetime(2026, 11, 5, 12, 0, tzinfo=datetime.UTC)


def shown(
    log_id: bytes,
    size: int,
    root: bytes,
    *,
    age: datetime.timedelta = datetime.timedelta(0),
) -> HeadRecord:
    """A head one path showed. `age` back-dates when we accepted it, for the staleness rule."""
    return HeadRecord(
        log_id=log_id,
        tree_size=size,
        root_hash=root,
        timestamp=int(NOW.timestamp() * 1000) - int(age.total_seconds() * 1000),
        accepted_utc=(NOW - age).isoformat(),
        receipt=a_receipt(),
        bootstrap=False,
    )


def root_of(seed: int) -> bytes:
    return bytes([seed]) * 32


def outcome(
    path_id: str,
    cls: TrustClass = TrustClass.LOCAL,
    **fields: Any,
) -> PathOutcome:
    return PathOutcome(path_id=path_id, trust_class=cls, **fields)


def test_divergent_is_not_publishable() -> None:
    """One tree size, two roots: freeze publication, alert, keep fetching - and say what disagreed.

    The four consequences are checked together because they are one decision. A state that froze the log but
    still allowed an absence claim would accuse a certificate of being unlogged using a tree we have just
    seen the log disagree about. A state that alerted without keeping the log scheduled would stop collecting
    the evidence that resolves it, and the table's "keep fetching" exists because disagreement is itself
    publishable data.
    """
    _, _, log_id = ephemeral_log()
    paths = (
        outcome("p-local", head=shown(log_id, 100, root_of(1))),
        outcome("p-hosted", TrustClass.HOSTED, head=shown(log_id, 100, root_of(2))),
    )
    seen = assess(log_id, ORIGIN, paths, now=NOW)

    assert seen.state is State.DIVERGENT
    assert not seen.publishable
    with pytest.raises(PublicationRefused, match="DIVERGENT"):
        seen.require_publishable()

    assert seen.freeze is not None
    assert seen.freeze.active
    assert seen.alert
    assert seen.keep_fetching
    assert not seen.supports_absence
    assert "100" in seen.reason
    assert root_of(1).hex()[:16] in seen.reason
    assert root_of(2).hex()[:16] in seen.reason
    assert seen.explanation().count("p-") == 2, "the explanation names both paths that disagreed"


def test_a_divergence_freeze_survives_a_corroborated_pass() -> None:
    """Good news does not clear a freeze; only a named human with a date does, and clearing is not re-trust.

    The later pass really is corroborated by two classes, so its own state is `VERIFIED` - and it is still not
    publishable, because the freeze is about the setup rather than about this response. Section 8 reserves the
    lifting decision for a human because the most realistic compromise looks entirely routine. Note what
    clearing does *not* do: it leaves the state alone, so the `DIVERGENT` observation is not rewritten
    afterwards to look like it never happened.
    """
    _, _, log_id = ephemeral_log()
    divergent = assess(
        log_id,
        ORIGIN,
        (
            outcome("p-local", head=shown(log_id, 100, root_of(1))),
            outcome("p-hosted", TrustClass.HOSTED, head=shown(log_id, 100, root_of(2))),
        ),
        now=NOW,
    )
    carried = assess(
        log_id,
        ORIGIN,
        (
            outcome("p-local", head=shown(log_id, 101, root_of(3))),
            outcome("p-hosted", TrustClass.HOSTED, head=shown(log_id, 101, root_of(3))),
        ),
        freeze=divergent.freeze,
        now=NOW + datetime.timedelta(minutes=5),
    )
    assert carried.state is State.VERIFIED
    assert carried.corroborated
    assert not carried.publishable, "a frozen log publishes nothing, corroborated or not"
    assert carried.keep_fetching

    decision = HumanDecision(
        by="ops@example.test",
        note="confirmed both roots against the log's own checkpoint feed; interceptor at the host",
        utc=NOW + datetime.timedelta(hours=1),
    )
    lifted = carried.cleared(decision)
    assert lifted.state is State.VERIFIED
    assert lifted.publishable
    assert "cleared 2026-11-05 by ops@example.test" in lifted.explanation()

    still_divergent = divergent.cleared(decision)
    assert still_divergent.state is State.DIVERGENT
    assert not still_divergent.publishable, "clearing lifts a freeze; it never rewrites a finding"


def test_two_paths_in_one_class_are_one_observation() -> None:
    """I5 and I7 count classes, not paths. Two fetches through one laptop is one way of being wrong.

    A configuration file that added a third local path would otherwise manufacture corroboration, which is
    the cheapest way for a deployment to believe it has bought independence it never paid for.
    """
    _, _, log_id = ephemeral_log()
    seen = assess(
        log_id,
        ORIGIN,
        (
            outcome("p-laptop", head=shown(log_id, 100, root_of(1))),
            outcome("p-laptop-vpn", head=shown(log_id, 100, root_of(1))),
        ),
        now=NOW,
    )
    assert seen.state is State.SINGLE_PATH
    assert seen.classes == ("local",)
    assert not seen.corroborated
    assert not seen.publishable
    assert not seen.supports_absence
    assert "one path class" in seen.reason


def test_a_completed_walk_supports_absence_from_a_single_class() -> None:
    """The other route I5 allows: leaves that hash to the signed root cannot be missing one.

    And the answer it permits carries its own qualification, in the words PLAN.md's loop asks for - "not in my
    copy, which is one path, complete up to head ..." - because an unqualified "not found" from one observer
    is how a monitor turns its own coverage into an accusation.
    """
    _, _, log_id = ephemeral_log()
    report = WalkReport(
        log_id=log_id,
        origin=ORIGIN,
        tree_size=64,
        entries=64,
        requests=2,
        response_bytes=4096,
        page_cap=32,
        gaps=(),
        root_hash=root_of(7),
        head_root=root_of(7),
    )
    seen = assess(
        log_id,
        ORIGIN,
        (outcome("p-local", head=shown(log_id, 64, root_of(7)), walk=report),),
        now=NOW,
    )
    assert seen.state is State.SINGLE_PATH
    assert seen.supports_absence, "the walk proved completeness by hash; I5 allows the claim"
    qualification = seen.absence_qualification()
    assert qualification.startswith("not in my copy, which is one path, complete up to head")
    assert "64/" in qualification


def test_an_unauthenticated_path_never_supplies_corroboration() -> None:
    """Never silently downgrade: a path that cannot prove its endpoint caps the result instead of counting.

    Dropping such a path and calling the rest `SINGLE_PATH` would be right by accident, and counting it would
    be the downgrade the rule names. So it cannot corroborate, it cannot divergence-freeze the log either - we
    cannot tell the log's word from an interceptor's - and it alerts, because "one path could not authenticate
    itself" is what A2 looks like from inside this process.
    """
    _, _, log_id = ephemeral_log()
    seen = assess(
        log_id,
        ORIGIN,
        (
            outcome("p-local", head=shown(log_id, 100, root_of(1))),
            outcome(
                "p-hosted",
                TrustClass.HOSTED,
                head=shown(log_id, 100, root_of(1)),
                authenticated=False,
            ),
        ),
        now=NOW,
    )
    assert seen.state is State.SINGLE_PATH
    assert seen.classes == ("local",)
    assert seen.alert
    assert not seen.publishable
    assert ", unauthenticated" in seen.explanation()


def test_staleness_beats_verification_and_defeats_absence() -> None:
    """A corroborated head that has not moved past budget is `STALE`: said plainly, never shown as current.

    `STALE` outranks `VERIFIED` even though the content is corroborated, because the property at issue is
    currency, and the only way to guarantee a stale tree is never presented as current is to make staleness
    destroy the publishable state rather than annotate it. Absence goes the same way: an absence claim against
    a tree known to be hours behind is a claim about the past.
    """
    _, _, log_id = ephemeral_log()
    aged = shown(log_id, 100, root_of(1), age=datetime.timedelta(hours=8))
    stale = assess(
        log_id,
        ORIGIN,
        (
            outcome("p-local", head=aged),
            outcome("p-hosted", TrustClass.HOSTED, head=aged),
        ),
        previous=aged,
        now=NOW,
    )
    assert stale.state is State.STALE
    assert stale.corroborated, "corroboration does not rescue currency"
    assert not stale.publishable
    assert not stale.supports_absence
    assert "no growth" in stale.reason

    current = assess(
        log_id,
        ORIGIN,
        (
            outcome("p-local", head=shown(log_id, 101, root_of(2))),
            outcome("p-hosted", TrustClass.HOSTED, head=shown(log_id, 101, root_of(2))),
        ),
        previous=aged,
        now=NOW,
    )
    assert current.state is State.VERIFIED
    assert current.publishable


def test_every_path_down_records_a_fetch_failure_and_no_absence() -> None:
    """`UNREACHABLE` is where an absence claim is most tempting and least deserved."""
    _, _, log_id = ephemeral_log()
    seen = assess(
        log_id,
        ORIGIN,
        (
            outcome("p-local", failure="Unreachable: connect timed out"),
            outcome("p-hosted", TrustClass.HOSTED, failure="FetchFailure: TLS handshake refused"),
        ),
        now=NOW,
    )
    assert seen.state is State.UNREACHABLE
    assert "all 2 path(s) failed" in seen.reason
    assert not seen.publishable
    assert not seen.supports_absence
    assert seen.keep_fetching
    assert "never absence of entry" in seen.state.behaviour
    assert seen.public, "a log we could not reach is still talkable about; it is not a secret"


def test_a_head_the_store_refused_is_an_incident_not_a_connectivity_problem() -> None:
    """The realistic route to `DIVERGENT`: `HeadStore` raises and the caller records that as an incident.

    A refused head means the path *answered*, so this is not `UNREACHABLE`; and the disagreement is between
    the log and our own monotonic record, which is `TreeShrank`, `HeadDivergence` or `BadConsistencyProof` -
    each of them a finding rather than something to retry.
    """
    _, _, log_id = ephemeral_log()
    seen = assess(
        log_id,
        ORIGIN,
        (
            outcome("p-local", head=shown(log_id, 100, root_of(1))),
            outcome(
                "p-hosted", TrustClass.HOSTED, incident="HeadDivergence: two histories at size 100"
            ),
        ),
        now=NOW,
    )
    assert seen.state is State.DIVERGENT
    assert "HeadDivergence" in seen.reason
    assert seen.freeze is not None
    assert seen.freeze.active
    assert not seen.publishable


def test_a_walk_that_saw_a_position_change_under_it_diverges_the_log() -> None:
    """One path's own walk can produce the finding without a second path being involved.

    A position served with different bytes is the tree disagreeing with itself over time - the same category
    as two paths disagreeing at one instant - and `WalkReport` already refuses to certify completeness on
    that evidence. The log state has to inherit the refusal rather than average it away.
    """
    _, _, log_id = ephemeral_log()
    report = WalkReport(
        log_id=log_id,
        origin=ORIGIN,
        tree_size=64,
        entries=64,
        requests=3,
        response_bytes=8192,
        page_cap=32,
        gaps=(Gap(5, 37, GapState.CONFLICT, "leaf at 5 changed", None),),
        root_hash=root_of(9),
        head_root=root_of(9),
    )
    seen = assess(
        log_id,
        ORIGIN,
        (outcome("p-local", head=shown(log_id, 64, root_of(9)), walk=report),),
        now=NOW,
    )
    assert seen.state is State.DIVERGENT
    assert "watched a position change under it" in seen.reason
    assert not seen.supports_absence


def test_nothing_that_answered_proved_its_endpoint() -> None:
    """`UNAUTHENTICATED` is internal only, and reserved for when *nothing* that answered was provable.

    A failed handshake also means the endpoint went unvalidated, so if this state outranked `UNREACHABLE`,
    every timeout in the fleet would be reported as a possible interceptor and the report would stop being
    believed when a real one turned up. Hence the ordering: nothing answered, that is `UNREACHABLE`; something
    answered and we cannot say to whom, that is this.
    """
    _, _, log_id = ephemeral_log()
    seen = assess(
        log_id, ORIGIN, (outcome("p-hosted", TrustClass.HOSTED, authenticated=False),), now=NOW
    )
    assert seen.state is State.UNAUTHENTICATED
    assert not seen.public
    assert not seen.publishable
    assert not seen.supports_absence
    assert seen.alert


def test_an_empty_pass_is_not_an_observation() -> None:
    """A pass with no outcomes is a report that left the failures out, not a healthy log."""
    _, _, log_id = ephemeral_log()
    with pytest.raises(ValueError, match="empty pass"):
        assess(log_id, ORIGIN, (), now=NOW)


def test_a_decision_to_resume_publication_has_to_be_attributable() -> None:
    """A freeze lifts only on something a later reader could ask questions of.

    Three refusals, one per field: no name, a note too short to be an audit record, and a timestamp with no
    zone, which could not be ordered against the fetch it describes. Clearing an observation that was never
    frozen is also raised, because it means two components disagree about the log's state - which is itself
    the kind of thing this file is not allowed to paper over.
    """
    with pytest.raises(ValueError, match="name the human"):
        HumanDecision(by="  ", note="checked the checkpoint feed against a second vantage", utc=NOW)
    with pytest.raises(ValueError, match="too short"):
        HumanDecision(by="ops@example.test", note="ok", utc=NOW)
    with pytest.raises(ValueError, match="without a zone"):
        HumanDecision(
            by="ops@example.test",
            note="checked the checkpoint feed against a second vantage",
            utc=datetime.datetime(2026, 11, 5, 12, 0),
        )

    _, _, log_id = ephemeral_log()
    healthy = assess(
        log_id,
        ORIGIN,
        (
            outcome("p-local", head=shown(log_id, 100, root_of(1))),
            outcome("p-hosted", TrustClass.HOSTED, head=shown(log_id, 100, root_of(1))),
        ),
        now=NOW,
    )
    assert healthy.publishable
    with pytest.raises(ValueError, match="nothing is frozen"):
        healthy.cleared(
            HumanDecision(by="ops@example.test", note="nothing was frozen here", utc=NOW)
        )


def test_a_path_that_answered_without_a_head_is_not_a_healthy_log() -> None:
    """A path that connected and produced nothing is `UNREACHABLE`, not `SINGLE_PATH` with zero evidence.

    Small and easy to lose: the TCP connection worked, so a naive "did any path answer" test says yes, and an
    observation built from an answer that carried no head would otherwise fall to the bottom of the ladder and
    be labelled `SINGLE_PATH` - a state that promises verified content. There is no content here, verified or
    otherwise.
    """
    _, _, log_id = ephemeral_log()
    seen = assess(log_id, ORIGIN, (outcome("p-local"),), now=NOW)
    assert seen.state is State.UNREACHABLE
    assert "without offering a head" in seen.reason
    assert not seen.publishable
    assert not seen.supports_absence
    assert "no head offered" in seen.explanation()


def test_the_qualification_names_the_route_the_claim_takes() -> None:
    """Both renderers have to tell apart two classes, one class, and no claim at all.

    `absence_qualification()` is the sentence that sits next to a "not found", and `explanation()` is what an
    operator reads when a log goes red. Each has to say *which* evidence stands behind it, because "not
    found" carries a different amount of risk depending on whether two path classes or one completed walk
    produced it - and a different amount again when nothing supports it.
    """
    _, _, log_id = ephemeral_log()
    corroborated = assess(
        log_id,
        ORIGIN,
        (
            outcome("p-local", head=shown(log_id, 100, root_of(1))),
            outcome("p-hosted", TrustClass.HOSTED, head=shown(log_id, 100, root_of(1))),
        ),
        now=NOW,
    )
    assert corroborated.supports_absence
    assert corroborated.absence_qualification() == (
        "not present in copies from 2 path classes: hosted, local"
    )

    disputed = assess(
        log_id,
        ORIGIN,
        (
            outcome("p-local", failure="Unreachable: connect timed out"),
            outcome(
                "p-hosted", TrustClass.HOSTED, incident="HeadDivergence: two histories at size 100"
            ),
        ),
        now=NOW,
    )
    assert disputed.state is State.DIVERGENT
    assert disputed.absence_qualification() == (
        "absence is not claimable from this observation (DIVERGENT)"
    )
    rendered = disputed.explanation()
    assert "Unreachable: connect timed out" in rendered, (
        "a failure stays visible, not averaged away"
    )
    assert "incident - HeadDivergence" in rendered


def test_a_gapped_walk_over_production_entries_supports_no_absence(tmp_path: pathlib.Path) -> None:
    """The two rows composed, on real bytes: a gapped walk over the captured prefix, then assessed.

    Imported from `test_walk` rather than re-derived, because the thing under test is the composition and the
    replay of Cloudflare Nimbus2027's entries is already written there. The first pass leaves a gap, so the
    state is `SINGLE_PATH` and absence is refused; the resume closes the gap, the root matches, and the same
    single path can suddenly say something about absence. Nothing about the log changed between the two
    calls - only what we have read of it - which is the whole content of I5.
    """
    from test_walk import ENTRIES, ReplayFetcher, accepted_head, leaves_of

    head, log_id = accepted_head(tmp_path, leaves_of(96))
    gapped = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES, answer=32, fail_at=(32,)),
        store=EntryStore(),
        head=head,
    ).run()
    first = assess(
        log_id,
        ORIGIN,
        (PathOutcome("p-local", TrustClass.LOCAL, head=head, walk=gapped),),
        now=NOW,
    )
    assert first.state is State.SINGLE_PATH
    assert not first.publishable
    assert not first.supports_absence, "one class and a gap: neither of I5's routes is satisfied"
    assert "not claimable" in first.absence_qualification()

    whole = LogWalk(
        origin=ORIGIN,
        log_id=log_id,
        fetcher=ReplayFetcher(ENTRIES, answer=32),
        store=EntryStore(),
        head=head,
    ).run(start=0)
    second = assess(
        log_id,
        ORIGIN,
        (PathOutcome("p-local", TrustClass.LOCAL, head=head, walk=whole),),
        now=NOW,
    )
    assert second.state is State.SINGLE_PATH
    assert second.supports_absence
    assert "96/" in second.absence_qualification()
