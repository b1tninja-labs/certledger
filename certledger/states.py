"""What an observation may be published as.

`cl.states`, trust model section 8. Six states, one table, and a rule above the table: **"Data carries a
state, and the state is shown to users rather than hidden behind a successful-looking page."** Everything in
this module exists to keep that true when the code gets complicated, because the failure mode is not a crash.
It is a dashboard that says "OK" because someone wrote `state = VERIFIED` in the reporting layer.

So `assess` is the only way in. It reads what the paths actually produced - accepted heads, walk reports,
receipts, refusals - and returns a state. There is no constructor argument that accepts a state, and the
properties that gate publication are derived, not stored.

## The precedence, and why it is ordered

```
DIVERGENT > UNREACHABLE > UNAUTHENTICATED > STALE > VERIFIED | SINGLE_PATH
```

`DIVERGENT` wins over everything because it is the only state that says *we have evidence two things are
true at once*, and the table's response is to freeze, alert, and keep fetching. It beats `UNREACHABLE`
deliberately: one path failing while another shows an equivocating head is still a finding, and reporting
"could not reach it" would hide it.

`UNREACHABLE` beats `UNAUTHENTICATED` for a mundane reason - a failed TLS handshake means the endpoint could
not be validated either, so if unauthenticated ranked higher, every connection timeout in the fleet would be
reported as a possible interceptor and nobody would believe the report when a real one appeared.

`STALE` beats `VERIFIED` even though a stale head is usually corroborated. The table says "never present as
current", and the only way to guarantee that is to make staleness destroy the publishable state rather than
sit beside it as a note.

## The two rules that cost the most to encode

**Never silently downgrade.** A path that could not authenticate its endpoint does not get dropped from the
majority vote on the way to a nicer state. It caps the result - content seen only on such a path can never
reach `VERIFIED` - and it raises an alert, because an unauthenticated path that *disagrees* is what adversary
A2 looks like from inside the process, and the honest statement is "we cannot tell whether the log
equivocated or someone intercepted us", not a silent choice between the two.

**A freeze survives good news.** A key or log-list change, or a divergence, freezes publication until a
`HumanDecision` with a name and a date clears it. Nothing in this module can construct one of those, and
clearing lifts the freeze without upgrading the state: the finding stays on the record, and only a later pass
that genuinely corroborates produces `VERIFIED`. Section 8's reason is that A5's most realistic attack looks
entirely routine, so re-trust is reserved for a named human and recorded as data.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, replace
from enum import StrEnum

from .errors import CertLedgerError
from .heads import HeadRecord
from .path import TrustClass
from .receipt import Receipt
from .walk import WalkReport

__all__ = [
    "Freeze",
    "HumanDecision",
    "LogObservation",
    "PathOutcome",
    "PublicationRefused",
    "State",
    "assess",
]

DEFAULT_STALENESS = datetime.timedelta(hours=6)


class PublicationRefused(CertLedgerError):
    """Something tried to publish an observation that does not support it."""


class State(StrEnum):
    """The six states of trust model section 8. The names are the table's, deliberately."""

    VERIFIED = "VERIFIED"
    SINGLE_PATH = "SINGLE_PATH"
    DIVERGENT = "DIVERGENT"
    STALE = "STALE"
    UNREACHABLE = "UNREACHABLE"
    UNAUTHENTICATED = "UNAUTHENTICATED"

    @property
    def behaviour(self) -> str:
        """The table's third column: what is owed to the reader of this state."""
        return {
            State.VERIFIED: "publishable",
            State.SINGLE_PATH: "shown; never used for an absence claim",
            State.DIVERGENT: "publication frozen for this log, alert, keep fetching",
            State.STALE: "stated plainly; never presented as current",
            State.UNREACHABLE: "records absence of fetch, never absence of entry",
            State.UNAUTHENTICATED: "internal only; may not support any public claim",
        }[self]

    @property
    def public(self) -> bool:
        """Whether anything in this state may be said in public. I7 and the table agree here."""
        return self is not State.UNAUTHENTICATED


@dataclass(frozen=True, slots=True)
class HumanDecision:
    """The dated note section 8 requires before publication resumes. This module cannot invent one.

    `by` and `note` are refused when blank because the point of the record is that a later reader can ask
    someone why the freeze was lifted. "looked fine" with no name is the shape of the decision that section
    8 exists to prevent, and validating it here is cheaper than discovering it during an incident review.
    """

    by: str
    note: str
    utc: datetime.datetime

    def __post_init__(self) -> None:
        if not self.by.strip():
            raise ValueError("a decision to resume publication must name the human who made it")
        if len(self.note.strip()) < 12:
            raise ValueError(
                f"the note {self.note!r} is too short to be an audit record; say what was checked"
            )
        if self.utc.tzinfo is None:
            raise ValueError(
                "a decision timestamp without a zone cannot be ordered against a fetch"
            )

    @property
    def dated(self) -> str:
        return f"{self.utc.date().isoformat()} by {self.by.strip()}"


@dataclass(frozen=True, slots=True)
class Freeze:
    """Publication is stopped for this log until a named human says otherwise."""

    reason: str
    since_utc: str
    decision: HumanDecision | None = None

    @property
    def active(self) -> bool:
        return self.decision is None

    def cleared_by(self, decision: HumanDecision) -> Freeze:
        """Lift the freeze. Note that this does not make anything verified.

        Clearing answers "may we publish again", not "was the finding wrong". A decision that also rewrote
        the state would let one line of text undo an equivocation finding, which is precisely the automated
        re-trust section 8 forbids.
        """
        return replace(self, decision=decision)


@dataclass(frozen=True, slots=True)
class PathOutcome:
    """What one path did in one pass over one log.

    The three ways a path can fail are kept apart because they lead to different states, and collapsing them
    is how an incident becomes a connectivity problem. `failure` means nothing useful arrived - the socket,
    TLS, or the HTTP layer. `incident` means something arrived that could be attributed to a named path and
    contradicts the record: a head this store refused (`TreeShrank`, `HeadDivergence`,
    `BadConsistencyProof`). `authenticated=False` means we cannot prove whose endpoint it was, which is not a
    failure at all and must not be counted as agreement.
    """

    path_id: str
    trust_class: TrustClass
    head: HeadRecord | None = None
    walk: WalkReport | None = None
    receipt: Receipt | None = None
    authenticated: bool = True
    failure: str | None = None
    incident: str | None = None

    @property
    def reachable(self) -> bool:
        """Whether the path answered at all, usable or not."""
        return self.failure is None

    @property
    def produced(self) -> bool:
        """Whether this path contributed evidence that may be believed."""
        return self.authenticated and self.head is not None and self.incident is None

    @property
    def complete(self) -> bool:
        """Whether this path's walk proved the whole tree by hash."""
        return self.walk is not None and self.walk.complete

    @property
    def conflicted(self) -> bool:
        """Whether this path's own walk watched a position get re-served differently."""
        return self.walk is not None and self.walk.conflicted

    @property
    def gapped(self) -> bool:
        """Whether this path's walk left unread ranges in the completeness record."""
        return self.walk is not None and bool(self.walk.gaps)

    def summary(self) -> str:
        if self.failure is not None:
            return f"{self.path_id} ({self.trust_class.value}): {self.failure}"
        if self.incident is not None:
            return f"{self.path_id} ({self.trust_class.value}): incident - {self.incident}"
        if self.head is None:
            return f"{self.path_id} ({self.trust_class.value}): no head offered"
        seen = f"size={self.head.tree_size} root={self.head.root_hash.hex()[:12]}"
        auth = "" if self.authenticated else ", unauthenticated"
        return f"{self.path_id} ({self.trust_class.value}{auth}): {seen}"


@dataclass(frozen=True, slots=True)
class LogObservation:
    """What one pass over one log concluded, and therefore what it is allowed to say.

    Constructed by `assess` and not by callers. The fields that look like policy - `state`, `freeze` - are
    results of reading evidence, and a reporting layer that could set them directly would eventually set them
    wrongly, which is the failure this whole file is arranged against.
    """

    log_id: bytes
    origin: str
    state: State
    outcomes: tuple[PathOutcome, ...]
    head: HeadRecord | None
    reason: str
    freeze: Freeze | None = None
    stale_after: datetime.timedelta = DEFAULT_STALENESS

    @property
    def believed(self) -> tuple[PathOutcome, ...]:
        """Paths whose evidence may be believed: authenticated, answered, not refused as an incident."""
        return tuple(outcome for outcome in self.outcomes if outcome.produced)

    @property
    def classes(self) -> tuple[str, ...]:
        """The trust classes that agreed. Two paths in one class are one observation, not two.

        I5 and I7 count classes rather than paths for the reason that matters operationally: a second fetch
        through the same laptop, resolver and uplink cannot contradict the first. Counting paths here would
        let a configuration file manufacture corroboration.
        """
        return tuple(sorted({outcome.trust_class.value for outcome in self.believed}))

    @property
    def corroborated(self) -> bool:
        return len(self.classes) >= 2

    @property
    def frozen(self) -> bool:
        return self.freeze is not None and self.freeze.active

    @property
    def publishable(self) -> bool:
        """`VERIFIED` and un-frozen, and nothing else.

        `SINGLE_PATH` is shown and not published as an absence claim; `STALE` is stated and never presented
        as current; `UNAUTHENTICATED` may not support a public claim at all. A freeze holds publication even
        over a corroborated head, because the thing under question is the setup rather than this response.
        """
        return self.state is State.VERIFIED and not self.frozen

    @property
    def alert(self) -> bool:
        """Whether a human should hear about this pass now rather than at the next review."""
        unauthenticated = any(
            not outcome.authenticated and outcome.reachable for outcome in self.outcomes
        )
        return self.state is State.DIVERGENT or unauthenticated

    @property
    def keep_fetching(self) -> bool:
        """The table's instruction for `DIVERGENT`: freeze publication, alert, keep fetching.

        A frozen log that stopped being fetched would stop producing the evidence that resolves the freeze,
        and the disagreement itself is data - the finding no single log can make about itself.
        """
        return self.state in {State.DIVERGENT, State.UNREACHABLE} or self.frozen

    @property
    def supports_absence(self) -> bool:
        """Whether "that certificate is not in this log" is supportable from this pass (I5).

        Two routes and only two: two or more path classes, or a walk that proved the whole tree by hash.
        Everything else answers False, including `STALE` - absence from a tree we know has not moved
        recently is a claim about the past - and `DIVERGENT`, where we cannot say which tree is being looked
        at. A freeze also defeats it, since what is in question is whether this log's word can be relied on.
        """
        if self.frozen or self.state not in {State.VERIFIED, State.SINGLE_PATH}:
            return False
        return self.corroborated or any(outcome.complete for outcome in self.believed)

    @property
    def public(self) -> bool:
        """Whether anything from this pass may be said in public at all.

        `UNAUTHENTICATED` is the one state that forbids that outright, and it is the property a publishing
        path should check before `publishable`: an observation about a log we could not reach is discussable
        - "we could not reach it" is a true sentence about our day - whereas an observation from an endpoint
        we cannot identify is not discussable at all, because we cannot say who it was about.
        """
        return self.state.public

    def require_publishable(self) -> None:
        """The gate, as an exception rather than a boolean somebody has to remember to read."""
        if not self.publishable:
            detail = " and publication is frozen" if self.frozen else ""
            raise PublicationRefused(
                f"{self.origin}: state {self.state.value}{detail} - {self.state.behaviour}"
            )

    def absence_qualification(self) -> str:
        """What an absence answer must say about itself, per PLAN.md's acquisition loop.

        A single path that completed its walk is entitled to its sentence, and the sentence has to name the
        head it is complete up to. "Not found" without that is how a private opinion becomes a public
        accusation.
        """
        if not self.supports_absence:
            return f"absence is not claimable from this observation ({self.state.value})"
        if self.corroborated:
            return (
                f"not present in copies from {len(self.classes)} path classes: "
                f"{', '.join(self.classes)}"
            )
        if self.head is None:
            return "not in my copy, which is one path, complete up to an unknown head"
        return (
            "not in my copy, which is one path, complete up to head "
            f"{self.head.tree_size}/{self.head.root_hash.hex()[:16]}"
        )

    def explanation(self) -> str:
        lines = [f"{self.origin}: {self.state.value} - {self.reason} [{self.state.behaviour}]"]
        if self.freeze is not None:
            if self.freeze.decision is None:
                status = "ACTIVE"
            else:
                status = f"cleared {self.freeze.decision.dated}"
            lines.append(f"  freeze ({status}) since {self.freeze.since_utc}: {self.freeze.reason}")
        lines.extend(f"  {outcome.summary()}" for outcome in self.outcomes)
        return "\n".join(lines)

    def cleared(self, decision: HumanDecision) -> LogObservation:
        """Attach a human decision to this observation's freeze. Never changes the state."""
        if self.freeze is None:
            raise ValueError(f"{self.origin}: nothing is frozen, so there is nothing to clear")
        return replace(self, freeze=self.freeze.cleared_by(decision))


def assess(
    log_id: bytes,
    origin: str,
    outcomes: tuple[PathOutcome, ...],
    *,
    previous: HeadRecord | None = None,
    freeze: Freeze | None = None,
    now: datetime.datetime | None = None,
    staleness: datetime.timedelta = DEFAULT_STALENESS,
) -> LogObservation:
    """Decide the state of one pass, from evidence only. Precedence is in the module docstring.

    `freeze` carries an existing freeze forward - the key-change case has no evidence of its own to weigh,
    and a pass that happens to corroborate must not silently lift it.
    """
    if not outcomes:
        raise ValueError(
            f"{origin}: an empty pass is not an observation. assess needs what each path did, "
            "including the ones that failed - a pass with no failures recorded is not a healthy log, "
            "it is a report that left them out"
        )
    moment = now if now is not None else datetime.datetime.now(datetime.UTC)
    believed = tuple(outcome for outcome in outcomes if outcome.produced)
    head = _newest(believed)

    equivocations = _equivocations(believed)
    incidents = tuple(outcome.incident for outcome in outcomes if outcome.incident is not None)
    conflicts = tuple(outcome.path_id for outcome in believed if outcome.conflicted)
    if equivocations or incidents or conflicts:
        reason = _divergence_reason(equivocations, incidents, conflicts)
        return LogObservation(
            log_id=log_id,
            origin=origin,
            state=State.DIVERGENT,
            outcomes=outcomes,
            head=head,
            reason=reason,
            freeze=freeze if freeze is not None else Freeze(reason, moment.isoformat()),
            stale_after=staleness,
        )

    if not any(outcome.reachable for outcome in outcomes):
        return _single(
            log_id,
            origin,
            State.UNREACHABLE,
            outcomes,
            reason=f"all {len(outcomes)} path(s) failed to answer",
            freeze=freeze,
            staleness=staleness,
        )

    if not believed:
        answered = tuple(outcome for outcome in outcomes if outcome.reachable)
        blind = tuple(outcome.path_id for outcome in answered if not outcome.authenticated)
        if blind and len(blind) == len(answered):
            return _single(
                log_id,
                origin,
                State.UNAUTHENTICATED,
                outcomes,
                reason=(
                    f"every path that answered failed to validate names or endpoint ({', '.join(blind)}); "
                    "nothing here may support a public claim"
                ),
                freeze=freeze,
                staleness=staleness,
            )
        return _single(
            log_id,
            origin,
            State.UNREACHABLE,
            outcomes,
            reason="paths answered without offering a head this store could accept",
            freeze=freeze,
            staleness=staleness,
        )

    sizes = {outcome.head.tree_size for outcome in believed if outcome.head is not None}
    if previous is not None and sizes == {previous.tree_size}:
        aged = moment - datetime.datetime.fromisoformat(previous.accepted_utc)
        if aged > staleness:
            return _single(
                log_id,
                origin,
                State.STALE,
                outcomes,
                reason=(
                    f"no growth in {aged} (budget {staleness}); tree size is still "
                    f"{previous.tree_size} - say that plainly rather than presenting it as current"
                ),
                head=head,
                freeze=freeze,
                staleness=staleness,
            )

    classes = tuple(sorted({outcome.trust_class.value for outcome in believed}))
    if len(classes) >= 2:
        return _single(
            log_id,
            origin,
            State.VERIFIED,
            outcomes,
            reason=(
                f"signature valid, monotonic, and agreed by {len(classes)} path classes "
                f"({', '.join(classes)})"
            ),
            head=head,
            freeze=freeze,
            staleness=staleness,
        )
    lonely = classes[0] if classes else "no class"
    return _single(
        log_id,
        origin,
        State.SINGLE_PATH,
        outcomes,
        reason=(
            f"verified content from one path class ({lonely}); never a basis for an absence claim, "
            "however many paths within that class agreed"
        ),
        head=head,
        freeze=freeze,
        staleness=staleness,
    )


def _single(
    log_id: bytes,
    origin: str,
    state: State,
    outcomes: tuple[PathOutcome, ...],
    *,
    reason: str,
    head: HeadRecord | None = None,
    freeze: Freeze | None,
    staleness: datetime.timedelta,
) -> LogObservation:
    return LogObservation(
        log_id=log_id,
        origin=origin,
        state=state,
        outcomes=outcomes,
        head=head,
        reason=reason,
        freeze=freeze,
        stale_after=staleness,
    )


def _newest(believed: tuple[PathOutcome, ...]) -> HeadRecord | None:
    """The largest tree any believed path showed. The outcomes still hold every head that was seen.

    Largest rather than latest by timestamp: a log's clock can lag its tree, and a head is identified by the
    tree it commits to, not by when the log said it.
    """
    candidates = [outcome.head for outcome in believed if outcome.head is not None]
    if not candidates:
        return None
    return max(candidates, key=lambda record: (record.tree_size, record.timestamp))


def _equivocations(believed: tuple[PathOutcome, ...]) -> tuple[str, ...]:
    """Sizes at which believed paths showed more than one root.

    Different sizes are not disagreement - one path may have caught growth the other missed, and the
    monotonic store has already decided which head stands. The case that cannot be explained away is one tree
    size carrying two roots, which is equivocation by definition and the reason CT was built.
    """
    by_size: dict[int, set[str]] = {}
    for outcome in believed:
        if outcome.head is None:
            continue
        by_size.setdefault(outcome.head.tree_size, set()).add(outcome.head.root_hash.hex())
    found: list[str] = []
    for size, roots in sorted(by_size.items()):
        if len(roots) > 1:
            ordered = sorted(roots)
            found.append(f"tree size {size} was shown as {ordered[0][:16]} and {ordered[1][:16]}")
    return tuple(found)


def _divergence_reason(
    equivocations: tuple[str, ...], incidents: tuple[str | None, ...], conflicts: tuple[str, ...]
) -> str:
    parts = list(equivocations)
    parts.extend(f"path reported {incident}" for incident in incidents if incident)
    parts.extend(f"walk on {path_id} watched a position change under it" for path_id in conflicts)
    return "; ".join(parts) if parts else "paths disagree"
