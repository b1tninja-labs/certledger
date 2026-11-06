"""Tree heads: monotonic per log, and never believed without a proof.

Phase 1's load-bearing module (`cl.sth-verify`, `cl.monotonic`, `cl.consistency`, `cl.inclusion`).
PLAN.md's acquisition loop is a few lines and every one of them is here:

  2. Verify the signature against the pinned key. Never against a key discovered on this path.
  3. Compare with the stored head. Equal means stale once beyond budget. Greater requires a
     consistency proof, which is verified. **Less means stop and page**, never clamp.

Three decisions worth stating, because each is a place where a plausible implementation is wrong.

**A smaller head raises; it is not corrected.** A log serving an older tree after a newer one has
either forked or is replaying history. Retrying, clamping, or "taking the max" all convert an
incident into silence. Trust model I4: a decrease is an incident, not a data error.

**Same size, different root, is the louder case.** Two heads with one size and two roots is
equivocation - the exact attack CT exists to make detectable - and a store that keyed by size and
overwrote would destroy the evidence of it.

**A first head is a baseline, not a verified history.** There is nothing to be consistent with yet,
so the record carries `bootstrap=True` and any later absence claim must say so. Pretending the first
head was proven as good as the second would credit the store with a property it does not have.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from ctspy.merkle import verify_consistency as ctspy_verify_consistency
from ctspy.merkle import verify_inclusion as ctspy_verify_inclusion
from ctspy.sth import SignedTreeHeadV1, SignedTreeHeadV2

from .errors import CertLedgerError
from .keys import KeyRing, LogPin, verify_sth
from .receipt import Receipt

__all__ = [
    "BadConsistencyProof",
    "HeadDivergence",
    "HeadRecord",
    "HeadStore",
    "MissingConsistencyProof",
    "TreeShrank",
    "UnacceptedHead",
    "UnknownHead",
]


class TreeShrank(CertLedgerError):
    """A head smaller than the last accepted one. Stop and page (I4); never clamp."""


class HeadDivergence(CertLedgerError):
    """Same tree size, different root hash: the log is showing two histories."""


class MissingConsistencyProof(CertLedgerError):
    """Growth was offered with no proof, so it cannot be believed yet."""


class BadConsistencyProof(CertLedgerError):
    """A proof was offered and does not verify. This is a finding, not something to retry."""


class UnknownHead(CertLedgerError):
    """Nothing is stored for this log. Absence of data, not a zero-sized tree (I8)."""


class UnacceptedHead(CertLedgerError):
    """An inclusion proof referenced a head this store never accepted."""


@dataclass(frozen=True, slots=True)
class HeadRecord:
    """An accepted tree head, and the receipt for the fetch that produced it (I6).

    `receipt` has no default on purpose: an object that cannot be constructed without provenance
    cannot be published without it either.
    """

    log_id: bytes
    tree_size: int
    root_hash: bytes
    timestamp: int
    accepted_utc: str
    receipt: Receipt
    bootstrap: bool

    def summary(self) -> str:
        return (
            f"{self.log_id.hex()[:16]} size={self.tree_size} root={self.root_hash.hex()[:16]} "
            f"{'(bootstrap) ' if self.bootstrap else ''}via {self.receipt.path_id}"
        )


class HeadStore:
    """Per-log monotonic head records, append-only."""

    def __init__(self) -> None:
        self._current: dict[bytes, HeadRecord] = {}
        self._history: list[HeadRecord] = []

    def current(self, log_id: bytes) -> HeadRecord:
        try:
            return self._current[log_id]
        except KeyError as exc:
            raise UnknownHead(f"no head accepted yet for log {log_id.hex()}") from exc

    def history(self, log_id: bytes) -> tuple[HeadRecord, ...]:
        return tuple(record for record in self._history if record.log_id == log_id)

    def accept(
        self,
        sth: SignedTreeHeadV1 | SignedTreeHeadV2,
        ring: KeyRing,
        *,
        origin: str,
        receipt: Receipt,
        consistency: tuple[bytes, ...] | None = None,
    ) -> HeadRecord:
        """Verify a head against the pinned key and the stored history, then record it."""
        pin = verify_sth(sth, ring, origin=origin)
        _, tree_size, root_hash = _fields(sth)
        previous = self._current.get(pin.log_id)

        if previous is not None:
            if tree_size < previous.tree_size:
                raise TreeShrank(
                    f"{pin.description}: tree size went backwards, {previous.tree_size} -> "
                    f"{tree_size}. Not corrected, not retried; this is an incident (I4)."
                )
            if tree_size == previous.tree_size:
                if root_hash != previous.root_hash:
                    raise HeadDivergence(
                        f"{pin.description}: size {tree_size} has two roots, "
                        f"{previous.root_hash.hex()} and {root_hash.hex()}; the log is presenting "
                        "two histories"
                    )
                return self._record(pin, sth, receipt, bootstrap=False)
            if consistency is None:
                raise MissingConsistencyProof(
                    f"{pin.description}: growth {previous.tree_size} -> {tree_size} needs a "
                    "consistency proof before it can be recorded"
                )
            if not ctspy_verify_consistency(
                previous.tree_size, tree_size, consistency, previous.root_hash, root_hash
            ):
                raise BadConsistencyProof(
                    f"{pin.description}: the consistency proof for {previous.tree_size} -> "
                    f"{tree_size} does not verify"
                )

        return self._record(pin, sth, receipt, bootstrap=previous is None)

    def _record(
        self,
        pin: LogPin,
        sth: SignedTreeHeadV1 | SignedTreeHeadV2,
        receipt: Receipt,
        *,
        bootstrap: bool,
    ) -> HeadRecord:
        timestamp, tree_size, root_hash = _fields(sth)
        record = HeadRecord(
            log_id=pin.log_id,
            tree_size=tree_size,
            root_hash=root_hash,
            timestamp=timestamp,
            accepted_utc=datetime.now(UTC).isoformat(),
            receipt=receipt,
            bootstrap=bootstrap,
        )
        self._current[pin.log_id] = record
        self._history.append(record)
        return record

    def verify_inclusion(
        self,
        log_id: bytes,
        leaf_hash: bytes,
        leaf_index: int,
        path: tuple[bytes, ...],
        *,
        tree_size: int | None = None,
    ) -> bool:
        """Prove a leaf against a head this store accepted, never against one it merely received.

        The binding is the whole point. An inclusion proof checked against a root the log simply
        asserted is a proof with no anchor; "anchored to a tree the pinned log signed, and that this
        store accepted monotonically" is the only version that means anything.
        """
        head = self.current(log_id)
        size = head.tree_size if tree_size is None else tree_size
        if size > head.tree_size:
            raise UnknownHead(f"proof claims tree size {size}, beyond the head {head.tree_size}")
        target = head.root_hash if size == head.tree_size else self._root_at(log_id, size)
        return ctspy_verify_inclusion(leaf_hash, leaf_index, size, path, target)

    def _root_at(self, log_id: bytes, tree_size: int) -> bytes:
        for record in reversed(self._history):
            if record.log_id == log_id and record.tree_size == tree_size:
                return record.root_hash
        raise UnacceptedHead(
            f"no accepted head for log {log_id.hex()} at tree size {tree_size}; a proof against an "
            "unaccepted root proves nothing"
        )


def _fields(sth: SignedTreeHeadV1 | SignedTreeHeadV2) -> tuple[int, int, bytes]:
    """(timestamp, tree_size, root_hash) for either version.

    v2 keeps the timestamp inside `tree_head` rather than beside it, which is exactly the kind of
    difference a `getattr` would paper over and a caller would then read as zero.
    """
    if isinstance(sth, SignedTreeHeadV2):
        return sth.tree_head.timestamp, sth.tree_head.tree_size, sth.tree_head.root_hash
    return sth.timestamp, sth.tree_size, sth.root_hash
