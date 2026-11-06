"""Walking a log under a budget, and what a gap is allowed to mean.

`cl.walk-budget`. A walk looks like a loop over `get-entries`, and the loop is the easy part. What this module
owns is the difference between two sentences that sound alike: **"we could not fetch that range"** and
**"there is nothing in that range."** Trust model I5 forbids the second sentence unless a full-tree walk or
two path-class replicas support it, and the state table says the same thing from the other side -
`UNREACHABLE` means "record absence of *fetch*, never absence of *entry*." A walk that silently conflates them
is the shape of a monitor that reports a missing certificate on a Tuesday because a socket timed out on a
Monday.

Three measured facts about deployed logs are built into the loop, all from this workspace's own surveys
rather than from the specification:

- **A short page is a cap, not the end of the tree.** Google answers 32 entries however many are asked for
  (RFC 6962 section 4.6 permits partial responses), and the log still had roughly three billion entries
  left. So the walk continues from the first index it did not receive, learns the observed cap, and asks for
  exactly that thereafter rather than re-requesting a window it knows will be truncated.
- **The signed head, not the response, decides how many entries exist.** The loop terminates at
  `head.tree_size`. A log answering with nothing at index 40 while its signed head promises three billion
  entries has not finished; that range is recorded `EMPTY_WITHIN_TREE`, which is an anomaly about the log
  rather than a completed walk.
- **`extra_data` framing differs by entry type** (`ctspy.entry.parse_extra_data`), so the walk hands the leaf
  octets and the extra octets to the parser together and lets an entry that cannot be read become opaque
  rather than dropping it.

Completeness is checked by hash, not by counting. A contiguous run of leaves from index 0 whose Merkle Tree
Hash equals the root the log signed cannot be missing an entry - the root commits to every leaf - so
`WalkReport.complete` requires that equality, and only then does `may_claim_absent` answer True. That is also
why a single path can support an absence claim here while it cannot support one about content: the arithmetic
does the work, not the number of observers. Publication still needs I7 corroboration, and a walk that stops
for budget says so in its own record instead of leaving the reader to notice.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from .entries import EntryConflict, EntryRecord, EntryStore
from .heads import HeadRecord
from .path import Exchange, FetchFailure
from .receipt import Receipt

__all__ = ["Gap", "GapState", "LogWalk", "WalkBudget", "WalkReport"]

DEFAULT_PAGE = 256


class GapState(StrEnum):
    """Why a range is missing. Each of these is an absence of fetch; none is an absence of entry."""

    UNREACHABLE = "UNREACHABLE"
    BUDGET = "BUDGET"
    EMPTY_WITHIN_TREE = "EMPTY_WITHIN_TREE"
    CONFLICT = "CONFLICT"


class Fetcher(Protocol):
    """What a walk needs of its transport: fetch a URL, or raise `FetchFailure` carrying a receipt.

    `FetchPath` satisfies this, and so does a replay of stored response bytes. The seam keeps receipts,
    because a walk tested against a fake that invents no provenance is tested against nothing the production
    path has to survive.
    """

    def fetch(self, url: str, *, method: str = "GET", body: bytes | None = None) -> Exchange: ...


@dataclass(frozen=True, slots=True)
class Gap:
    """A range of a tree this walk does not have, and the reason it does not have it."""

    start: int
    end: int
    state: GapState
    reason: str
    receipt: Receipt | None

    @property
    def count(self) -> int:
        return self.end - self.start

    def covers(self, index: int) -> bool:
        return self.start <= index < self.end

    def summary(self) -> str:
        where = "no request was made" if self.receipt is None else self.receipt.path_id
        return f"[{self.start},{self.end}) {self.state.value} via {where}: {self.reason}"


@dataclass(frozen=True, slots=True)
class WalkBudget:
    """How far a walk may go before it stops and records what it did not reach.

    `page` is what the walk *asks* for. One half-year Google log held about 242 million entries when
    measured, which at Google's observed 32-entry answer is roughly 7.6 million requests - so a walk with no
    budget is not a thorough walk, it is a walk that never reports.
    """

    requests: int = 2000
    page: int = DEFAULT_PAGE
    response_bytes: int = 512 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class WalkReport:
    """What one walk achieved: the ranges held, the ranges missing, and whether the root agrees."""

    log_id: bytes
    origin: str
    tree_size: int
    entries: int
    requests: int
    response_bytes: int
    page_cap: int | None
    gaps: tuple[Gap, ...]
    root_hash: bytes | None
    head_root: bytes

    @property
    def conflicted(self) -> bool:
        """Whether this walk watched a position get re-served with different bytes."""
        return any(gap.state is GapState.CONFLICT for gap in self.gaps)

    @property
    def complete(self) -> bool:
        """True only when the held leaves are the whole tree *and* their root is the signed one.

        Counting entries is not this. A log can serve a plausible number of entries for a range while the
        tree they belong to is a different tree; the equality of two hashes is the only thing in this report
        that rules that out.

        A conflict disqualifies the report even when the inventory matches. Two versions of one position is
        the state table's `DIVERGENT` case - freeze publication for that log, keep fetching - and a walk
        that certified completeness while holding that evidence would be reporting a tree it had just seen
        the log disagree about.
        """
        return (
            not self.conflicted
            and self.entries == self.tree_size
            and self.root_hash is not None
            and self.root_hash == self.head_root
        )

    def missing(self) -> int:
        return sum(gap.count for gap in self.gaps)

    def covers(self, index: int) -> bool:
        """Whether the walk read this index. Unknown is not the same as absent."""
        return 0 <= index < self.tree_size and not any(gap.covers(index) for gap in self.gaps)

    def gaps_at(self, index: int) -> tuple[Gap, ...]:
        return tuple(gap for gap in self.gaps if gap.covers(index))

    def may_claim_absent(self, index: int) -> bool:
        """Whether "this log does not contain that certificate" is supportable at an index.

        I5 permits the claim from a full-tree walk, and a full-tree walk earns it from the root hash: leaves
        0..tree_size-1 whose tree hash equals the signed root cannot be missing one. Anything short of
        that - a gap, a budget stop, a root that does not match - answers False, and answering False is the
        correct behaviour rather than the conservative one.
        """
        return self.complete and self.covers(index)

    def summary(self) -> str:
        return (
            f"{self.origin}: {self.entries}/{self.tree_size} entries in {self.requests} requests "
            f"({self.response_bytes} bytes, page cap {self.page_cap}), {len(self.gaps)} gap(s) covering "
            f"{self.missing()}, root {'MATCHES' if self.complete else 'does not match'} the signed head"
        )


class LogWalk:
    """Reads a log's entries from 0 to an accepted head's tree size, within a budget."""

    def __init__(
        self,
        *,
        origin: str,
        log_id: bytes,
        fetcher: Fetcher,
        store: EntryStore,
        head: HeadRecord,
        budget: WalkBudget | None = None,
    ) -> None:
        if head.log_id != log_id:
            raise ValueError(
                f"head is for log {head.log_id.hex()} but the walk names {log_id.hex()}: a walk whose "
                "tree size comes from another log's head would call a short tree complete"
            )
        self.origin = origin.rstrip("/")
        self.log_id = log_id
        self.fetcher = fetcher
        self.store = store
        self.head = head
        self.budget = budget if budget is not None else WalkBudget()
        self._cap: int | None = None

    def run(self, *, start: int = 0) -> WalkReport:
        """Walk forward from `start`, recording a gap for whatever this pass could not read.

        Gaps are never retried inside a pass. A retry loop here would be the walk deciding that its own
        failure was the log's; the resume-with-gap behaviour the state table prescribes is one forward sweep
        that leaves the gap in the record. `start` exists so a later pass can close old gaps deliberately,
        with its own receipts, rather than having this pass pretend the earlier ones did not happen.
        """
        index = start
        requests = 0
        response_bytes = 0
        gaps: list[Gap] = []
        while index < self.head.tree_size:
            if requests >= self.budget.requests:
                gaps.append(
                    Gap(
                        start=index,
                        end=self.head.tree_size,
                        state=GapState.BUDGET,
                        reason=f"request budget of {self.budget.requests} exhausted",
                        receipt=None,
                    )
                )
                break
            want = self._want(index)
            requests += 1
            try:
                exchange = self.fetcher.fetch(self._url(index, want))
            except FetchFailure as failure:
                gaps.append(
                    Gap(index, index + want, GapState.UNREACHABLE, str(failure), failure.receipt)
                )
                index += want
                continue

            response_bytes += len(exchange.body)
            batch, problem = _entries_of(exchange.body)
            if problem is not None:
                gaps.append(
                    Gap(index, index + want, GapState.UNREACHABLE, problem, exchange.receipt)
                )
                index += want
                continue
            if not batch:
                gaps.append(
                    Gap(
                        index,
                        index + want,
                        GapState.EMPTY_WITHIN_TREE,
                        f"get-entries answered with no entries inside tree size {self.head.tree_size}",
                        exchange.receipt,
                    )
                )
                index += want
                continue

            if self._cap is None and len(batch) < want:
                self._cap = len(batch)
            stored, state, reason = self._store_batch(index, batch, exchange.receipt)
            if state is not None:
                if state is GapState.CONFLICT:
                    gaps.append(
                        Gap(index, index + max(stored, len(batch)), state, reason, exchange.receipt)
                    )
                    break
                # One unreadable entry is a position we do not have, not a tree that stopped existing. Skip
                # exactly that position so a malformed entry cannot freeze the whole log.
                end = index + stored + 1
                gaps.append(Gap(index + stored, end, state, reason, exchange.receipt))
                index = end
                continue
            index += len(batch)
            if response_bytes >= self.budget.response_bytes:
                gaps.append(
                    Gap(
                        index,
                        self.head.tree_size,
                        GapState.BUDGET,
                        f"response budget of {self.budget.response_bytes} bytes exhausted",
                        exchange.receipt,
                    )
                )
                break

        return WalkReport(
            log_id=self.log_id,
            origin=self.origin,
            tree_size=self.head.tree_size,
            entries=len(self.store.positions(self.log_id)),
            requests=requests,
            response_bytes=response_bytes,
            page_cap=self._cap,
            gaps=tuple(gaps),
            root_hash=self.store.root_hash(self.log_id),
            head_root=self.head.root_hash,
        )

    def _want(self, index: int) -> int:
        """How many to ask for: the learned cap if there is one, else the page, clipped to the tree."""
        size = self._cap if self._cap is not None else self.budget.page
        return max(1, min(size, self.head.tree_size - index))

    def _url(self, index: int, want: int) -> str:
        return f"{self.origin}/ct/v1/get-entries?start={index}&end={index + want - 1}"

    def _store_batch(
        self, index: int, batch: list[dict[str, Any]], receipt: Receipt
    ) -> tuple[int, GapState | None, str]:
        """Store one page positionally, so an index is a position in the tree and nothing else.

        The receipt is the one for this fetch, attached to every entry it produced (I6). Position is taken
        from the request's `start` plus the offset in the array, because `get-entries` documents entries as
        sequential from `start` and the tree agrees: a walk that trusted a per-entry index field would be
        believing an unsigned label instead of the position it asked for.

        The two ways a page can stop are reported apart, because the walk treats them apart. A field that
        will not decode is a bad response and costs one position; a position that disagrees with what is
        already stored is a changed tree and stops everything.
        """
        for offset, item in enumerate(batch):
            try:
                leaf = base64.b64decode(item["leaf_input"], validate=True)
                extra = base64.b64decode(item["extra_data"], validate=True)
            except (KeyError, TypeError, binascii.Error) as failure:
                return (
                    offset,
                    GapState.UNREACHABLE,
                    f"entry at {index + offset} was undecodable: {type(failure).__name__}: {failure}",
                )
            record = EntryRecord.from_bytes(
                log_id=self.log_id,
                index=index + offset,
                leaf_input=leaf,
                extra_data=extra,
                receipt=receipt,
            )
            try:
                self.store.add(record)
            except EntryConflict as conflict:
                return offset, GapState.CONFLICT, str(conflict)
        return len(batch), None, ""


def _entries_of(body: bytes) -> tuple[list[dict[str, Any]], str | None]:
    """The `entries` array of a response, or the reason the response is unusable.

    A body that is not JSON, or JSON with no `entries` array, is a failed fetch and not an empty tree.
    Collapsing those two is the exact conflation this module exists to prevent, which is why the distinction
    lives in a function with one job rather than inline where `document.get("entries", [])` would be tempting.
    """
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, ValueError) as failure:
        return [], f"response was not JSON: {type(failure).__name__}"
    if not isinstance(document, dict):
        return [], f"response JSON was {_shape(document)}, not an object"
    if "entries" not in document:
        return [], "response JSON had no entries array"
    entries = document["entries"]
    if not isinstance(entries, list):
        return [], f"entries was {_shape(entries)}, not an array"
    return [item for item in entries if isinstance(item, dict)], None


def _shape(value: object) -> str:
    return type(value).__name__
