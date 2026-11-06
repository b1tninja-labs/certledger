"""certledger: independent CT acquisition, with the ambient trust removed.

Phase 0 removed adversary A2, the attacker who needs this process's environment and nothing else:

- `anchors` - the only certificates this process will trust, each with a date and a reason.
- `context` - a TLS context that cannot contain anything else, and never reads the system store.
- `transport` - dial the address we resolved, then prove we did.
- `path` - a configured path that emits a receipt for every fetch, including the failures.
- `der` - verification over stored octets (I3).

Phase 1 added `keys` (pin registry, origin-keyed) and `heads` (monotonic tree heads, consistency, inclusion
against an accepted head). Phase 2 added the parts that consume entries rather than heads: `entries` (the
dedupe store, where an entry and a certificate are different counts by design) and `cag` (the CA-layer graph
and its reconciliation arithmetic). `ROADMAP.md` names the test that closes each obligation; nothing here
claims a row that has no passing test behind it.
"""

from __future__ import annotations

from .anchors import Anchor, AnchorSet, pem_to_der
from .cag import CaGraph, CaNode, Reconciliation
from .context import build_client_context
from .der import StoredDocument, capture, verify_over_stored
from .entries import EntryConflict, EntryRecord, EntryStats, EntryStore
from .errors import (
    AmbientTrust,
    AnchorSetProblem,
    CertLedgerError,
    PeerAddressMismatch,
    Unreachable,
)
from .heads import (
    HeadRecord,
    HeadStore,
    MissingConsistencyProof,
    TreeShrank,
    UnacceptedHead,
    UnknownHead,
)
from .keys import KeyRing, LogPin, UnknownLogKey, verify_sth
from .path import Exchange, FetchFailure, FetchPath, TrustClass, Vantage
from .receipt import Receipt
from .states import (
    Freeze,
    HumanDecision,
    LogObservation,
    PathOutcome,
    PublicationRefused,
    State,
    assess,
)
from .transport import DirectTransport, Resolver, SystemResolver, Transport
from .walk import Gap, GapState, LogWalk, WalkBudget, WalkReport

__version__ = "0.0.1"

__all__ = [
    "AmbientTrust",
    "Anchor",
    "AnchorSet",
    "AnchorSetProblem",
    "CaGraph",
    "CaNode",
    "CertLedgerError",
    "DirectTransport",
    "EntryConflict",
    "EntryRecord",
    "EntryStats",
    "EntryStore",
    "Exchange",
    "FetchFailure",
    "FetchPath",
    "Freeze",
    "Gap",
    "GapState",
    "HeadRecord",
    "HeadStore",
    "HumanDecision",
    "KeyRing",
    "LogObservation",
    "LogPin",
    "LogWalk",
    "MissingConsistencyProof",
    "PathOutcome",
    "PeerAddressMismatch",
    "PublicationRefused",
    "Receipt",
    "Reconciliation",
    "Resolver",
    "State",
    "StoredDocument",
    "SystemResolver",
    "Transport",
    "TreeShrank",
    "TrustClass",
    "UnacceptedHead",
    "UnknownHead",
    "UnknownLogKey",
    "Unreachable",
    "Vantage",
    "WalkBudget",
    "WalkReport",
    "__version__",
    "assess",
    "build_client_context",
    "capture",
    "pem_to_der",
    "verify_over_stored",
    "verify_sth",
]
