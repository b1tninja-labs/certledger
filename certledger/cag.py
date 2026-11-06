"""The CA layer: which keys issued what, and whether the graph accounts for the whole tree.

`cl.cag-graph`. PLAN.md's Tier A is every entry with `cA=TRUE`, held in full, because it answers the
questions leaf-level data cannot - what did this key issue, which keys share an SPKI across two roots, whose
name constraints are violated - and because during the October 2026 incident the query that mattered ("find
certificates by this intermediate's common name") was the one crt.sh could not answer.

Three properties this module is built to keep.

**Edges are keyed by keys, not names.** An issuer is identified by SHA-256 over the issuer's SPKI, not by its
distinguished name: names are reused across unrelated CAs, and a graph built on names merges two businesses
into one node. This is also why PLAN partitions the leaf layer by issuer SPKI.

**Precert entries are attributed to `issuer_key_hash`, never to `chain[0]`.** A precertificate signed by a
Precertificate Signing Certificate has the PSC first in its chain, while the log's own `issuer_key_hash`
names the CA that will issue the final certificate. Measured across 494 production precerts in five logs, 321
match `chain[0]` and 173 match `chain[1]` - so a graph that took `chain[0]` would invent a third of its
issuers out of CT-only signing certificates. `issuer_authenticated` records which a value came from: the
leaf's hash sits inside the hashed transcript, and a chain read out of `extra_data` does not (RFC 6962
section 4.6 leaves that unsigned).

**Reconciliation is arithmetic the reader can see.** `reconcile(tree_size=N)` states the entry count it
believed, the edges drawn, and the entries that could not be attributed - an unparseable certificate or an
opaque entry type - because a graph that quietly drops entries reports a smaller CA layer, and "this key
issued nothing" is exactly the claim a monitor must not make on absent data (I8).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .entries import EntryRecord, EntryStore

__all__ = ["CaGraph", "CaNode", "Reconciliation"]


@dataclass(frozen=True, slots=True)
class CaNode:
    """One issuing key, and what this corpus shows it doing."""

    spki_sha256: bytes
    issued: int
    children: frozenset[bytes]
    ca_children: int
    authenticated_issuance: int

    def summary(self) -> str:
        return (
            f"{self.spki_sha256.hex()[:16]} issued {self.issued} "
            f"({len(self.children)} distinct subjects, {self.ca_children} of them CAs, "
            f"{self.authenticated_issuance} attributed by the leaf)"
        )


@dataclass(frozen=True, slots=True)
class Reconciliation:
    """The arithmetic tying the graph to a tree size, including what it could not place."""

    tree_size: int
    entries: int
    edges: int
    unattributed: int
    identities: int
    ca_entries: int
    issuers: int

    @property
    def complete(self) -> bool:
        """Every entry of the believed tree is present, and every present entry is placed or reported."""
        return self.entries == self.tree_size and self.edges + self.unattributed == self.entries

    def summary(self) -> str:
        return (
            f"tree size {self.tree_size}: {self.entries} entries stored, {self.edges} edges drawn from "
            f"{self.issuers} issuing keys, {self.unattributed} unattributed, {self.ca_entries} entries are "
            f"CA certificates, {self.identities} distinct certificates"
            + ("" if self.complete else " -- DOES NOT RECONCILE")
        )


class CaGraph:
    """Issuer-to-subject edges over an `EntryStore`, rebuildable from the entries at any time."""

    def __init__(self, entries: Iterable[EntryRecord]) -> None:
        self._entries = tuple(entries)
        self._by_issuer: dict[bytes, list[EntryRecord]] = {}
        self._unattributed: list[EntryRecord] = []
        for record in self._entries:
            if record.issuer is None or record.subject_spki_sha256 is None:
                self._unattributed.append(record)
                continue
            self._by_issuer.setdefault(record.issuer, []).append(record)

    @classmethod
    def build(cls, store: EntryStore) -> CaGraph:
        return cls(store.entries())

    def node(self, spki_sha256: bytes) -> CaNode | None:
        issued = self._by_issuer.get(spki_sha256)
        if not issued:
            return None
        return CaNode(
            spki_sha256=spki_sha256,
            issued=len(issued),
            children=frozenset(r.subject_spki_sha256 or b"" for r in issued),
            ca_children=sum(1 for r in issued if r.ca is True),
            authenticated_issuance=sum(1 for r in issued if r.issuer_authenticated),
        )

    def issuers(self) -> tuple[CaNode, ...]:
        nodes = [node for node in (self.node(key) for key in self._by_issuer) if node is not None]
        return tuple(sorted(nodes, key=lambda node: (-node.issued, node.spki_sha256)))

    def issued_by(self, spki_sha256: bytes) -> tuple[EntryRecord, ...]:
        """Everything these keys issued - the incident-shaped question that forced the SPKI partition."""
        return tuple(self._by_issuer.get(spki_sha256, ()))

    def ca_layer(self) -> tuple[EntryRecord, ...]:
        """Every entry whose certificate claims `cA=TRUE`: PLAN's Tier A, held in full."""
        return tuple(record for record in self._entries if record.ca is True)

    def unattributed(self) -> tuple[EntryRecord, ...]:
        """Entries with no known issuer or no readable certificate, surfaced rather than skipped."""
        return tuple(self._unattributed)

    def reconcile(self, tree_size: int) -> Reconciliation:
        """Compare the graph against a tree size, and count what could not be placed.

        `tree_size` is expected to be a size a signed head vouches for - the corpus fixture proves its
        prefix root consistent with the log's own signature - so a mismatch here is a statement about the log
        or about the walk, not about parsing.
        """
        return Reconciliation(
            tree_size=tree_size,
            entries=len(self._entries),
            edges=sum(len(rows) for rows in self._by_issuer.values()),
            unattributed=len(self._unattributed),
            identities=len({record.identity for record in self._entries}),
            ca_entries=len(self.ca_layer()),
            issuers=len(self._by_issuer),
        )
