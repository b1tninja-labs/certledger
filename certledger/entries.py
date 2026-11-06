"""Entries are not certificates, and the store exists to keep both counts honest.

`cl.dedupe`. PLAN.md gives an Entry the identity "SHA-256 of the TBSCertificate" and warns that raw counts
are meaningless without the dedupe, because one certificate is logged in several logs. Measured on production
bytes for this repository's corpus, the gap has more structure than that sentence, and the causes have to be
distinguishable or the store publishes a number nobody can explain:

- **The same certificate in several logs.** One identity, several entries. This is the case the row names.
- **The same certificate twice in one log.** A resubmission. Real: the captured Cloudflare prefix contains
  one, which is why the corpus fixture is sized by where the duplicates are rather than by a round number.
- **An entry this codec cannot parse.** Recorded with `parse_issue` set and an identity still computed,
  because the alternative is a store whose counts go quiet. RFC 6962 section 4.6 is explicit that a client
  "MUST NOT construe an unrecognized MerkleLeafType or LogEntryType value as an error" while still being able
  to verify the tree, so an entry whose contents are opaque still gets a record - keyed on the leaf octets
  the tree hashes, which is the only identity available for something that cannot be read.

Two rules keep the identities meaningful. A precert entry's identity comes from the **leaf's**
`TBSCertificate`, never from the precertificate stored beside it: the leaf is what the tree hashes, and the
stored copy is unsigned and encoded differently - RFC 6962 section 3.2 paragraph 9 rewrites its issuer and
Authority Key Identifier when a Precertificate Signing Certificate was used, so 35% of production precerts
do not match their own stored copy byte for byte. And every record carries the `Receipt` for the fetch that
produced it (I6), including whether the transport was trusted at all: for the corpus in `tests/fixtures` it
was not, and that is recorded rather than hidden, because the bytes are believed by the log's signature and
not by TLS.

One distinction this store does **not** fold: a final certificate that embeds its SCT list has a different
TBSCertificate from the precertificate it was issued from, by exactly the extension RFC 6962 section 3.2
paragraph 9 names as the reconstructible difference. Both are recorded - `identity` keeps them apart and
`has_sct_extension` says which is which - so the number of certificates that such a normalisation would
merge stays a measured quantity rather than a silent decision.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from asn1core import Asn1Error, certificate_parts, parse_certificate
from ctspy import entry as ctentry
from ctspy import merkle
from ctspy.errors import CtspyError

from .errors import CertLedgerError
from .receipt import Receipt

__all__ = ["EntryConflict", "EntryRecord", "EntryStats", "EntryStore"]

BASIC_CONSTRAINTS_OID = (2, 5, 29, 19)
SCT_LIST_OID = (1, 3, 6, 1, 4, 1, 11129, 2, 4, 2)


class EntryConflict(CertLedgerError):
    """A log served two different leaves at one index. The tree changed underneath the store."""


@dataclass(frozen=True, slots=True)
class EntryRecord:
    """One leaf from one log: the identity it establishes, what could be read out of it, and its receipt."""

    log_id: bytes
    index: int
    leaf: bytes
    leaf_sha256: bytes
    entry_type: str
    identity: bytes
    certificate: bytes | None
    certificate_authenticated: bool
    issuer: bytes | None
    issuer_authenticated: bool
    subject_spki_sha256: bytes | None
    ca: bool | None
    has_sct_extension: bool
    chain_count: int
    parse_issue: str | None
    receipt: Receipt

    @classmethod
    def from_bytes(
        cls,
        *,
        log_id: bytes,
        index: int,
        leaf_input: bytes,
        extra_data: bytes,
        receipt: Receipt,
    ) -> EntryRecord:
        """Build a record from the two base64-decoded fields a log served, and nothing else.

        Nothing here proves the entry into a tree - that is `heads.py`'s job, done once per prefix rather
        than once per entry. The promise is narrower: the identity is the one the tree commits to, and a
        certificate that will not parse is recorded as unparseable instead of disappearing.
        """
        leaf_sha256 = merkle.leaf_hash(leaf_input)
        try:
            leaf = ctentry.MerkleTreeLeaf.parse(leaf_input)
            stored = ctentry.parse_extra_data(leaf, extra_data)
        except CtspyError as failure:
            # An entry the client cannot read is still an entry in the tree (RFC 6962 section 4.6), so it is
            # stored with the only identity available for opaque bytes and the reason it stayed opaque.
            return cls(
                log_id=log_id,
                index=index,
                leaf=leaf_input,
                leaf_sha256=leaf_sha256,
                entry_type="opaque",
                identity=hashlib.sha256(leaf_input).digest(),
                certificate=None,
                certificate_authenticated=False,
                issuer=None,
                issuer_authenticated=False,
                subject_spki_sha256=None,
                ca=None,
                has_sct_extension=False,
                chain_count=0,
                parse_issue=f"{type(failure).__name__}: {failure}",
                receipt=receipt,
            )

        signed = leaf.entry.entry
        tbs: bytes
        issuer: bytes | None
        if isinstance(signed, ctentry.PrecertEntry):
            entry_type, tbs = "precert", signed.tbs_certificate
            issuer, issuer_authenticated = signed.issuer_key_hash, True
        else:
            entry_type = "x509"
            tbs = certificate_parts(stored.certificate).tbs_certificate
            issuer, issuer_authenticated = _issuer_from_chain(stored.chain), False

        subject, ca, has_sct, parse_issue = _certificate_facts(stored.certificate)
        return cls(
            log_id=log_id,
            index=index,
            leaf=leaf_input,
            leaf_sha256=leaf_sha256,
            entry_type=entry_type,
            identity=hashlib.sha256(tbs).digest(),
            certificate=stored.certificate,
            certificate_authenticated=stored.authenticated,
            issuer=issuer,
            issuer_authenticated=issuer_authenticated,
            subject_spki_sha256=subject,
            ca=ca,
            has_sct_extension=has_sct,
            chain_count=len(stored.chain),
            parse_issue=parse_issue,
            receipt=receipt,
        )

    def summary(self) -> str:
        return (
            f"{self.log_id.hex()[:12]}@{self.index} {self.entry_type} id={self.identity.hex()[:12]} "
            f"issuer={(self.issuer or b'none').hex()[:12]} ca={self.ca} chain={self.chain_count}"
            + (f" issue={self.parse_issue}" if self.parse_issue else "")
        )


def _issuer_from_chain(chain: tuple[bytes, ...]) -> bytes | None:
    """SHA-256 over the issuer's stored SPKI, for entries that have no authenticated issuer hash.

    A precert entry carries `issuer_key_hash` inside the leaf and needs none of this. An x509 entry does:
    its issuer identity exists only in `extra_data`, which RFC 6962 section 4.6 leaves unsigned, so callers
    get `issuer_authenticated=False` beside the value. Taking the issuer from the chain rather than from the
    leaf certificate's own Issuer DN is deliberate: names collide across unrelated CAs and keys do not, which
    is why PLAN.md partitions the leaf layer by issuer SPKI and not by issuer name.
    """
    if not chain:
        return None
    try:
        return hashlib.sha256(parse_certificate(chain[0]).subject_public_key_info).digest()
    except Asn1Error:
        return None


def _certificate_facts(certificate: bytes) -> tuple[bytes | None, bool | None, bool, str | None]:
    """(subject SPKI hash, cA flag, SCT-extension present, parse problem).

    The cA flag is `None` when the certificate carries no basicConstraints at all, which RFC 5280 section
    4.2.1.9 treats as "not a CA" but which is worth distinguishing from an explicit `cA=FALSE`: the difference
    is between a certificate that says it is an end entity and one that never said anything.
    """
    try:
        parsed = parse_certificate(certificate)
    except Asn1Error as failure:
        return None, None, False, f"{type(failure).__name__}: {failure}"
    ca: bool | None = None
    has_sct = False
    for extension in parsed.extensions:
        if extension.oid == BASIC_CONSTRAINTS_OID:
            ca = b"\x01\x01\xff" in extension.value
        elif extension.oid == SCT_LIST_OID:
            has_sct = True
    return hashlib.sha256(parsed.subject_public_key_info).digest(), ca, has_sct, None


@dataclass(frozen=True, slots=True)
class EntryStats:
    """The counts the row is about, with everything that could make them disagree kept separate."""

    entries: int
    identities: int
    logs: int
    precerts: int
    x509s: int
    opaque: int
    unparseable: int
    unattributed: int
    sct_bearing: int

    def summary(self) -> str:
        return (
            f"{self.entries} entries from {self.logs} log(s) establish {self.identities} certificate "
            f"identities ({self.precerts} precert, {self.x509s} x509, {self.opaque} opaque); "
            f"{self.unparseable} refused parsing, {self.unattributed} have no known issuer, "
            f"{self.sct_bearing} embed an SCT list"
        )


class EntryStore:
    """Entries keyed by (log, index) and grouped by identity. Append-only, and it refuses a changed history."""

    def __init__(self) -> None:
        self._by_position: dict[tuple[bytes, int], EntryRecord] = {}

    def add(self, record: EntryRecord) -> EntryRecord:
        """Store one entry. The same position with different bytes is an incident, not an update.

        A log that serves two leaves at one index has changed its tree. A consistency proof is what catches
        that properly, but this is the last place it can be noticed for free, and overwriting here would
        destroy the evidence exactly as `HeadStore` refuses to overwrite a divergent root hash.
        """
        previous = self._by_position.get((record.log_id, record.index))
        if previous is not None:
            if previous.leaf_sha256 != record.leaf_sha256:
                raise EntryConflict(
                    f"log {record.log_id.hex()} index {record.index} served two different leaves: "
                    f"{previous.leaf_sha256.hex()[:16]} and {record.leaf_sha256.hex()[:16]}"
                )
            return previous
        self._by_position[(record.log_id, record.index)] = record
        return record

    def entries(self) -> tuple[EntryRecord, ...]:
        return tuple(self._by_position.values())

    def get(self, log_id: bytes, index: int) -> EntryRecord | None:
        return self._by_position.get((log_id, index))

    def certificates(self) -> Mapping[bytes, tuple[EntryRecord, ...]]:
        """Identity to the entries carrying it. More than one entry per key is the dedupe working."""
        return _group(self._by_position.values(), lambda record: record.identity)

    def by_issuer(self) -> Mapping[bytes, tuple[EntryRecord, ...]]:
        """Entries grouped by issuing key. PLAN's Tier B partition, and the incident-shaped question."""
        return _group(
            (record for record in self._by_position.values() if record.issuer is not None),
            lambda record: record.issuer or b"",
        )

    def positions(self, log_id: bytes) -> tuple[int, ...]:
        """Every index held for this log, ascending. Holes here are why `root_hash` can answer None."""
        return tuple(
            sorted(record.index for record in self._by_position.values() if record.log_id == log_id)
        )

    def leaves(self, log_id: bytes) -> tuple[tuple[int, bytes], ...]:
        """(index, leaf octets) ascending - the input a tree hash needs, in the order the tree has it."""
        return tuple(
            (record.index, record.leaf)
            for record in sorted(
                (found for found in self._by_position.values() if found.log_id == log_id),
                key=lambda found: found.index,
            )
        )

    def root_hash(self, log_id: bytes) -> bytes | None:
        """The Merkle Tree Hash over everything held for this log, or None if the record has holes.

        A tree hash is only a statement about a tree when the leaves are a contiguous run from zero; the
        hash of a set with a hole in it is a number about nothing, and handing one back would be worse than
        admitting the record is incomplete. This is what lets a finished walk *prove* completeness by
        comparing against the signed head rather than asserting it from a counter.
        """
        held = self.leaves(log_id)
        if not held or [index for index, _ in held] != list(range(len(held))):
            return None
        return merkle.tree_hash([leaf for _, leaf in held])

    def stats(self) -> EntryStats:
        records = self.entries()
        return EntryStats(
            entries=len(records),
            identities=len(self.certificates()),
            logs=len({record.log_id for record in records}),
            precerts=sum(1 for record in records if record.entry_type == "precert"),
            x509s=sum(1 for record in records if record.entry_type == "x509"),
            opaque=sum(1 for record in records if record.entry_type == "opaque"),
            unparseable=sum(1 for record in records if record.parse_issue),
            unattributed=sum(1 for record in records if record.issuer is None),
            sct_bearing=sum(1 for record in records if record.has_sct_extension),
        )


def _group(
    records: Iterable[EntryRecord], key: Callable[[EntryRecord], bytes]
) -> Mapping[bytes, tuple[EntryRecord, ...]]:
    grouped: dict[bytes, list[EntryRecord]] = {}
    for record in records:
        grouped.setdefault(key(record), []).append(record)
    return {identity: tuple(mates) for identity, mates in grouped.items()}
