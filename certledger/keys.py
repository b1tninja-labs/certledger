"""Which log signing keys this deployment trusts, and refusing the ones it does not.

`cl.key-pins` (RFC 9162 section 4.1 "Public Key", section 4.4 "Log ID"). This file exists to make one
rule unavoidable: **authenticity comes only from a log signature over a pinned key** (trust model I2).
Not from a valid TLS chain, not from HTTP 200, and not from a key the response happened to carry.

Two consequences, each easy to get wrong.

**A v1 STH does not say who signed it.** `SignedTreeHeadDataV2` carries a `log_id`; the v1 JSON
response carries only tree size, timestamp, root hash and signature. So the *caller* decides which log
it was talking to - from configuration, never from the response - and the lookup here is by origin. An
implementation that inferred the log from the artifact would let an attacker choose whose key the
verification used, which is adversary A7 in one line of code.

**The log ID is a hash of the key, not a label.** Section 4.4: it is SHA-256 over the DER
`SubjectPublicKeyInfo`. That is checked on load, so a pin whose `log_id` does not match its `key` is
refused at startup instead of producing "signature valid, wrong log" at three in the morning.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import tomllib
from dataclasses import dataclass
from pathlib import Path

from asn1core import spki_sha256
from ctspy.ecdsa import EcdsaKey, SignatureDecodeError
from ctspy.errors import VerificationError
from ctspy.sth import SignedTreeHeadV1, SignedTreeHeadV2
from ctspy.sth import verify as ctspy_verify

from .errors import CertLedgerError

__all__ = ["KeyRing", "LogPin", "PinProblem", "UnknownLogKey", "verify_sth"]

REQUIRED = (
    "log_id",
    "description",
    "origin",
    "key",
    "added",
    "source",
    "decided_by",
    "reviewed_by",
)


class PinProblem(CertLedgerError):
    """The pin file is malformed, or an entry could not be audited by whoever reads it next."""


class UnknownLogKey(CertLedgerError):
    """Nobody pinned this log. Refusing is the correct answer, not a missing feature."""


@dataclass(frozen=True, slots=True)
class LogPin:
    """One log's identity: its URL, its key, and the record of why it is trusted."""

    log_id: bytes
    description: str
    origin: str
    key_der: bytes
    added: datetime.date
    source: str
    decided_by: str
    reviewed_by: str

    @property
    def spki_sha256(self) -> str:
        return spki_sha256(self.key_der)

    def key(self) -> EcdsaKey:
        return EcdsaKey.from_spki(self.key_der)

    def usable_for(self, origin: str) -> bool:
        return self.origin.rstrip("/") == origin.rstrip("/")


@dataclass(frozen=True, slots=True)
class KeyRing:
    """The pinned log keys. An empty ring refuses everything, which is the safe default."""

    pins: tuple[LogPin, ...]
    source: str

    @classmethod
    def empty(cls) -> KeyRing:
        return cls(pins=(), source="<empty>")

    @classmethod
    def load(cls, manifest: Path | str) -> KeyRing:
        """Read a pin file, refusing an entry that nobody could later attribute or revoke."""
        path = Path(manifest)
        if not path.is_file():
            raise PinProblem(f"{path} is missing; an empty ring is written, not implied")
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as exc:
            raise PinProblem(f"{path} cannot be read: {exc}") from exc
        entries = data.get("log", [])
        if not isinstance(entries, list):
            raise PinProblem(f"{path}: [[log]] must be a list of tables")

        pins: list[LogPin] = []
        identities: set[str] = set()
        descriptions: set[str] = set()
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise PinProblem(f"{path}: log #{index} is not a table")
            missing = [field for field in REQUIRED if field not in entry]
            if missing:
                raise PinProblem(
                    f"{path}: log #{index} is missing {', '.join(missing)}; a pin nobody can "
                    "attribute is a pin nobody can revoke"
                )
            pin = _build(path, index, entry)
            if pin.log_id.hex() in identities or pin.description in descriptions:
                raise PinProblem(f"{path}: log #{index} duplicates an earlier entry")
            identities.add(pin.log_id.hex())
            descriptions.add(pin.description)
            pins.append(pin)
        return KeyRing(pins=tuple(pins), source=str(path))

    def for_origin(self, origin: str) -> LogPin:
        """The pin for the log at `origin`. Raises if nobody pinned that URL."""
        for pin in self.pins:
            if pin.usable_for(origin):
                return pin
        raise UnknownLogKey(
            f"{self.source}: no log key is pinned for {origin!r}. A key discovered on the path "
            "being verified is not a substitute (trust model I2)."
        )

    def by_log_id(self, log_id: bytes) -> LogPin:
        for pin in self.pins:
            if pin.log_id == log_id:
                return pin
        raise UnknownLogKey(f"{self.source}: log id {log_id.hex()} is not pinned")


def _build(path: Path, index: int, entry: dict[str, object]) -> LogPin:
    try:
        key_der = base64.b64decode(str(entry["key"]), validate=True)
        declared_id = base64.b64decode(str(entry["log_id"]), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PinProblem(f"{path}: log #{index} is not valid base64: {exc}") from exc
    if len(declared_id) != 32:
        raise PinProblem(f"{path}: log #{index} log_id is {len(declared_id)} bytes, not 32")
    try:
        # Parse the key now. A pin that cannot be loaded is a configuration error, and finding that
        # out during verification - after a fetch, under load, at night - is how it gets mistaken for
        # a compromised log.
        EcdsaKey.from_spki(key_der)
    except SignatureDecodeError as exc:
        raise PinProblem(f"{path}: log #{index} key is unusable: {exc}") from exc
    actual = hashlib.sha256(key_der).digest()
    if actual != declared_id:
        raise PinProblem(
            f"{path}: log #{index} declares log_id {declared_id.hex()} but its key hashes to "
            f"{actual.hex()}; section 4.4 says the ID is SHA-256 over the DER SPKI"
        )
    added = entry["added"]
    if not isinstance(added, datetime.date):
        raise PinProblem(f"{path}: log #{index} added must be a date, not {added!r}")
    if not str(entry["reviewed_by"]).strip():
        raise PinProblem(
            f"{path}: log #{index} names no reviewer. Trust model section 8 reserves key "
            "decisions for a human; an unreviewed pin is not a pin."
        )
    return LogPin(
        log_id=declared_id,
        description=str(entry["description"]),
        origin=str(entry["origin"]),
        key_der=key_der,
        added=added,
        source=str(entry["source"]),
        decided_by=str(entry["decided_by"]),
        reviewed_by=str(entry["reviewed_by"]),
    )


def verify_sth(sth: SignedTreeHeadV1 | SignedTreeHeadV2, ring: KeyRing, *, origin: str) -> LogPin:
    """Verify an STH against the key pinned for `origin`, and return the pin that accepted it.

    v2 artifacts name their own log, so the pin chosen by URL and the pin named by the artifact have
    to be the same object. A mismatch is refused rather than reconciled: two sources disagreeing
    about who signed is the finding, not an obstacle to answering.
    """
    pin = ring.for_origin(origin)
    if isinstance(sth, SignedTreeHeadV2) and sth.log_id != pin.log_id:
        raise VerificationError(
            f"{origin}: the STH names log {sth.log_id.hex()} but the pin for that URL is "
            f"{pin.log_id.hex()} ({pin.description})"
        )
    ctspy_verify(sth, pin.key())
    return pin
