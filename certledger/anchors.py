"""Anchors: the only things this process will ever trust, and why each one is here.

I1 says every anchor is a file in this repository with a date and a reason, and that an entry
missing either is a bug rather than a default. That is enforced on load, not in review:
`AnchorSet.load` refuses an entry with no `added` date or no `reason`, and refuses a manifest that
names a file which is not there. A malformed anchor list therefore never reads as an empty one -
empty means "nothing is trusted on this path", malformed means "someone changed this file", and
the two have opposite consequences.

The set is deliberately parsed here rather than handed to a certificate library. Reading our own
anchors is part of not depending on ambient machinery: the same call that accepts one PEM also
accepts a whole system bundle, and this file has no way to ask for the former and get the latter by
accident.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .errors import AnchorSetProblem

__all__ = ["Anchor", "AnchorSet", "pem_to_der"]

_PEM_BEGIN = b"-----BEGIN CERTIFICATE-----"
_PEM_END = b"-----END CERTIFICATE-----"


def pem_to_der(text: bytes, *, source: str) -> bytes:
    """Strip one PEM certificate to its DER, refusing anything else.

    Refuses lenient behaviour on purpose: a PEM with trailing junk, a private key, or a CSR would
    all be accepted by a general-purpose reader, and none of them is an anchor.
    """
    try:
        body = text.decode("ascii")
    except UnicodeDecodeError as exc:  # pragma: no cover - a PEM header is ASCII
        raise AnchorSetProblem(f"{source}: not ASCII: {exc}") from exc
    begin = body.find(_PEM_BEGIN.decode())
    end = body.find(_PEM_END.decode())
    if begin < 0 or end < 0 or end < begin:
        raise AnchorSetProblem(f"{source}: expected one PEM certificate")
    armor = body[begin + len(_PEM_BEGIN) : end]
    try:
        return base64.b64decode("".join(armor.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AnchorSetProblem(f"{source}: PEM body is not valid base64: {exc}") from exc


@dataclass(frozen=True, slots=True)
class Anchor:
    """One trusted certificate, with the record of why it is trusted.

    `origin` is the host this anchor is usable for, matched exactly. Logs are hosted on names that
    other things use too, and a set that trusts a key "for anything" turns a pin into the ambient
    store it replaced.
    """

    anchor_id: str
    origin: str
    added: datetime.date
    reason: str
    der: bytes

    def spki_sha256(self) -> str:
        """Hash of the stored SubjectPublicKeyInfo, for pinning and for receipts."""
        from asn1core import spki_sha256  # imported lazily so this module imports without it

        return spki_sha256(self.der)

    def usable_for(self, host: str) -> bool:
        return host.casefold() == self.origin.casefold()


@dataclass(frozen=True, slots=True)
class AnchorSet:
    """The anchors available to one path. An empty set is a valid, refusing configuration."""

    anchors: tuple[Anchor, ...]
    source: str

    @classmethod
    def empty(cls) -> AnchorSet:
        return cls(anchors=(), source="<empty>")

    @classmethod
    def load(cls, directory: Path | str) -> AnchorSet:
        """Read `anchors.toml` and every PEM file it names, refusing a half-correct set."""
        root = Path(directory)
        manifest = root / "anchors.toml"
        if not manifest.is_file():
            raise AnchorSetProblem(
                f"{manifest} is missing; an empty anchor set is written, not implied"
            )
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as exc:
            raise AnchorSetProblem(f"{manifest} cannot be read: {exc}") from exc

        entries = data.get("anchor", [])
        if not isinstance(entries, list):
            raise AnchorSetProblem(f"{manifest}: [[anchor]] must be a list of tables")

        seen: set[str] = set()
        loaded: list[Anchor] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise AnchorSetProblem(f"{manifest}: anchor #{index} is not a table")
            missing = [k for k in ("id", "origin", "added", "reason", "file") if k not in entry]
            if missing:
                raise AnchorSetProblem(
                    f"{manifest}: anchor #{index} is missing {', '.join(missing)}; "
                    "I1 requires a date and a reason for every anchor"
                )
            anchor_id = str(entry["id"])
            if anchor_id in seen:
                raise AnchorSetProblem(f"{manifest}: duplicate anchor id {anchor_id!r}")
            seen.add(anchor_id)
            added = entry["added"]
            if not isinstance(added, datetime.date):
                raise AnchorSetProblem(
                    f"{manifest}: anchor {anchor_id!r} has added={added!r}; it must be a date, "
                    "because an undated trust decision cannot be reviewed later"
                )
            reason = str(entry["reason"]).strip()
            if not reason:
                raise AnchorSetProblem(f"{manifest}: anchor {anchor_id!r} has an empty reason")
            path = root / str(entry["file"])
            if not path.is_file():
                raise AnchorSetProblem(
                    f"{manifest}: anchor {anchor_id!r} names {path}, which is absent"
                )
            loaded.append(
                Anchor(
                    anchor_id=anchor_id,
                    origin=str(entry["origin"]),
                    added=added,
                    reason=reason,
                    der=pem_to_der(path.read_bytes(), source=str(path)),
                )
            )
        return cls(anchors=tuple(loaded), source=str(manifest))

    def for_host(self, host: str) -> tuple[Anchor, ...]:
        return tuple(anchor for anchor in self.anchors if anchor.usable_for(host))

    def cadata(self, host: str) -> str:
        """PEM text for the anchors usable for `host`, for `SSLContext.load_verify_locations`.

        Raises rather than returning an empty string when nothing matches. An empty cadata would
        build a context that trusts nothing - the right *outcome*, the wrong way to learn it, since
        the caller needs to know the name was never pinned rather than that verification failed.
        """
        usable = self.for_host(host)
        if not usable:
            raise AnchorSetProblem(
                f"{self.source}: no anchor is pinned for {host!r}; pinning one is a dated "
                "decision, not a fallback"
            )
        return "\n".join(_to_pem(anchor.der) for anchor in usable)


def _to_pem(der: bytes) -> str:
    armor = base64.b64encode(der).decode("ascii")
    body = "\n".join(armor[i : i + 64] for i in range(0, len(armor), 64))
    return f"{_PEM_BEGIN.decode()}\n{body}\n{_PEM_END.decode()}"
