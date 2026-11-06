"""Receipts: the artefact nobody else publishes.

An observation without provenance is a discrepancy to investigate, not data (I6), so every fetch
produces one receipt whether it succeeded, failed, or was refused mid-flight. Recording failures is
the part that is easy to skip and impossible to reconstruct afterwards: six months later, the
difference between "this log never had that entry" and "we could not reach this log on the 14th"
is entirely a receipt.

`peer_spki_sha256` is taken from the negotiated certificate rather than from the anchor we hoped
for. Recording the anchor would make every receipt look correct by construction and would hide the
one event that matters - a peer presenting a key nobody pinned, which is where a corporate
interceptor or an impostor endpoint first becomes visible.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

__all__ = ["Receipt"]


@dataclass(frozen=True, slots=True)
class Receipt:
    """What was asked of which path, from where, and what actually answered."""

    path_id: str
    vantage: str
    trust_class: str
    request_target: str
    started_utc: str
    duration_ms: int
    peer_address: str | None = None
    peer_port: int | None = None
    peer_spki_sha256: str | None = None
    status: int | None = None
    response_sha256: str | None = None
    response_bytes: int | None = None
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None and self.status is not None and self.status < 400

    @staticmethod
    def hash_response(body: bytes) -> str:
        """The hash of the bytes as received, before anything was parsed.

        Raw response bytes are written to storage before parsing (PLAN.md step 4), and this is the
        handle on them. Hashing a re-serialised object would attest to our own encoder.
        """
        return hashlib.sha256(body).hexdigest()

    def summary(self) -> str:
        if self.error is not None:
            return f"{self.path_id} {self.request_target} -> {self.error}"
        return (
            f"{self.path_id} {self.request_target} -> HTTP {self.status} "
            f"{self.response_bytes}B sha256={self.response_sha256}"
        )
