"""I3: a signature is verified over the octets that arrived, never over a re-encoding.

This is the reason `asn1core` exists and the reason this module is thin. A codec that normalises on
the way in produces a document that *looks* identical and hashes differently, and the failure goes
the wrong way round: a respelled certificate verifies happily against the re-encoding, so the
tampering is repaired instead of reported.

The shape of the API is the control. `capture` keeps the exact bytes and hands out slices of them;
`verify_over_stored` passes those slices to the caller's verifier and nothing else.
`reencoded_parts` exists so a test can demonstrate what the shortcut would have accepted, and it is
named to say so out loud - it returns digests of a document that no log ever signed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from asn1core import CertificateParts, certificate_parts, decode, encode_der

__all__ = ["StoredDocument", "capture", "verify_over_stored"]

Verifier = Callable[[bytes, bytes], bool]
"""Takes (signed region, signature) and returns whether it verifies."""


@dataclass(frozen=True, slots=True)
class StoredDocument:
    """A signed document and the slices of it that a verifier needs, all as stored octets."""

    raw: bytes
    tbs: bytes
    signature: bytes
    signature_algorithm: bytes
    canonical: bool

    def reencoded(self) -> bytes:
        """The DER re-encoding of this document - **not** something to verify against.

        Exposed because the only way to show that a pipeline is faithful is to compare against the
        version that is not. For a document that arrived canonical this equals `raw`, which is also
        the check `capture` records in `canonical`.
        """
        node, _ = decode(self.raw, der=False)
        return encode_der(node)

    def reencoded_parts(self) -> CertificateParts:
        """The same slices taken from `reencoded()`, for the contrast case in the tests."""
        return certificate_parts(self.reencoded())


def capture(raw: bytes, *, der: bool = True) -> StoredDocument:
    """Slice a certificate from its own bytes.

    ``der=True`` is the default and rejects a non-canonical document at the door, which is the right
    answer for a log that claims to serve DER. ``der=False`` keeps the original octets and marks the
    document non-canonical, so a respelled certificate stays available for *reporting* - it is a
    finding, not something to fix silently - while verification still runs over what arrived.

    Raises:
        DerViolation: a non-canonical encoding reached the DER path.
        CertificateError, TruncatedError, DecodeError: as in `asn1core.certificate_parts`.
    """
    parts = certificate_parts(raw, der=der)
    node, end = decode(raw, der=False)
    return StoredDocument(
        raw=raw[:end],
        tbs=parts.tbs_certificate,
        signature=parts.signature_value,
        signature_algorithm=parts.signature_algorithm,
        canonical=raw[:end] == encode_der(node),
    )


def verify_over_stored(document: StoredDocument, verify: Verifier) -> bool:
    """Run `verify` over the stored slices. The only verification entry point here."""
    return verify(document.tbs, document.signature)
