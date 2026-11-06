"""`cl.der-fidelity` (trust model I3): the signature is checked over the bytes that arrived.

This is the invariant `asn1core` was written for, so the test is not "verification works" - it is
"verification does not quietly move to a re-encoding". The two directions are separated here:

- A canonical document verifies over its stored slices, using a verifier built by a *different*
  library. That cross-check is what proves the slice is the signed region: `cryptography` produced
  the signature it is checking, and it accepted the region `asn1core` cut out.
- A respelled document - the same certificate, re-framed with a non-minimal length - **must** fail
  over the stored bytes, and *would have passed* had the pipeline normalised first. The second half
  is the whole point. A codec that re-encodes on the way in repairs tampering instead of reporting
  it, and does so silently, because everything downstream sees a well-formed certificate.

The respelling uses X.690 8.1's allowance that BER may use a long form where a short one would do:
`30 84 00 00 01 9d ...` decodes to the same `TBSCertificate` as `30 82 01 9d ...` and re-encodes to
it exactly, which is precisely why it is dangerous.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest
from _support import make_path
from asn1core import DerViolation, certificate_parts, decode, encode_der
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_der_x509_certificate

from certledger import AnchorSet, capture, verify_over_stored
from certledger.transport import Resolver


def der_verifier(der: bytes) -> Callable[[bytes, bytes], bool]:
    """A verifier built from a second implementation, so the slices are not self-confirming.

    `cryptography`'s order is `verify(signature, data, algorithm)`, which reads backwards next to
    every other library and fails as an `InvalidSignature` rather than a type error when reversed.
    """
    certificate = load_der_x509_certificate(der)
    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise AssertionError("the fixture must hand us an EC key; the test is about the bytes")
    hash_algorithm = certificate.signature_hash_algorithm
    assert hash_algorithm is not None

    def verify(signed_region: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(signature, signed_region, ec.ECDSA(hash_algorithm))
            return True
        except InvalidSignature:
            return False

    return verify


def bloat_tbs_length(der: bytes) -> bytes:
    """The same certificate with the `TBSCertificate` length re-framed in non-minimal long form."""
    node, end = decode(der, der=True)
    assert end == len(der)
    tbs, signature_algorithm, signature_value = node.children
    content = tbs.content()
    respelled_tbs = bytes((0x30, 0x84)) + len(content).to_bytes(4, "big") + content
    outer = respelled_tbs + signature_algorithm.raw + signature_value.raw
    return bytes((0x30, 0x82)) + len(outer).to_bytes(2, "big") + outer


def test_signature_uses_stored_bytes(leaf_der: bytes) -> None:
    document = capture(leaf_der)
    assert document.canonical is True
    assert document.raw == leaf_der
    assert verify_over_stored(document, der_verifier(leaf_der)) is True


def test_the_stored_slices_are_the_signed_region(leaf_der: bytes) -> None:
    """`asn1core`'s slice verifies under a signature `cryptography` handed us."""
    certificate = load_der_x509_certificate(leaf_der)
    document = capture(leaf_der)
    assert document.signature == certificate.signature
    assert document.tbs != leaf_der, "the signed region is a slice, not the whole document"
    assert verify_over_stored(document, der_verifier(leaf_der))


def test_a_respelled_document_fails_where_reencoding_would_have_passed(leaf_der: bytes) -> None:
    respelled = bloat_tbs_length(leaf_der)
    assert respelled != leaf_der

    document = capture(respelled, der=False)
    assert document.canonical is False
    assert document.reencoded() == leaf_der, "same document, different spelling"

    verify = der_verifier(leaf_der)
    # What actually arrived: the CA never signed these octets.
    assert verify_over_stored(document, verify) is False
    # What a normalising pipeline would have verified instead, and therefore never reported.
    parts = document.reencoded_parts()
    assert verify(parts.tbs_certificate, parts.signature_value) is True


def test_the_der_path_refuses_the_respelling_rather_than_silently_fixing_it(
    leaf_der: bytes,
) -> None:
    with pytest.raises(DerViolation):
        capture(bloat_tbs_length(leaf_der), der=True)


def test_fetched_bytes_are_hashed_as_received(
    log_endpoint: str, resolver: Resolver, anchor_dir: Path
) -> None:
    """The receipt attests to the raw response, before anything was parsed (PLAN step 4)."""
    exchange = make_path(AnchorSet.load(anchor_dir), resolver).fetch(log_endpoint)
    assert exchange.receipt.response_sha256 == hashlib.sha256(exchange.body).hexdigest()
    assert exchange.receipt.response_bytes == len(exchange.body)


def test_certificate_parts_and_capture_agree(leaf_der: bytes) -> None:
    parts = certificate_parts(leaf_der)
    document = capture(leaf_der)
    assert (document.tbs, document.signature) == (
        parts.tbs_certificate,
        parts.signature_value,
    )
    assert encode_der(decode(leaf_der, der=True)[0]) == leaf_der
