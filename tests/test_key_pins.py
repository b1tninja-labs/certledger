"""Which log keys are pinned, and what happens when one is not.

`cl.key-pins` (RFC 9162 section 4.1 "Public Key", section 4.4 "Log ID"). The trust model is blunt
about this (I2): authenticity arrives only as a log signature over a pinned key, and "a key
discovered on the path being verified is never a substitute". The test the roadmap names is
`test_unknown_key_is_rejected`, and the interesting part of it is not the happy path - it is that an
unpinned log produces a refusal rather than a fallback.

`keys/pins.toml` in the package ships empty. The pins used here come from
`tests/fixtures/log-pins.toml`: the real keys of two Google logs, read from Chrome's CT log list
v96.2 on 2026-11-05, which is test material and not a deployment decision - trust model section 8
reserves key decisions for a named human, and section 6 names the failure mode of getting that
backwards ("a poorly-anchored first pin").
"""

from __future__ import annotations

import base64
import json
import pathlib
from pathlib import Path

import pytest
from _support import ephemeral_log, sign_v1_head, write_pins
from ctspy.errors import VerificationError
from ctspy.sth import SignedTreeHeadV1

from certledger.keys import KeyRing, PinProblem, UnknownLogKey, verify_sth

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
PACKAGE_PINS = pathlib.Path(__file__).parents[1] / "keys" / "pins.toml"


@pytest.fixture(scope="module")
def production_ring() -> KeyRing:
    return KeyRing.load(FIXTURES / "log-pins.toml")


def test_the_shipped_pin_ring_is_empty_until_a_human_decides() -> None:
    """Mirrors the phase-0 rule for TLS anchors: shipped empty, with the reason written down."""
    ring = KeyRing.load(PACKAGE_PINS)
    assert ring.pins == ()


def test_a_real_log_key_verifies_a_real_sth_from_that_log(production_ring: KeyRing) -> None:
    document = json.loads((FIXTURES / "production-sth.json").read_text(encoding="utf-8"))
    origin = "https://ct.googleapis.com/logs/eu1/xenon2026h2/"
    for body in document["responses"]:
        pin = verify_sth(SignedTreeHeadV1.from_v1_json(body), production_ring, origin=origin)
        assert pin.description == "Google Xenon2026h2"


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    """The roadmap's named test. An unpinned origin is refused; nothing is inferred about it."""
    _, spki, _ = ephemeral_log()
    ring = KeyRing.load(write_pins(tmp_path, [("Test Log", "https://log.test/", spki)]))

    with pytest.raises(UnknownLogKey, match="no log key is pinned"):
        ring.for_origin("https://other-log.test/")

    # A head signed by a different key is not rescued by the ring that exists: it fails, rather than
    # being matched against whichever pin happens to validate.
    other_private, other_spki, _ = ephemeral_log()
    head = sign_v1_head(other_private, 1700000000000, 10, bytes(32))
    with pytest.raises(VerificationError):
        verify_sth(head, ring, origin="https://log.test/")
    assert other_spki != ring.for_origin("https://log.test/").key_der


def test_a_production_sth_does_not_verify_under_an_unrelated_pin(
    tmp_path: Path, production_ring: KeyRing
) -> None:
    """The other direction of the same rule: a real artifact needs its own log's pin."""
    document = json.loads((FIXTURES / "production-sth.json").read_text(encoding="utf-8"))
    sth = SignedTreeHeadV1.from_v1_json(document["responses"][0])
    xenon = production_ring.for_origin("https://ct.googleapis.com/logs/eu1/xenon2026h2/")
    verify_sth(sth, production_ring, origin="https://ct.googleapis.com/logs/eu1/xenon2026h2/")

    _, foreign_spki, _ = ephemeral_log()
    foreign = KeyRing.load(write_pins(tmp_path, [("Foreign", "https://log.test/", foreign_spki)]))
    with pytest.raises(VerificationError):
        verify_sth(sth, foreign, origin="https://log.test/")
    # The Argon pin is real but is not Xenon's, and the lookup is by origin, not by "any pin that fits"
    with pytest.raises(VerificationError):
        verify_sth(sth, production_ring, origin="https://ct.googleapis.com/logs/us1/argon2026h2/")
    assert (
        xenon.log_id
        != production_ring.for_origin("https://ct.googleapis.com/logs/us1/argon2026h2/").log_id
    )


def test_a_pin_whose_id_does_not_match_its_key_is_refused(tmp_path: Path) -> None:
    """Section 4.4: the log ID is SHA-256 over the DER SPKI. A mismatch is caught at load."""
    _, spki, _ = ephemeral_log()
    path = write_pins(tmp_path, [("Test Log", "https://log.test/", spki)])
    lines = path.read_text(encoding="utf-8").split("\n")
    lines[1] = 'log_id = "' + base64.b64encode(bytes(32)).decode() + '"'  # 32 bytes, wrong hash
    path.write_text("\n".join(lines), encoding="utf-8")
    with pytest.raises(PinProblem, match="SHA-256 over the DER SPKI"):
        KeyRing.load(path)


def test_an_unusable_key_is_refused_at_load_not_at_verification(tmp_path: Path) -> None:
    _, spki, _ = ephemeral_log()
    tampered = spki[:-1] + bytes([spki[-1] ^ 0x01])
    path = write_pins(tmp_path, [("Test Log", "https://log.test/", tampered)])
    with pytest.raises(PinProblem, match="unusable"):
        KeyRing.load(path)


def test_a_missing_pin_file_is_a_problem_not_an_empty_ring(tmp_path: Path) -> None:
    """Silence about configuration is how a deployment ends up trusting nothing and noticing late."""
    with pytest.raises(PinProblem, match="is missing"):
        KeyRing.load(tmp_path / "nope.toml")


def test_a_duplicate_entry_is_refused(tmp_path: Path) -> None:
    _, spki, _ = ephemeral_log()
    path = write_pins(tmp_path, [("Test Log", "https://a.test/", spki)])
    path.write_text(
        path.read_text(encoding="utf-8")
        + path.read_text(encoding="utf-8").replace("https://a.test/", "https://b.test/"),
        encoding="utf-8",
    )
    with pytest.raises(PinProblem, match="duplicates"):
        KeyRing.load(path)


def test_lookup_by_log_id_refuses_an_unpinned_log(tmp_path: Path) -> None:
    _, spki, log_id = ephemeral_log()
    ring = KeyRing.load(write_pins(tmp_path, [("Test Log", "https://log.test/", spki)]))
    assert ring.by_log_id(log_id).origin == "https://log.test/"
    with pytest.raises(UnknownLogKey, match="is not pinned"):
        ring.by_log_id(bytes(32))


def test_a_v2_head_naming_another_log_is_refused(tmp_path: Path) -> None:
    """Two sources of identity must agree; reconciling them silently is the bug being prevented."""
    from ctspy.sth import SignedTreeHeadV2, TreeHeadDataV2

    _, spki, _ = ephemeral_log()
    ring = KeyRing.load(write_pins(tmp_path, [("Test Log", "https://log.test/", spki)]))
    head = TreeHeadDataV2(timestamp=1700000000000, tree_size=1, root_hash=bytes(32))
    claims_to_be_someone_else = SignedTreeHeadV2(
        log_id=bytes(32), tree_head=head, signature=b"\x30\x06\x02\x01\x01\x02\x01\x01"
    )
    with pytest.raises(VerificationError, match="names log"):
        verify_sth(claims_to_be_someone_else, ring, origin="https://log.test/")


@pytest.mark.parametrize(
    "field",
    ["added", "source", "decided_by", "reviewed_by"],
)
def test_a_pin_nobody_can_attribute_or_revoke_is_refused(tmp_path: Path, field: str) -> None:
    _, spki, _ = ephemeral_log()
    path = write_pins(tmp_path, [("Test Log", "https://log.test/", spki)])
    text = path.read_text(encoding="utf-8")
    lines = [line for line in text.split("\n") if not line.startswith(f"{field} =")]
    path.write_text("\n".join(lines), encoding="utf-8")
    with pytest.raises(PinProblem, match=field):
        KeyRing.load(path)
