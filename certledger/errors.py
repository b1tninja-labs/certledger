"""The failure modes this layer distinguishes.

Each one exists because collapsing it into a neighbouring state would be a security bug, not a
convenience. The trust model calls this I8: unknown, unavailable, empty and zero are four
different answers.

- **AmbientTrust** - something tried to reach a trust anchor or a route that this process was not
  given explicitly. It is raised by the guard, not by the network.
- **PeerAddressMismatch** - we connected somewhere other than the address we chose. The peer
  assertion in `transport.py` exists precisely so this can be raised rather than assumed away.
- **AnchorSetProblem** - the anchor file is missing, unreadable, or an entry has no date or no
  reason. A malformed anchor list must never read as an empty-but-fine one, because empty means
  "nothing is trusted here" and malformed means "someone edited the file".
"""

from __future__ import annotations


class CertLedgerError(Exception):
    """Base for every error this package raises."""


class AmbientTrust(CertLedgerError):
    """An ambient-trust path was taken: default certificate stores, proxy environment, or a
    resolver we did not call. Raised by the guard in `context.py`, so a future refactor that
    reaches for `load_default_certs()` fails a test instead of quietly trusting a stranger."""


class PeerAddressMismatch(CertLedgerError):
    """The socket we ended up with is not connected to the address we chose.

    Trust model L1: asserting the peer proves we reached the address we picked, which is all the
    assertion can prove - that the name mapped to the right address is L2's question. A mismatch
    means something between us and the destination redirected the connection: a proxy, a NAT that
    is not ours, or an attacker.
    """


class AnchorSetProblem(CertLedgerError):
    """The anchor set could not be read, or an entry is missing what I1 requires of it."""


class Unreachable(CertLedgerError):
    """A fetch could not be completed.

    Distinct from "completed, and the answer was empty", and from "completed, and the answer
    failed to verify". PLAN.md's loop step 7 records a gap rather than pretending it did not
    happen, and that requires the type to exist.
    """
