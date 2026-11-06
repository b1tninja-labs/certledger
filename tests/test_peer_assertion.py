"""`cl.peer-assert` (trust model L1): prove we reached the address we chose.

L1 is precise about what the assertion buys and what it does not. It proves the connection went to
the address this process picked - **not** that the name mapped to the right address, which is L2's
DNSSEC question. PLAN.md calls anything weaker "theatre": without the check the OS resolver silently
picks the destination no matter which resolver a path claims to use.

The mismatch is produced with real sockets rather than a double that merely claims to be elsewhere:
the transport dials 127.0.0.2 while being told 127.0.0.1, both of which route to this machine, so
what the guard inspects is the peer the kernel actually connected to.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
from _support import make_path

from certledger import AnchorSet, DirectTransport, FetchFailure, PeerAddressMismatch, Unreachable
from certledger.transport import Resolver, SystemResolver


class RedirectingTransport:
    """Dials a different address than it is asked for, through the real guard."""

    def __init__(self, actually_dial: str) -> None:
        self.actually_dial = actually_dial
        self.asked_for: list[str] = []

    def connect(self, address: str, port: int, timeout: float) -> socket.socket:
        self.asked_for.append(address)
        return DirectTransport(
            dial=lambda _ignored, dial_port, dial_timeout: socket.create_connection(
                (self.actually_dial, dial_port), timeout=dial_timeout
            )
        ).connect(address, port, timeout)


def test_peer_address_is_asserted(log_endpoint: str, resolver: Resolver, anchor_dir: Path) -> None:
    """The named exit test for `cl.peer-assert`: the successful path records what it verified."""
    exchange = make_path(AnchorSet.load(anchor_dir), resolver).fetch(log_endpoint)
    assert exchange.receipt.peer_address == "127.0.0.1"
    assert exchange.receipt.peer_port is not None
    assert exchange.receipt.peer_port > 0


def test_a_connection_elsewhere_is_refused(
    resolver: Resolver, anchor_dir: Path, alias_tls_port: int
) -> None:
    """Asked for 127.0.0.1, dialled 127.0.0.2: the guard sees the real peer and stops.

    The listener lives only on the alias address, so the connection genuinely succeeds - a refused
    socket would show the transport working and prove nothing about the assertion.
    """
    transport = RedirectingTransport("127.0.0.2")
    url = f"https://ct.test.local:{alias_tls_port}/ct/v1/get-sth"
    with pytest.raises(FetchFailure) as caught:
        make_path(AnchorSet.load(anchor_dir), resolver, transport=transport).fetch(url)
    assert isinstance(caught.value.cause, PeerAddressMismatch)
    assert transport.asked_for == ["127.0.0.1"], "we asked for the address we resolved"
    assert "127.0.0.2" in str(caught.value.cause)
    assert caught.value.receipt.error is not None
    assert caught.value.receipt.peer_address is None, "unknown peer, not the one we meant (I6)"


def test_the_connection_asserts_even_when_the_transport_does_not(
    resolver: Resolver, anchor_dir: Path, alias_tls_port: int
) -> None:
    """The check is not delegable: a transport that skips it is caught after the handshake.

    This case keeps the layering honest. Without it the assertion in `transport.py` could be deleted
    and the one in `_PinnedConnection` would still pass every other test, so "defence in depth" would
    be a comment rather than a property someone can break.
    """

    class NaiveTransport:
        """Connects wherever it likes and reports nothing about it."""

        def connect(self, address: str, port: int, timeout: float) -> socket.socket:
            del address
            return socket.create_connection(("127.0.0.2", port), timeout=timeout)

    url = f"https://ct.test.local:{alias_tls_port}/ct/v1/get-sth"
    with pytest.raises(FetchFailure) as caught:
        make_path(AnchorSet.load(anchor_dir), resolver, transport=NaiveTransport()).fetch(url)
    assert isinstance(caught.value.cause, PeerAddressMismatch)
    assert "TLS session" in str(caught.value.cause)


def test_a_name_is_not_an_address() -> None:
    """The transport refuses to resolve; dialling a name would make the assertion circular."""
    with pytest.raises(Unreachable, match="not an address"):
        DirectTransport().connect("ct.test.local", 443, 2.0)


def test_an_unreachable_address_is_unreachable_not_empty() -> None:
    """A refused connection is `Unreachable`, not the same answer as "it replied with nothing"."""
    with pytest.raises(Unreachable, match="could not reach"):
        DirectTransport().connect("127.0.0.1", 1, 2.0)


def test_the_system_resolver_is_explicit() -> None:
    """Ugly on purpose: this is L1's stopgap, and L2 replaces the call rather than a call site."""
    assert SystemResolver("localhost") in {"127.0.0.1", "::1"}
    with pytest.raises(Unreachable):
        SystemResolver("no-such-name.invalid")
