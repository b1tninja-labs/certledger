"""Reaching the address we chose, and knowing afterwards that we did.

Two rules live here, and they are the whole of trust model L1's transport half.

**No resolution inside the HTTP layer.** `http.client` and `urllib` resolve the host they are
handed, which means the OS resolver picks the destination no matter what this process believes
about its own resolver. So resolution is a separate, injected call whose *result* is what we
connect to, and the name is passed to TLS only as `server_hostname`. PLAN.md is blunt about why:
without that, "we use our own resolver" is theatre.

**No proxy, by construction rather than by configuration.** `urllib.request` reads `HTTPS_PROXY`
and `NO_PROXY` through `ProxyHandler` unless you hand it an empty one, and `requests`/`httpx` do
the same behind a `trust_env` flag that defaults to true. This module uses `http.client`, which
never consults the environment at all, so there is no flag to forget to set. That is the reason
the standard library's lower layer is used despite being less convenient: a control that depends
on remembering a keyword argument is a control that eventually gets remembered wrong.

The assertion itself compares `getpeername()` against the chosen address after the plain socket
connects, and again after TLS wrapping. The second check is not paranoia about the same socket:
it is where a proxy that re-originates the connection would show up.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .errors import PeerAddressMismatch, Unreachable

__all__ = ["Dial", "DirectTransport", "Resolver", "SystemResolver", "Transport"]

Resolver = Callable[[str], str]
"""Name to address. Anything that is not this process's own call is ambient (I1)."""

Dial = Callable[[str, int, float], socket.socket]
"""How a socket actually gets opened, once the address has been chosen and validated."""


def SystemResolver(host: str) -> str:  # noqa: N802 - named as a strategy, not a function
    """The OS resolver, called explicitly so the result can be pinned and asserted.

    This is what phase 0 uses. It is *not* what L2 wants: trust model L2 replaces it with our own
    recursive validator, because a forwarder's answer and its `AD` bit are both somebody else's
    data. Naming it loudly keeps that on the roadmap instead of buried in a call site.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise Unreachable(f"{host} did not resolve: {exc}") from exc
    if not infos:
        raise Unreachable(f"{host} resolved to nothing")
    return str(infos[0][4][0])


class Transport(Protocol):
    """Anything able to produce a connected stream socket to a given address and port.

    A protocol rather than a base class so that the test double - a transport that connects
    somewhere other than where it was told to - is a legitimate implementation and not a subclass
    bending the real one's rules.
    """

    def connect(self, address: str, port: int, timeout: float) -> socket.socket: ...


@dataclass(frozen=True, slots=True)
class DirectTransport:
    """Connects to the address it is given. Never resolves, never proxies.

    `dial` is the one seam: a vantage may need to open the socket some other way - bound to an
    interface, or through another host's network stack for the phase-4 second vantage - without
    becoming a subclass. Subclassing is not merely inelegant here: a frozen dataclass with
    `slots=True` is rebuilt by the interpreter, so the generated methods' `super()` refers to the
    pre-slots class and any subclass that sets an attribute dies with a confusing `TypeError`. The
    assertion below is what must not be bypassable, so it lives in `connect`, which the seam cannot
    replace.
    """

    dial: Dial | None = None

    def connect(self, address: str, port: int, timeout: float) -> socket.socket:
        """Connect, then prove the socket handed back is the one that was asked for.

        The assertion is here rather than in the caller on purpose. In the caller it is a step the
        next person to build a connection can skip, and skipping it is invisible: the request still
        succeeds. Here it happens once before TLS, and `FetchPath` checks again after wrapping,
        which is where a proxy that re-originates the connection shows itself.
        """
        try:
            # An IP literal means no name lookup happens anywhere on this path. If a caller passes a
            # name, that lookup is exactly the ambiguity the assertion exists to catch, so it is
            # refused rather than performed.
            socket.inet_pton(socket.AF_INET6 if ":" in address else socket.AF_INET, address)
        except OSError as exc:
            raise Unreachable(
                f"{address!r} is not an address; resolution belongs to the path"
            ) from exc

        sock = self._open(address, port, timeout)
        try:
            peer = sock.getpeername()
        except OSError as exc:  # pragma: no cover - a connected socket always reports
            raise PeerAddressMismatch(f"{address}:{port} gave no peer identity: {exc}") from exc
        if peer[0] != address:
            sock.close()
            raise PeerAddressMismatch(
                f"asked for {address}:{port}, connected to {peer[0]}:{peer[1]}; "
                "something between here and the log redirected the connection"
            )
        return sock

    def _open(self, address: str, port: int, timeout: float) -> socket.socket:
        if self.dial is not None:
            return self.dial(address, port, timeout)
        try:
            return socket.create_connection((address, port), timeout=timeout)
        except OSError as exc:
            raise Unreachable(f"could not reach {address}:{port}: {exc}") from exc
