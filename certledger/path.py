"""A path is a configured object, not a function call.

Each path carries an identifier, a trust class, a vantage, its own anchors, its own resolver and a
response budget, and every fetch - successful, refused, or failed mid-handshake - produces exactly
one receipt. The receipt on a failure is the part that pays off later: the difference between "this
log never carried that entry" and "we could not reach this log that day" is unrecoverable without
it, and PLAN.md's loop step 5 asks for one per fetch per path including failures.

Two orderings in `fetch` are load-bearing and easy to reverse by accident:

**The anchor decision comes before any network call.** `build_client_context` raises if the name was
never pinned, so an unpinned host is refused without a SYN leaving the process. Reversing that makes
"we contacted it and then decided not to trust it" the normal path, which is how a pinning layer
ends up leaking lookups and traffic to hosts it will never accept.

**Resolution is ours, and its result is what we dial.** `http.client` would resolve the name itself;
`connect` is overridden so the address this process chose is the address that gets connected to, and
the name goes to TLS only as `server_hostname`.
"""

from __future__ import annotations

import datetime
import http.client
import ssl
import time
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from .anchors import AnchorSet
from .context import build_client_context
from .errors import CertLedgerError, PeerAddressMismatch, Unreachable
from .receipt import Receipt
from .transport import DirectTransport, Resolver, Transport

__all__ = ["Exchange", "FetchFailure", "FetchPath", "TrustClass", "Vantage"]

DEFAULT_TIMEOUT = 10.0
DEFAULT_RESPONSE_BUDGET = 64 * 1024 * 1024


class TrustClass(StrEnum):
    """How a path could be corrupted, which is what makes two paths comparable.

    I5 and I7 count *classes*, not paths: two fetches through the same laptop, the same resolver and
    the same uplink are one observation with two log lines. The values here are the ones the
    architecture names, and the phase-4 second vantage is what turns the third into data.
    """

    LOCAL = "local"
    HOSTED = "hosted"
    ARCHIVE = "archive"


@dataclass(frozen=True, slots=True)
class Vantage:
    provider: str
    region: str
    autonomous_system: int | None
    trust_class: TrustClass

    def label(self) -> str:
        asn = "unknown-as" if self.autonomous_system is None else f"as{self.autonomous_system}"
        return f"{self.trust_class}:{self.provider}:{self.region}:{asn}"


class FetchFailure(CertLedgerError):
    """A fetch that did not complete, carrying the receipt that proves it was attempted."""

    def __init__(self, message: str, *, receipt: Receipt, cause: Exception | None = None) -> None:
        super().__init__(message)
        self.receipt = receipt
        self.cause = cause


@dataclass(frozen=True, slots=True)
class Exchange:
    """Response bytes as received, plus the receipt describing how they arrived."""

    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    receipt: Receipt


class _PinnedConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a chosen address instead of resolving the name it is given."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        address: str,
        context: ssl.SSLContext,
        transport: Transport,
        timeout: float,
    ) -> None:
        super().__init__(host, port=port, context=context, timeout=timeout)
        self._address = address
        self._transport = transport
        # Own handles rather than the base class's privates: `_context` is not in typeshed, and
        # `self.timeout` on the base is typed Optional because HTTPConnection accepts None.
        self._ssl_context = context
        self._connect_timeout = timeout
        self.observed_peer: str | None = None
        self.peer_spki_sha256: str | None = None

    def connect(self) -> None:
        sock = self._transport.connect(self._address, self.port, self._connect_timeout)
        # server_hostname carries the name; the socket carries the address. Keeping them apart is
        # what makes hostname verification meaningful while still dialing our own answer.
        wrapped = self._ssl_context.wrap_socket(sock, server_hostname=self.host)
        observed = wrapped.getpeername()
        if observed[0] != self._address:
            wrapped.close()
            raise PeerAddressMismatch(
                f"the TLS session is with {observed[0]}, not the resolved {self._address}"
            )
        # Peer identity is taken here, at the handshake, and not after the body is read:
        # `http.client` closes the connection as soon as a non-keep-alive response is drained, so
        # `self.sock` is None by the time a caller could look at it. A log that answered and then
        # dropped would otherwise be recorded as having had no peer at all.
        self.observed_peer = observed[0]
        self.peer_spki_sha256 = _peer_spki(wrapped)
        self.sock = wrapped


class FetchPath:
    """One configured way of reaching the logs."""

    def __init__(
        self,
        *,
        path_id: str,
        vantage: Vantage,
        anchors: AnchorSet,
        resolver: Resolver,
        transport: Transport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        response_budget: int = DEFAULT_RESPONSE_BUDGET,
    ) -> None:
        self.path_id = path_id
        self.vantage = vantage
        self.anchors = anchors
        self.resolver = resolver
        self.transport = transport if transport is not None else DirectTransport()
        self.timeout = timeout
        self.response_budget = response_budget

    def fetch(self, url: str, *, method: str = "GET", body: bytes | None = None) -> Exchange:
        """Fetch `url` over this path. Raises `FetchFailure`, carrying a receipt, on any failure."""
        _scheme, host, port, target = _split(url)
        started = datetime.datetime.now(datetime.UTC)
        clock = time.monotonic()

        def failed(
            cause: Exception,
            *,
            known_peer: str | None = None,
            known_port: int | None = None,
        ) -> FetchFailure:
            """A receipt for a fetch that did not complete (PLAN step 5: failures get one too)."""
            record = Receipt(
                path_id=self.path_id,
                vantage=self.vantage.label(),
                trust_class=self.vantage.trust_class.value,
                request_target=f"{method} {target}",
                started_utc=started.isoformat(),
                duration_ms=int((time.monotonic() - clock) * 1000),
                peer_address=known_peer,
                peer_port=known_port,
                error=f"{type(cause).__name__}: {cause}",
            )
            return FetchFailure(
                f"{self.path_id}: {host}{target} - {cause}", receipt=record, cause=cause
            )

        # Pinned first, connected second: an unpinned name is refused before anything leaves here.
        try:
            context = build_client_context(self.anchors, host)
            address = self.resolver(host)
        except (CertLedgerError, OSError) as exc:
            raise failed(exc) from exc

        connection = _PinnedConnection(
            host,
            port,
            address=address,
            context=context,
            transport=self.transport,
            timeout=self.timeout,
        )
        try:
            connection.request(method, target, body=body)
            response = connection.getresponse()
            payload = response.read(self.response_budget + 1)
            if len(payload) > self.response_budget:
                raise Unreachable(
                    f"{host} exceeded the {self.response_budget} byte budget for {target}"
                )
            if connection.observed_peer != address:  # pragma: no cover - connect() asserts it
                raise PeerAddressMismatch(
                    f"{host}: the session reported {connection.observed_peer}, not {address}"
                )
            status, reason = response.status, response.reason
            headers = tuple(response.getheaders())
            peer_spki = connection.peer_spki_sha256
        except PeerAddressMismatch as exc:
            # The peer is deliberately not recorded: writing the address we *meant* here would make
            # the receipt look like a normal failure and hide the one fact that matters - that we do
            # not know what answered. The observed address is in the message.
            raise failed(exc) from exc
        except (OSError, ssl.SSLError, http.client.HTTPException, CertLedgerError) as exc:
            raise failed(exc, known_peer=address, known_port=port) from exc
        finally:
            connection.close()

        record = Receipt(
            path_id=self.path_id,
            vantage=self.vantage.label(),
            trust_class=self.vantage.trust_class.value,
            request_target=f"{method} {target}",
            started_utc=started.isoformat(),
            duration_ms=int((time.monotonic() - clock) * 1000),
            peer_address=address,
            peer_port=port,
            peer_spki_sha256=peer_spki,
            status=status,
            response_sha256=Receipt.hash_response(payload),
            response_bytes=len(payload),
        )
        return Exchange(status=status, reason=reason, headers=headers, body=payload, receipt=record)


def _split(url: str) -> tuple[str, str, int, str]:
    """Scheme, host, port and target. Only https, and no environment involved."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(
            f"{url!r} is not an https URL with a host; this layer fetches nothing else, and "
            "there is no proxy scheme to fall back on"
        )
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    return parts.scheme, parts.hostname, parts.port or 443, target


def _peer_spki(sock: ssl.SSLSocket) -> str | None:
    """SPKI hash of whatever the peer actually presented, or None if it presented nothing.

    Recorded from the negotiation rather than from the anchor we hoped to meet, so that a peer
    presenting a different key - an interceptor, an impostor - shows up here instead of matching
    the expectation by construction.
    """
    from asn1core import Asn1Error, spki_sha256

    der = sock.getpeercert(binary_form=True)
    if not der:
        return None
    try:
        return spki_sha256(der)
    except Asn1Error:  # pragma: no cover - the handshake would have refused it first
        return None
