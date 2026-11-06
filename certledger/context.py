"""Building a TLS context that can only ever contain the anchors we were given.

The two calls this module never makes are `ssl.SSLContext.load_default_certs()` and
`set_default_verify_paths()`. Neither is called, and `tests/test_ambient_trust.py` patches both to
raise so that a future refactor cannot reach for them by habit - the guard is a test, not a comment.

Why it matters more than the generic advice suggests: on Windows `load_default_certs()` reads the
machine's certificate store, and the published mitigation for the 2026 compromised-intermediate
incident *writes into that same store*. An auditor that used it would have its view of the world
altered by the incident it was trying to measure, and would not know. That is trust model L1's
worked example, so it is quoted in the test rather than assumed.

`SSL_CERT_FILE` and `SSL_CERT_DIR` are honoured by `load_default_certs()` and by
`load_verify_locations()` when called with no arguments. Both are avoided here: anchors arrive as
`cadata`, so the environment cannot add a trust anchor to a context built by this function.
"""

from __future__ import annotations

import ssl

from .anchors import AnchorSet

__all__ = ["FORBIDDEN", "build_client_context"]

# Written down so the test can assert this module never mentions them as calls.
FORBIDDEN = ("load_default_certs", "set_default_verify_paths")


def build_client_context(anchors: AnchorSet, host: str) -> ssl.SSLContext:
    """A client context whose entire trust store is the anchors pinned for `host`.

    `PROTOCOL_TLS_CLIENT` is chosen over a bare `PROTOCOL_TLS_*` because it arrives with
    `check_hostname` and `verify_mode` already correct; starting from a neutral context and
    forgetting one of the two flags is the classic way to build something that verifies nothing
    while looking like it verifies everything.

    There is deliberately no "server name" parameter. The name is supplied per connection as
    `server_hostname` to `wrap_socket`; an earlier draft assigned `context.server_hostname`, which
    mypy rejected and the interpreter would not have: an `SSLContext` has no such attribute, so the
    line would have created a plausible-looking setting that checks nothing while the real check used
    whatever name the caller passed at handshake time.

    Raises:
        AnchorSetProblem: no anchor is pinned for `host`. That is a refusal, not an insecure
            default - see `AnchorSet.cadata`.
    """
    cadata = anchors.cadata(host)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    # No ca_certs / capath arguments anywhere: those paths are where SSL_CERT_FILE creeps in.
    context.load_verify_locations(cadata=cadata)
    return context
