"""Shared test scaffolding that is not a pytest fixture.

Kept out of `conftest.py` so the test modules import it by name rather than reaching into a file
pytest loads implicitly, and prefixed with an underscore so pytest never tries to collect it.
"""

from __future__ import annotations

from certledger import AnchorSet, FetchPath, TrustClass, Vantage
from certledger.transport import Resolver, Transport

VANTAGE = Vantage(
    provider="test", region="loopback", autonomous_system=None, trust_class=TrustClass.LOCAL
)

HOSTED_VANTAGE = Vantage(
    provider="elsewhere",
    region="another-as",
    autonomous_system=64512,
    trust_class=TrustClass.HOSTED,
)


def make_path(
    anchors: AnchorSet,
    resolver: Resolver,
    transport: Transport | None = None,
    *,
    path_id: str = "p-loopback",
    vantage: Vantage = VANTAGE,
) -> FetchPath:
    return FetchPath(
        path_id=path_id,
        vantage=vantage,
        anchors=anchors,
        resolver=resolver,
        transport=transport,
        timeout=5.0,
    )
