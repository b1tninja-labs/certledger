"""Every fetch leaves a receipt behind, including the fetches that did not work.

I6 says an observation without provenance is a discrepancy rather than data, and PLAN.md's loop step
5 asks for one receipt per fetch per path *including failures*. The failure half is the one that gets
dropped in implementation, because a failed fetch has no response to describe - which is exactly why
it needs recording: six months later, "the log never had that entry" and "we could not reach the log"
are different claims, and only a receipt can tell them apart.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from _support import VANTAGE, make_path
from conftest import BODY, LogServer

from certledger import AnchorSet, FetchFailure, FetchPath, Receipt
from certledger.transport import Resolver


def test_a_successful_fetch_carries_a_full_receipt(
    log_endpoint: str, resolver: Resolver, anchor_dir: Path, log_server: LogServer
) -> None:
    receipt = make_path(AnchorSet.load(anchor_dir), resolver).fetch(log_endpoint).receipt
    assert receipt.succeeded
    assert receipt.path_id == "p-loopback"
    assert receipt.trust_class == "local"
    assert receipt.vantage == "local:test:loopback:unknown-as"
    assert receipt.status == 200
    assert receipt.peer_address == "127.0.0.1"
    assert receipt.peer_port == log_server.port
    assert receipt.peer_spki_sha256
    assert receipt.response_bytes == len(BODY)
    assert receipt.error is None
    assert "HTTP 200" in receipt.summary()


def test_a_failed_fetch_still_carries_a_receipt(
    log_endpoint: str, resolver: Resolver, unrelated_dir: Path
) -> None:
    with pytest.raises(FetchFailure) as caught:
        make_path(AnchorSet.load(unrelated_dir), resolver).fetch(log_endpoint)
    receipt = caught.value.receipt
    assert receipt.succeeded is False
    assert receipt.error is not None
    assert "certificate verify failed" in receipt.error
    assert receipt.status is None, "no answer, not a zero answer (I8)"
    assert receipt.response_sha256 is None
    assert "->" in receipt.summary()


def test_an_oversized_response_is_recorded_as_a_gap(
    log_endpoint: str, resolver: Resolver, anchor_dir: Path
) -> None:
    """The budget is a completeness fact, so it is written down rather than silently truncated."""
    path = FetchPath(
        path_id="p-tiny",
        vantage=VANTAGE,
        anchors=AnchorSet.load(anchor_dir),
        resolver=resolver,
        timeout=5.0,
        response_budget=8,
    )
    with pytest.raises(FetchFailure) as caught:
        path.fetch(log_endpoint)
    assert "budget" in str(caught.value.cause)
    assert caught.value.receipt.error is not None
    assert caught.value.receipt.response_bytes is None


def test_a_receipt_names_the_path_not_just_the_host(resolver: Resolver, anchor_dir: Path) -> None:
    """Two paths to the same log must be distinguishable in the record, or the diff is meaningless."""
    first = make_path(AnchorSet.load(anchor_dir), resolver, path_id="p-a")
    assert first.path_id == "p-a"
    receipt = Receipt(
        path_id="p-a",
        vantage="local:test:loopback:unknown-as",
        trust_class="local",
        request_target="GET /ct/v1/get-sth",
        started_utc="2026-11-05T00:00:00+00:00",
        duration_ms=1,
    )
    assert receipt.summary().startswith("p-a GET /ct/v1/get-sth -> ")
    assert receipt.succeeded is False, "no status yet is not status 200"


def test_a_query_reaches_the_log_intact(
    log_server: LogServer, resolver: Resolver, anchor_dir: Path
) -> None:
    """`get-entries` is a query endpoint, so the query has to survive to the wire.

    Dropping it would still return plausible JSON and fetch the wrong range - every later stage
    would look correct. The receipt records what was asked, which is what makes the mistake
    catchable after the fact rather than only before it.
    """
    url = f"https://{log_server.host}:{log_server.port}/ct/v1/get-entries?start=7&end=9"
    exchange = make_path(AnchorSet.load(anchor_dir), resolver).fetch(url)
    assert exchange.receipt.request_target == "GET /ct/v1/get-entries?start=7&end=9"
    assert "/ct/v1/get-entries?start=7&end=9" in log_server.served
