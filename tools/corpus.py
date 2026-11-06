"""Capture a prefix of production logs that can be checked against the log's own signature.

`certledger`'s entry store needs real entries, and a fixture of entries is only as good as the reason to
believe it. An entry is an assertion about a tree, so the corpus here is a **prefix** - entries 0 to N-1 -
because a prefix has a Merkle Tree Hash, and a prefix's root can be tied to a signed tree head with a
consistency proof. An arbitrary window was excluded on the belief that no deployed log serves an inclusion
proof by hash, so middle entries would be bytes with no claim attached to them. That belief was measured
against a path that appears in no RFC, and it is retracted: asked at RFC 6962 section 4.5's
`get-proof-by-hash` with both of its inputs, every log in the fleet served an audit path that verified (see
`ctspy/docs/interop.md`). A window of entries can therefore be tied to a signed head after all, which makes
the prefix here a choice about capture cost rather than a limit the deployment imposes; adding a
`get-proof-by-hash` pass to this tool is what would retire the choice.

What the tool records, and what it declines to claim:

- The tree head is the log's own `get-sth` response, verified against the key from its `get-sth-keys`, which
  must hash to the published log id. No trust anchor, system store, or environment variable is consulted.
- The prefix root is computed from the leaf octets as they arrived, then proved consistent with that head.
  `consistent_with_head` is the tool's own check, recorded so a reader knows whether the fixture is evidence
  or merely data.
- The HTTP transport is **not** verified: there is no anchor decision yet, so `transport.verified` is false.
  That is the trust model working rather than a gap in it - the bytes are genuine because a pinned key signed
  a tree containing them, not because TLS said so.
- Entries that a duplicate search turned up in a second log begin as positional evidence and are then asked
  for a real inclusion path: `get-proof-by-hash` at the tree size that block's own stored head names, checked
  against that head's root, with the head itself re-verified against the key stored beside it first. A peer
  block is marked `verified` only when *every* entry in it carries a path that verifies offline, so
  `verified: false` still means "do not cite this as proved". It just gets rarer now that the request is
  asked correctly: this tool once assumed no log would answer it, because it had asked a path no RFC defines.

Run it with `python tools/corpus.py`; it writes `tests/fixtures/entry-corpus.json`. `--prove-only` adds those
inclusion paths to a fixture that already exists and changes nothing else, which is how a capture made before
the corrected request gets finished without disturbing the prefix or any number drawn from it.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT.parent / "asn1core"))
sys.path.insert(0, str(ROOT.parent / "ctspy"))
sys.path.insert(0, str(ROOT))

from asn1core import certificate_parts  # noqa: E402
from ctspy import entry as ctentry  # noqa: E402
from ctspy import merkle  # noqa: E402
from ctspy import sth as ctsth  # noqa: E402
from ctspy.ecdsa import EcdsaKey, verify_sha256  # noqa: E402

USER_AGENT = "certledger-corpus/0 (evidence capture; independent monitor)"
LOG_LIST = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
WINDOW_FILE = "midwindow-corpus.json"


def get_json(url: str, *, retries: int = 3) -> dict:
    """GET and parse, retrying only where a retry can help.

    A 429 or a 5xx is a moment; a 403 is a fact about the deployment, and this tool's own callers read 403 as
    an answer (Cloudflare refuses `get-sth-keys`, which is why `key_from_log_list` exists). Retrying that would
    turn a documented behaviour into a slow hang, so the two are kept apart.
    """
    last: Exception | None = None
    for attempt in range(retries):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code not in {429, 500, 502, 503, 504}:
                raise
            time.sleep(1.5 * (attempt + 1))
    if last is None:  # only reachable with retries=0; a raise, not an assert, so -O keeps it
        raise RuntimeError(f"{url}: no attempt made")
    raise last


def prefix(origin: str, count: int, page: int = 32) -> list[dict]:
    """Entries 0 to count-1, paged. A log may answer fewer than asked (RFC 6962 section 4.6)."""
    out: list[dict] = []
    start = 0
    while len(out) < count:
        want = min(page, count - len(out))
        batch = get_json(f"{origin}/ct/v1/get-entries?start={start}&end={start + want - 1}")[
            "entries"
        ]
        if not batch:
            break
        out.extend(batch)
        start += len(batch)
    return out[:count]


def identity(leaf_input: bytes, extra_data: bytes) -> bytes:
    """SHA-256 over the logged TBSCertificate, which is the identity `certledger.entries` uses."""
    leaf = ctentry.MerkleTreeLeaf.parse(leaf_input)
    signed = leaf.entry.entry
    if isinstance(signed, ctentry.PrecertEntry):
        tbs = signed.tbs_certificate
    else:
        tbs = certificate_parts(
            ctentry.parse_extra_data(leaf, extra_data).certificate
        ).tbs_certificate
    return hashlib.sha256(tbs).digest()


def key_from_log_list(origin: str) -> EcdsaKey:
    """The key the log list publishes for `origin`, when the log itself will not publish one.

    Cloudflare answers `get-sth-keys` with 403, which is a fact about the deployment rather than an error to
    retry. Falling back to Chrome's published list is legitimate for *test* material - it is the same list
    browsers use to decide which logs exist - and `key_source` records which route the key took, because a
    key whose provenance is unclear is worse than a missing one. Production pinning stays where it belongs:
    a named human writing `keys/pins.toml`.
    """
    document = get_json(LOG_LIST)
    want = origin.rstrip("/")
    for operator in document.get("operators", []):
        for log in operator.get("logs", []):
            candidates = ([log["url"]] if log.get("url") else []) + list(log.get("urls", []))
            if any(str(url).rstrip("/") == want for url in candidates):
                return EcdsaKey.from_spki(base64.b64decode(log["key"]))
    raise SystemExit(f"{origin}: no key from get-sth-keys and none in the log list")


def head_and_key(origin: str) -> tuple[ctsth.SignedTreeHeadV1, EcdsaKey, str]:
    """The log's current tree head, and the key that signs it, cross-checked against the published log id."""
    tree_head = ctsth.SignedTreeHeadV1.from_v1_json(get_json(f"{origin}/ct/v1/get-sth"))
    try:
        published = get_json(f"{origin}/ct/v1/get-sth-keys")["keys"]
    except Exception:
        published = []
    for candidate in published:
        key = EcdsaKey.from_spki(base64.b64decode(candidate["static_key"]))
        if key.log_id != base64.b64decode(candidate["key_id"]):
            raise SystemExit(f"{origin}: published key_id does not hash from static_key")
        if verify_sha256(key, tree_head.transcript(), tree_head.signature):
            return tree_head, key, "get-sth-keys"
    key = key_from_log_list(origin)
    if not verify_sha256(key, tree_head.transcript(), tree_head.signature):
        raise SystemExit(f"{origin}: neither its own keys nor the log list's verify its tree head")
    return tree_head, key, "chrome-log-list-v3"


def consistency(origin: str, first_size: int, first_root: bytes, head) -> list[bytes] | None:
    """A proof that the prefix root is a piece of the signed tree, or None if it cannot be had."""
    try:
        body = get_json(
            f"{origin}/ct/v1/get-sth-consistency?first={first_size}&second={head.tree_size}"
        )
    except Exception:
        return None
    # Both specifications call this `consistency`: RFC 6962 section 4.4, RFC 9162 section 5.3. The alternate
    # name is not a spec spelling (an earlier note here said RFC 6962 called it `audit_consistency`, which is
    # wrong twice over - wrong field, wrong section) but it stays as tolerance for a front end, because a
    # proof nobody can read is not made more true by being rejected for its spelling.
    nodes = body.get("consistency") or body.get("audit_consistency") or []
    proof = [base64.b64decode(node) for node in nodes]
    if merkle.verify_consistency(first_size, head.tree_size, proof, first_root, head.root_hash):
        return proof
    return None


def head_block(tree_head: ctsth.SignedTreeHeadV1, key: EcdsaKey, source: str) -> dict:
    return {
        "timestamp": tree_head.timestamp,
        "tree_size": tree_head.tree_size,
        "root_hash": tree_head.root_hash.hex(),
        "signature": base64.b64encode(tree_head.signature).decode(),
        "log_id": key.log_id.hex(),
        "key_spki": base64.b64encode(key.spki).decode(),
        "key_source": source,
    }


def window(origin: str, start: int, count: int, page: int = 32) -> list[tuple[int, bytes, bytes]]:
    """Entries `start` to `start+count-1` as (index, leaf, extra), paged and position-tagged.

    No log answers more than 32 entries per request in practice - measured on Google's logs, and permitted by
    RFC 9162 section 5.6 paragraph 8 - so this pages. The index travels *with* each entry rather than being
    inferred from the order they arrive in: a short page in the middle would otherwise turn a window into an
    unnamed set of bytes, and the whole point of this file is a claim about positions.
    """
    rows: list[tuple[int, bytes, bytes]] = []
    cursor = start
    while len(rows) < count:
        want = min(page, count - len(rows))
        batch = get_json(f"{origin}/ct/v1/get-entries?start={cursor}&end={cursor + want - 1}")[
            "entries"
        ]
        if not batch:
            break
        for offset, item in enumerate(batch):
            rows.append(
                (
                    cursor + offset,
                    base64.b64decode(item["leaf_input"]),
                    base64.b64decode(item["extra_data"]),
                )
            )
        cursor += len(batch)
    if [index for index, _, _ in rows] != list(range(start, start + len(rows))):
        raise SystemExit(f"{origin}: entries came back non-contiguous, so this is not a window")
    return rows[:count]


def _load_windows(path: pathlib.Path) -> dict:
    """The existing window fixture, coerced to the shape this tool writes from now on.

    The first capture held one window at the top level because there was one window. Sampling a second log
    turns that into a list, and the migration happens on read rather than by editing committed evidence: the
    bytes already recorded keep their head and index exactly as captured, and only the container changes shape.
    """
    if not path.exists():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if "windows" not in document and "entries" in document:
        document["windows"] = [
            {
                "log": document.pop("log"),
                "window": document.pop("window"),
                "entries": document.pop("entries"),
            }
        ]
    return document


def capture_window(out: pathlib.Path, origin: str, count: int, start: int | None) -> int:
    """A proved slice from somewhere in the middle of a tree.

    The prefix corpus answers one question and cannot answer this one: how many CAs *begin* a log, and how many
    sit in the middle of it. Positions 0 to 235 of Nimbus2027 are the start of a half-year log, and a CA layer
    measured there is a ratio about beginnings. This captures entries at the midpoint of a tree and proves each
    one individually with the request the earlier version of this tool believed nobody would answer.

    One window per log, merged into `midwindow-corpus.json`, so capturing the prefix's *own* log adds a sample
    that differs from the prefix in position and in nothing else. Re-capturing a log replaces that log's window
    and leaves the others alone, because a window's bytes are bound to the head beside them and a head that has
    since grown cannot be reproduced.

    Every entry must come back proved. A window with holes is a different sample than the one described, and
    selection bias inside a transparency fixture is the last thing it needs.
    """
    origin = origin.rstrip("/")
    tree_head, key, source = head_and_key(origin)
    first = start if start is not None else tree_head.tree_size // 2
    rows = window(origin, first, count)
    if len(rows) < count:
        raise SystemExit(f"{origin}: asked for {count} entries at {first}, got {len(rows)}")

    entries = []
    for index, leaf, extra in rows:
        got = inclusion_block(origin, leaf, tree_head)
        if got is None or got["leaf_index"] != index:
            raise SystemExit(f"{origin}: entry {index} is not proved, so the window is not written")
        entries.append(
            {
                "index": index,
                "leaf_input": base64.b64encode(leaf).decode(),
                "extra_data": base64.b64encode(extra).decode(),
                "identity": identity(leaf, extra).hex(),
                "inclusion": got,
            }
        )

    out.mkdir(parents=True, exist_ok=True)
    path = out / WINDOW_FILE
    document = _load_windows(path)
    document["tool"] = "certledger/tools/corpus.py --window"
    document["why"] = (
        "the CA layer away from position 0. The prefix corpus says how many issuers begin a tree; this says how "
        "many appear in the middle of one, each entry proved into that tree by its own path."
    )
    document["transport"] = {
        "verified": False,
        "why": "no anchor decision exists yet, so TLS is not trusted; the bytes are believed because a "
        "published key signed a tree that contains them",
    }
    windows = [w for w in document.get("windows", []) if w["log"]["origin"] != origin]
    windows.append(
        {
            "log": {"origin": origin, "head": head_block(tree_head, key, source)},
            "window": {"start": first, "count": len(entries), "chosen_by": "tree_size // 2"},
            "entries": entries,
        }
    )
    document["windows"] = sorted(windows, key=lambda w: str(w["log"]["origin"]))
    document["captured"] = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"wrote {path} ({path.stat().st_size} bytes): {len(document['windows'])} windows, "
        f"newest {len(entries)} proved entries at {first} ({origin})"
    )
    return 0


def head_from_block(stored: dict, origin: str) -> ctsth.SignedTreeHeadV1:
    """A stored head block, re-verified against the key stored beside it.

    A proof bound to a tree size that nobody attests is worth nothing, so before asking for any path this
    re-checks the head the log block already carries: an ECDSA signature over these exact octets, from the key
    that hashes to the log id named in the same block. Doing it here rather than trusting `key_source` is what
    lets a reader months later tell a stale fixture from a tampered one.
    """
    head = ctsth.SignedTreeHeadV1(
        timestamp=int(stored["timestamp"]),
        tree_size=int(stored["tree_size"]),
        root_hash=bytes.fromhex(stored["root_hash"]),
        signature=base64.b64decode(stored["signature"]),
    )
    key = EcdsaKey.from_spki(base64.b64decode(stored["key_spki"]))
    ctsth.verify(head, key)
    if key.log_id.hex() != stored["log_id"]:
        raise RuntimeError(f"{origin}: stored key hashes to a log id the block does not name")
    return head


def inclusion_block(origin: str, leaf: bytes, head: ctsth.SignedTreeHeadV1) -> dict | None:
    """A path from one leaf to `head`'s root, or None if the log will not give one that verifies.

    RFC 6962 section 4.5 defines `get-proof-by-hash` with `hash` and `tree_size` as its inputs and
    `leaf_index` plus `audit_path` as its outputs. The tree size asked for is the one the stored head names,
    not the log's current size: binding a path to a head that post-dates the capture would make the fixture
    claim something about a tree it never saw.
    """
    digest = merkle.leaf_hash(leaf)
    # Quote the hash. Of the two peer hashes this pass asked about, the one containing a `+` came back 400
    # while the one containing `/` and `=` was served: a query string reads `+` as a space, which is no longer
    # base64, so the log was right to refuse it. Un-quoted base64 looks like an endpoint that does not work,
    # which is the mistake this repository has already made once with a different URL.
    encoded = urllib.parse.quote(base64.b64encode(digest).decode(), safe="")
    body = get_json(f"{origin}/ct/v1/get-proof-by-hash?hash={encoded}&tree_size={head.tree_size}")
    path = tuple(base64.b64decode(node) for node in body.get("audit_path", []))
    index = int(body["leaf_index"])
    if not merkle.verify_inclusion(digest, index, head.tree_size, path, head.root_hash):
        return None
    return {
        "leaf_index": index,
        "tree_size": head.tree_size,
        "audit_path": [node.hex() for node in path],
        "verifies": True,
    }


def prove_peers(path: pathlib.Path) -> int:
    """Bind each peer entry to the head already stored in its block, without re-capturing anything.

    Re-running the capture would move the prefix and every count the documentation draws from it; the proofs
    are additive, so this loads the fixture, asks each log for a path to the tree size its own stored head
    names, verifies it, and writes it back. A block's `verified` becomes true only when *every* entry in it
    carries a verifying path - one unproved entry keeps the whole block unproved, because a flag that means
    "mostly proved" means nothing to a reader deciding what it may cite.

    The prefix half is left alone deliberately: its root is proved consistent with a signed head, which binds
    all of its entries at the cost of one request.
    """
    document = json.loads(path.read_text(encoding="utf-8"))
    unproved = []
    for block in document["logs"]:
        if "prefix" in block:
            continue
        head = head_from_block(block["head"], block["origin"])
        proved = 0
        for entry in block["entries"]:
            leaf = base64.b64decode(entry["leaf_input"])
            try:
                got = inclusion_block(block["origin"], leaf, head)
            except Exception as exc:
                print(f"  {block['origin']} entry {entry['index']}: {type(exc).__name__}: {exc}")
                got = None
            if got is not None and got["leaf_index"] == entry["index"]:
                entry["inclusion"] = got
                proved += 1
            else:
                entry.pop("inclusion", None)
                unproved.append(f"{block['origin']}#{entry['index']}")
        block["verified"] = proved > 0 and proved == len(block["entries"])
        print(
            f"  {block['origin']}: {proved}/{len(block['entries'])} peer entries proved by inclusion"
        )
    document["proved"] = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path} ({path.stat().st_size} bytes); unproved: {unproved or 'none'}")
    return 0


def read_block(
    origin: str, wanted: int
) -> tuple[list[tuple[int, bytes, bytes, bytes]], ctsth.SignedTreeHeadV1, EcdsaKey, str]:
    """(entries, head, key, key source) for a log's first `wanted` leaves, identities computed once."""
    tree_head, key, source = head_and_key(origin)
    batch = prefix(origin, wanted)
    rows = []
    for index, item in enumerate(batch):
        leaf = base64.b64decode(item["leaf_input"])
        extra = base64.b64decode(item["extra_data"])
        rows.append((index, leaf, extra, identity(leaf, extra)))
    return rows, tree_head, key, source


def size_to_keep(
    rows: list[tuple[int, bytes, bytes, bytes]], shared: set[bytes], floor: int
) -> int:
    """The shortest prefix that still contains a duplicate of either kind, and never less than `floor`.

    A fixture chosen by a round number demonstrates whatever it happens to contain. This one is chosen by
    where the duplicates actually are, so the store's tests have real cases rather than a probability.
    """
    seen: set[bytes] = set()
    deepest = 0
    for index, _, _, value in rows:
        if value in seen or value in shared:
            deepest = max(deepest, index)
        seen.add(value)
    return min(max(deepest + 1, floor), len(rows))


def duplicates_within(rows: list[tuple[int, bytes, bytes, bytes]], within: int) -> list[list[int]]:
    """Index pairs inside the kept prefix that carry the same certificate identity."""
    first_seen: dict[bytes, int] = {}
    found: list[list[int]] = []
    for index, _, _, value in rows[:within]:
        if value in first_seen:
            found.append([first_seen[value], index])
        else:
            first_seen[value] = index
    return found


def entry_rows(rows: list[tuple[int, bytes, bytes, bytes]]) -> list[dict]:
    return [
        {
            "index": index,
            "leaf_input": base64.b64encode(leaf).decode(),
            "extra_data": base64.b64encode(extra).decode(),
            "identity": value.hex(),
        }
        for index, leaf, extra, value in rows
    ]


def primary_block(origin, rows, tree_head, key, source, size, proof) -> dict:
    """The verified half of the corpus: a prefix, its root, and the proof that binds it to the head."""
    return {
        "origin": origin,
        "verified": True,
        "head": head_block(tree_head, key, source),
        "prefix": {
            "size": size,
            "root_hash": merkle.tree_hash([leaf for _, leaf, _, _ in rows[:size]]).hex(),
            "consistency_proof": [node.hex() for node in (proof or [])],
            "consistent_with_head": proof is not None,
        },
        "duplicate_pairs": duplicates_within(rows, size),
        "entries": entry_rows(rows[:size]),
    }


def peer_block(origin, rows, tree_head, key, source, shared: set[bytes]) -> dict:
    """Another log's entries whose identities the verified prefix also carries.

    Written with `verified: false`, because at this point they are only positional evidence: they put a real
    certificate behind the cross-log half of `cl.dedupe`, and the flag stops a reader treating them as more
    than that. `prove_peers` then asks each log for an inclusion path to the head stored in this very block
    and flips the flag only if every entry verifies, so a false flag here means the request was refused, not
    that it was never made.
    """
    kept = [row for row in rows if row[3] in shared]
    print(f"  {origin}: {len(kept)} certificates shared with the prefix")
    return {
        "origin": origin,
        "verified": False,
        "head": head_block(tree_head, key, source),
        "entries": entry_rows(kept),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path("tests/fixtures"))
    parser.add_argument(
        "--origin",
        default="https://ct.cloudflare.com/logs/nimbus2027",
        help="log to take the verified prefix from; it should contain a duplicate of its own",
    )
    parser.add_argument(
        "--peers",
        nargs="*",
        default=["https://tiger2027h1.ct.sectigo.com"],
        help="other logs to look for the same certificates in",
    )
    parser.add_argument("--entries", type=int, default=256, help="how many prefix entries to read")
    parser.add_argument("--floor", type=int, default=64, help="smallest prefix to keep regardless")
    parser.add_argument(
        "--prove-only",
        action="store_true",
        help="add get-proof-by-hash paths to the existing fixture without re-capturing it",
    )
    parser.add_argument(
        "--window",
        type=int,
        metavar="COUNT",
        help="capture COUNT proved entries from the middle of --origin and write midwindow-corpus.json",
    )
    parser.add_argument(
        "--start", type=int, help="leaf index to start the window at (default: midpoint)"
    )
    args = parser.parse_args()
    if args.window:
        return capture_window(args.out, args.origin, args.window, args.start)
    if args.prove_only:
        return prove_peers(args.out / "entry-corpus.json")

    origin = args.origin.rstrip("/")
    print(f"reading {args.entries} entries from {origin}")
    primary_rows, primary_head, primary_key, primary_source = read_block(origin, args.entries)
    peers = [(url.rstrip("/"), *read_block(url.rstrip("/"), args.entries)) for url in args.peers]

    primary_ids = {value for _, _, _, value in primary_rows}
    shared = {
        value
        for _, peer_rows, _, _, _ in peers
        for _, _, _, value in peer_rows
        if value in primary_ids
    }
    size = size_to_keep(primary_rows, shared, args.floor)
    root = merkle.tree_hash([leaf for _, leaf, _, _ in primary_rows[:size]])
    proof = consistency(origin, size, root, primary_head)
    print(
        f"  kept {size} of {len(primary_rows)} entries, root {root.hex()[:16]}..., "
        f"consistent={'yes' if proof else 'NO'}, "
        f"own duplicates: {duplicates_within(primary_rows, size)}, shared with peers: {len(shared)}"
    )

    kept_ids = {value for _, _, _, value in primary_rows[:size]}
    blocks = [
        primary_block(origin, primary_rows, primary_head, primary_key, primary_source, size, proof)
    ]
    for url, rows, head, key, source in peers:
        blocks.append(
            peer_block(url, rows, head, key, source, {v for _, _, _, v in rows if v in kept_ids})
        )

    document = {
        "captured": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "tool": "certledger/tools/corpus.py",
        "transport": {
            "verified": False,
            "why": "no anchor decision exists yet, so TLS is not trusted; the bytes are believed because a "
            "published key signed a tree that contains them",
        },
        "logs": blocks,
    }
    if not proof:
        print(
            "refusing to write a corpus whose prefix is not proved consistent with the signed head"
        )
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / "entry-corpus.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path} ({path.stat().st_size} bytes)")
    # A fresh capture proves its peers too: a fixture that could be proved and wasn't is indistinguishable
    # from one whose proofs were refused, which is the distinction the whole cross-log half rests on.
    return prove_peers(path)


if __name__ == "__main__":
    raise SystemExit(main())
