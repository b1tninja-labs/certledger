# certledger roadmap

This is the obligation-level plan for the service described in `TRUST-MODEL.md`. The
trust model decides *why* each row exists and which adversary it closes; this table is
what gets worked on. The rule inherited from the rest of the portfolio applies: a row
moves to done only when the named test exists and passes.

Position: **Tier 1**, wave 1 onwards. Depends on `asn1core` for byte-faithful DER
handling and `ctspy` for the CT data structures; consumes `namespy` for resolution
rather than writing a resolver.

## Obligations

**Read this before citing a specification here.** RFC 6962 is **Obsolete** (it was
Experimental, published 2013-06, and carries one verified erratum). The current document
is **RFC 9162, Certificate Transparency Version 2.0**, published 2021-12, which obsoletes
it - and 9162 is itself **Experimental**, not a Standard, with one erratum on file. The
protocol this service depends on was never standardised by the IETF, which is a property
of the design space rather than a footnote: the deployed wire format at logs today is
version 1, and version 2 replaces signed tree heads with checkpoints and changes the TLS
extension. Cite 9162 as the authority and 6962 only when naming what a v1 log actually
sends. Verify against the record rather than memory: `info('RFC9162')`,
`errata('RFC9162')`, `read('RFC9162', view='normative')`.

| Id | Spec | Status | Where | Evidence |
|---|---|---|---|---|
| `cl.ambient-trust` | Model I1 | [x] | `anchors.py`, `context.py`, `path.py` | `test_environment_is_ignored` |
| `cl.peer-assert` | Model L1 | [x] | `transport.py`, `path.py` | `test_peer_address_is_asserted` |
| `cl.der-fidelity` | Model I3 | [x] | `der.py` | `test_signature_uses_stored_bytes` |
| `cl.key-pins` | RFC 9162 section 3 | [x] | `keys` | `test_unknown_key_is_rejected` |
| `cl.sth-verify` | RFC 9162 section 2.1.1; v1 head: 6962 section 3.5, obsolete | [x] | `verify/tree` | `test_sth_signature_round_trip` |
| `cl.monotonic` | RFC 9162 section 2.1.1 | [x] | `verify/tree` | `test_smaller_tree_is_rejected` |
| `cl.consistency` | RFC 9162 section 2.1.1 | [x] | `verify/proofs` | `test_mstc_rejects_bad_proof` |
| `cl.inclusion` | RFC 9162 section 2.1.2 | [x] | `verify/proofs` | `test_mth_and_audit_path` |
| `cl.receipts` | Model I6 | [x] | `store/receipt` | `test_every_object_has_a_receipt` |

Phase 1 lives in two new modules: `certledger/keys.py` (the pin registry and the origin-keyed lookup)
and `certledger/heads.py` (monotonic head store, consistency on growth, inclusion bound to an
accepted head). Both depend on `ctspy` for the signature and Merkle layers rather than reimplementing
them, which is the reason that library exists.

Two things this does **not** claim. The shipped `keys/pins.toml` is empty: the real production keys in
`tests/fixtures/log-pins.toml` are test material, and trust model section 8 reserves a key decision
for a named human, so the deployment ring stays empty until one is recorded. And nothing in the package
fetches: these modules verify artifacts that are handed to them, so the acquisition loop that produces
those artifacts over an asserted path (`cl.walk-budget`, `cl.multi-path`) is still open. What does fetch is
`tools/corpus.py`, a capture tool outside the package, and its output says so - `transport.verified` is
false because there is no anchor decision to verify TLS against, and the bytes are believed anyway, because
a published key signed a tree that contains them.

| `cl.dedupe` | RFC 6962 section 2.1 | [x] | `store/entries` | `test_entry_count_differs_from_cert_count` |
| `cl.walk-budget` | Model I5, section 8 | [ ] | `acquire/walk` | `test_gap_is_recorded_as_unreachable` |
| `cl.cag-graph` | - | [x] | `store/cag` | `test_ca_layer_reconciles_with_tree_size` |
| `cl.multi-path` | Model I7 | [ ] | `acquire/fanout` | `test_absence_needs_two_path_classes` |
| `cl.states` | Model section 8 | [ ] | `store/state` | `test_divergent_is_not_publishable` |
| `cl.keyproof-consume` | keyproof PLAN, ladder rung 1 | [ ] | `verify/denylist` | `test_chain_with_listed_spki_is_flagged` |
| `cl.dane` | RFC 6698 as updated | [ ] | `fetch/dane` | `test_impostor_endpoint_is_unauthenticated` |
| `cl.self-transparency` | Model I9 | [ ] | `publish/checkpoints` | `test_our_checkpoint_is_mirrored` |
| `cl.aup-review` | Chrome log-list AUP | [ ] | docs | legal sign-off recorded with a date |
| `cl.claims-discipline` | Model section 9 | [ ] | docs, UI | copy review: no "all certificates" claim |

## Why this ordering

`cl.ambient-trust`, `cl.peer-assert` and `cl.der-fidelity` come first because they are
the cheapest rows that remove a whole adversary: A2, the attacker who today needs only
an environment variable and no access to this code. `cl.multi-path` is deliberately late
- it needs a second vantage, which is money and not code - but note that until it lands,
**no absence claim is supportable**, so the service must not make one.

## What this project will not claim

CT cannot see unlogged issuance, and the October 2026 incident's own diagnostics
depended on chains that were never logged. Detecting that requires in-the-wild
observation, a separate dataset with separate costs. Until then the honest description is
"every TLS certificate that was logged, plus what has been revoked, and the delta between
them", and `cl.claims-discipline` exists to keep the marketing from outrunning that.

## Status, 2026-11-05

**Phase 0 is done.** `cl.ambient-trust`, `cl.peer-assert` and `cl.der-fidelity` closed with the
tests named against them: 30 tests green under `pytest`, `ruff check`, `ruff format --check` and
`mypy --strict`, 97% coverage.

They run against live loopback sockets rather than mocks - a TLS server on 127.0.0.1 with a
throwaway CA, a listener where a configured proxy would have gone, and a second TLS endpoint on
127.0.0.2 so that a connection to the wrong address genuinely *succeeds* and can then be refused for
the right reason. `SSL_CERT_FILE` is pointed at a CA that would verify the server, because pointing
it at garbage would pass for an implementation that honoured it.

Two things learned while building it, both of which change how a control looks rather than whether
it exists:

- **`http.client` rather than `urllib` is what makes "no proxy" structural.** `urllib.request` reads
  `HTTPS_PROXY` unless handed an empty `ProxyHandler`; `requests` and `httpx` read it unless
  `trust_env=False`. `http.client` never consults the environment. A control that depends on
  remembering a keyword argument is a control that eventually gets remembered wrong.
- **Peer identity must be taken at the handshake.** `http.client` closes the connection once a
  non-keep-alive response is drained, so a receipt built after `read()` records "no peer" for a
  fetch that worked perfectly.

**Phase 1 is blocked on a decision, not on effort.** Its exit test needs STH and checkpoint
structures, which `PORTFOLIO.md` section 6 assigns to `ctspy` - a Tier 2 project that does not exist
yet. Either `ctspy` moves up, or the Merkle and transcript code is written here and later extracted.
That is a sequencing call for the human, so it is recorded rather than assumed.

**Phase 2 has started with the two rows that consume entries.** `entries.py` gives an Entry the identity
PLAN.md specifies - SHA-256 over the TBSCertificate - and it is tested on a prefix rather than a sample: 236
entries of Cloudflare Nimbus2027 whose root is proved consistent with the tree head the log signed under a
pinned key (`tools/corpus.py` writes `tests/fixtures/entry-corpus.json`; the fixture is 1.5 MB of bytes two
operators served). Those 236 entries establish **235 identities** - one certificate is in that log twice, and
two more certificates also appear in Sectigo Tiger2027h1 - so the row's claim is measured rather than
assumed. It is also smaller than the sentence implies: across 23 operational logs, the largest overlap
between two logs' *verifiable* prefixes was 2 certificates, because a prefix is a log's oldest content and
static-merge logs inherit disjoint sources. Cross-log duplication is real and rare in the part of a log a
monitor can prove anything about.

The CA graph over the same prefix draws 236 edges from 4 issuing keys, and **8 entries claim `cA=TRUE`** -
3.4% of the sample. That is one data point against PLAN.md's unmeasured Tier A cardinality, and nowhere near
an estimate for a 242-million-entry half-year.

Two rules came out of the measurement and are now load-bearing in the code. A precert entry is attributed to
the leaf's `issuer_key_hash`, never to `chain[0]`: across 494 production precerts in five logs, 173 had a
Precertificate Signing Certificate first in their chain, and the corpus contains 13 such entries, each of
which the graph must place under the real CA. And a precert entry's *identity* comes from the leaf's
`TBSCertificate` rather than the stored precertificate, because RFC 6962 section 3.2 paragraph 9 rewrites the
issuer and Authority Key Identifier of that stored copy - keying on it would split one certificate into
several identities, which is the failure this row exists to prevent. Both are documented in
`ctspy/docs/interop.md`, which also records the two wrong answers held before these were right.

What the corpus does not settle: no entry in it embeds an SCT list, so the case where one issuance has two
TBSCertificate spellings - with and without that extension - is untested on production bytes here.
`has_sct_extension` records it per entry and `EntryStats.sct_bearing` counts it, so folding them stays a
decision made against a number. The walk itself remains gated on `cl.walk-budget`, `cl.multi-path`, and the
anchor decision.


## Known costs


One half-year Google log held about 242 million entries when measured on 2026-11-05, so
entries and certificates are different counts by design. Per-log rate limits, the real
cardinality of the `cA=TRUE` layer, and whether public archives cover every currently
usable log are all unmeasured; each is a phase-2 blocker rather than a footnote, and
`TRUST-MODEL.md` section 11 tracks them. The first two data points on the CA layer landed with
`cl.cag-graph`: 8 of 236 entries in a verified Nimbus2027 prefix carry `cA=TRUE`, and 236 entries drew edges
from 4 issuing keys - a ratio, not an estimate, and recorded as such. Google answers 32 entries per
`get-entries` request however many are asked for (RFC 6962 section 4.6 permits this), which sets the walk's
request count: about 7.6 million requests for one such half-year log.
