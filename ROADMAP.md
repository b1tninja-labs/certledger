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
| `cl.ambient-trust` | Model I1 | [ ] | `fetch/anchors` | `test_environment_is_ignored` |
| `cl.peer-assert` | Model L1 | [ ] | `fetch/path` | `test_peer_address_is_asserted` |
| `cl.der-fidelity` | Model I3 | [ ] | `verify` | `test_signature_uses_stored_bytes` |
| `cl.key-pins` | RFC 9162 section 3 | [ ] | `keys` | `test_unknown_key_is_rejected` |
| `cl.sth-verify` | RFC 9162 section 2.1.1; v1 head: 6962 section 3.5, obsolete | [ ] | `verify/tree` | `test_sth_signature_round_trip` |
| `cl.monotonic` | RFC 9162 section 2.1.1 | [ ] | `verify/tree` | `test_smaller_tree_is_rejected` |
| `cl.consistency` | RFC 9162 section 2.1.1 | [ ] | `verify/proofs` | `test_mstc_rejects_bad_proof` |
| `cl.inclusion` | RFC 9162 section 2.1.2 | [ ] | `verify/proofs` | `test_mth_and_audit_path` |
| `cl.receipts` | Model I6 | [ ] | `store/receipt` | `test_every_object_has_a_receipt` |
| `cl.dedupe` | RFC 6962 section 2.1 | [ ] | `store/entries` | `test_entry_count_differs_from_cert_count` |
| `cl.walk-budget` | Model I5, section 8 | [ ] | `acquire/walk` | `test_gap_is_recorded_as_unreachable` |
| `cl.cag-graph` | - | [ ] | `store/cag` | `test_ca_layer_reconciles_with_tree_size` |
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

## Known costs

One half-year Google log held about 242 million entries when measured on 2026-11-05, so
entries and certificates are different counts by design. Per-log rate limits, the real
cardinality of the `cA=TRUE` layer, and whether public archives cover every currently
usable log are all unmeasured; each is a phase-2 blocker rather than a footnote, and
`TRUST-MODEL.md` section 11 tracks them.
