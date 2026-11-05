# certledger architecture

Status: **design, 2026-11-05.** `TRUST-MODEL.md` decides *why* each control exists and which
adversary it closes; this file decides *how* the system is assembled. Where they disagree,
the trust model wins - it owns the security properties, and this document is an attempt to
satisfy them without inventing new ones.

Position: Tier 1, wave 1 onwards. Obligations and exit tests are in `ROADMAP.md`.

## Components

```
acquire/   paths -> raw bytes + receipts     (never trusts a transport for authenticity)
verify/    log signatures, trees, proofs     (the only component with a security claim)
store/     entries, heads, receipts, list    (append-only, content-addressed)
index/     CA graph, leaf tail, name maps    (read-only projections, rebuildable)
publish/   query API, dashboards, anomalies  (gated by corroboration and state)
```

`verify/` is the piece that matters. Everything else can be wrong and merely produce a bad
answer; `verify/` being wrong produces a **wrong answer that looks authoritative**, and being
authoritative is the entire product. Consequences:

- Verification lives in this repository with no plugin or extension point, and no runtime
  dependency is allowed to decide a trust outcome (trust model I10).
- Verification consumes the **stored original bytes** of every object, never a re-encoding
  (I3). This is why `asn1core` is a hard dependency rather than a convenience: the codec
  available today discards those bytes, and the corpus in `asn1core/VECTORS.md` is the gate.
- A failure to verify is a distinct stored state. It is never collapsed into "no data" (I8).

## Objects

| Object | Identity | Must retain | Notes |
|---|---|---|---|
| `Entry` | SHA-256 of the TBSCertificate | original DER, issuer SPKI, subject SPKI, `cA` flag, names, validity, policy OIDs, name constraints | **entry is not certificate**: one certificate appears in several logs, so raw counts are meaningless without the dedupe |
| `TreeHead` | (log id, tree size) | the signed checkpoint or STH bytes, verification result, predecessor link | monotonic per log; a decrease is an incident, not a data error (I4) |
| `Receipt` | (fetch id) | path id, vantage, AS, timestamp, peer address, peer SPKI, response-bytes hash, proof it was not proxied | the artefact nobody else publishes; without it a claim is unpublishable (I6) |
| `LogIdentity` | log id | pinned public key, origin URL, state, date pinned, who decided | a key change freezes publication and needs a human (trust model §8) |
| `DenyListItem` | SPKI hash | proof artifact bytes, signature, commit and inclusion proofs, dates | arrives from `keyproof`; monotone, never expires |

## Two tiers, because they are different problems

The corpus is billions of entries - one half-year log held about 242 million when measured
on 2026-11-05. Storing and indexing all of it first is the classic way this project fails.

**Tier A - the CA layer, held in full.** Every entry with `cA=TRUE`. Its true cardinality is
a measurement we do not have yet (trust model §11), but it is orders of magnitude smaller
than the leaf layer, and it answers the questions nobody else can: what did this key issue;
which keys share an SPKI across two roots; whose name constraints are violated; which
issuers produce certificates outliving browser policy; what is the serial-number entropy per
CA; how fast is each CA issuing. This is the first publishable artefact, it needs no
own-stack work, and it is the query `crt.sh` could not answer during the incident - a search
for a compromised intermediate's common name returned "Certificates None found".

**Tier B - the leaf tail, streamed forward from today**, partitioned by (issuer SPKI, month),
deduplicated by TBS hash, with historical backfill only for keys implicated by an incident.
Partitioning by issuer SPKI is not a performance guess; it is forced by the access pattern,
because the incident-shaped question is always "everything these keys issued".

The storage engine for Tier B stays undecided until Tier A is measured. Naming one now would
be a preference dressed as an engineering conclusion.

## The acquisition loop

Steady state, per log, per interval:

1. Fetch the current head over each configured path.
2. Verify the signature against the pinned key. Never against a key discovered on this path.
3. Compare with the stored head. Equal means `STALE` once beyond budget. Greater requires a
   consistency proof, which is verified. **Less means stop and page**, never clamp.
4. Fetch new ranges, writing raw response bytes to storage before parsing anything.
5. Write one receipt per fetch per path, including for failures.
6. Diff what two paths returned for the same range. Any disagreement sets `DIVERGENT` for
   that log and range, freezes publication for it, and keeps fetching - the disagreement is
   itself data worth publishing.
7. Record rate limits and cost pressure as `UNREACHABLE` with a recorded gap. The gap is part
   of the completeness record; pretending it did not happen is how a completeness claim turns
   into a lie.

Absence is asserted only from a completed walk or from two path-class replicas (I5). Any
single-path answer says, in the response itself: "not in my copy, which is one path, complete
up to head H".

## Paths as a first-class interface

A path is a configured object, not a function call. Each carries an identifier, a trust
class, a vantage (hosting provider, region, autonomous system), its own anchors, its own
resolver, and its own failure and disagreement history. Responsibilities:

- Resolve with its own resolver, connect to **the address it resolved**, then assert the peer
  address equals the chosen one. Without that assertion "we use our own resolver" is theatre:
  the OS resolver still picked the destination.
- Never read proxy or certificate-store environment variables, and record that it did not
  (I1). Concretely: no default CA loading, an explicitly built context holding only our
  anchors, and every HTTP client constructed with environment trust switched off, because the
  defaults honour `HTTPS_PROXY` and `SSL_CERT_FILE` without being asked.
- Emit a receipt for every fetch.
- Rate-limit itself against each log's tolerance rather than discovering it in production.

Two properties of the *set* matter more than any individual path: a publishable observation
needs two paths from different classes, and at least one path used for completeness claims
must not traverse the local network at all. Otherwise one adversary filters both of our
"independent" views identically, which is precisely the failure the replica diff exists to
catch.

## Deliberately not built

- **No live-web certificate scanning.** In-the-wild observation is the only way to see
  unlogged issuance, and it is a different dataset with different costs and legal exposure.
  Until it exists, the coverage description in trust model §9 is the honest one, and
  `cl.claims-discipline` exists to stop the marketing outrunning it.
- **No CT log server.** We audit logs; we do not become one. Running a log would place us
  inside the attack surface we are watching, with an availability obligation to issuers.
- **No CT enforcement in a non-Chrome TLS client using Chrome's log list.** Its
  acceptable-use policy permits monitor and auditor use, forbids the other without written
  permission, and reserves unannounced changes intended to disrupt unauthorised use. Legal
  review is obligation `cl.aup-review`: a launch gate, not a footnote.
- **No accounts, auth, or paid tier in v1.** Query volume is the threat model; a rate-limited
  read-only API plus a bulk export covers the useful cases.
- **No general CA store.** Around a dozen log origins are contacted and all are pinnable.
  Maintaining a bundle would recreate the update lag that left Electron apps exposed during
  the incident, and would accidentally turn this into a CA-bundle project.

## Public surface

Every response carries its state and its receipts, because an auditor's output that cannot
be interrogated about how it was obtained is just an opinion with better typography.

| Endpoint | Returns | Constraint |
|---|---|---|
| `/ca/{spki}/issued` | everything those keys issued, with validity | corroborated only |
| `/ca/{spki}/keys` | SPKIs shared across issuers, cross-signs | - |
| `/logs/{id}/head` | pinned head, growth history, verification state | per-path receipts |
| `/entry/{tbs-hash}/logs` | which logs contain this certificate | dedupe-aware |
| `/anomalies` | published findings | gated by I7: two path classes, cited spec with errata checked, named reproducing test |
| `/denylist` | compromised SPKIs consumed from `keyproof` | monotone, no expiry |

## Open decisions

1. **Storage engine for Tier B**, after Tier A is measured. This is the one decision that a
   wrong early answer makes expensive to reverse.
2. **Second vantage**: hosting in a different autonomous system is the only way to satisfy
   rule 2 of the path set. It costs money and is the main reason phase 4 is phase 4.
3. **Do we accept submissions** (a CA sending us data directly) or only fetch? Accepting
   creates a data-source trust question that fetching does not have.
4. **Whether to publish absence at all** before a full walk of every usable log exists. The
   conservative answer is no, and it is also the answer that makes the service less
   interesting; that tension should be decided explicitly rather than by drift.

