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
| `cl.inclusion` | RFC 9162 section 2.1.2 | [x] | `verify/proofs` | `test_mth_and_audit_path`, and a production path bound to an accepted head in `test_a_peer_entry_is_proved_into_its_own_log_by_an_audit_path` |
| `cl.receipts` | Model I6 | [x] | `store/receipt` | `test_every_object_has_a_receipt` |
| `cl.dedupe` | RFC 6962 section 2.1 | [x] | `store/entries` | `test_entry_count_differs_from_cert_count` |
| `cl.walk-budget` | Model I5, section 8 | [x] | `acquire/walk` | `test_gap_is_recorded_as_unreachable` |
| `cl.cag-graph` | - | [x] | `store/cag` | `test_ca_layer_reconciles_with_tree_size` |
| `cl.multi-path` | Model I7 | [ ] | `acquire/fanout` | `test_absence_needs_two_path_classes` |
| `cl.states` | Model section 8 | [x] | `store/state` | `test_divergent_is_not_publishable` |
| `cl.keyproof-consume` | keyproof PLAN, ladder rung 1 | [ ] | `verify/denylist` | `test_chain_with_listed_spki_is_flagged` |
| `cl.dane` | RFC 6698 as updated | [ ] | `fetch/dane` | `test_impostor_endpoint_is_unauthenticated` |
| `cl.self-transparency` | Model I9 | [ ] | `publish/checkpoints` | `test_our_checkpoint_is_mirrored` |
| `cl.aup-review` | Chrome log-list AUP | [ ] | docs | legal sign-off recorded with a date |
| `cl.claims-discipline` | Model section 9 | [ ] | docs, UI | copy review: no "all certificates" claim |

Nineteen obligations, thirteen closed with a named test, six waiting on something named beside them. The
table used to read "18" while carrying nineteen rows, which is the sort of error a count kept in prose rather
than derived from the rows makes by itself.

Phase 1 lives in two new modules: `certledger/keys.py` (the pin registry and the origin-keyed lookup)
and `certledger/heads.py` (monotonic head store, consistency on growth, inclusion bound to an
accepted head). Both depend on `ctspy` for the signature and Merkle layers rather than reimplementing
them, which is the reason that library exists.

Two things this does **not** claim. The shipped `keys/pins.toml` is empty: the real production keys in
`tests/fixtures/log-pins.toml` are test material, and trust model section 8 reserves a key decision
for a named human, so the deployment ring stays empty until one is recorded. And nothing in the package
fetches: these modules verify artifacts that are handed to them, so the acquisition loop that produces
those artifacts over an asserted path (`cl.multi-path`) is still open. What does fetch is
`tools/corpus.py`, a capture tool outside the package, and its output says so - `transport.verified` is
false because there is no anchor decision to verify TLS against, and the bytes are believed anyway, because
a published key signed a tree that contains them.

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

`cl.walk-budget` closed the same phase as a mechanism, and its content is three refusals rather than a loop.
A **short page is a cap, not the end of the tree**: Google answers 32 entries however many are requested
(measured here; RFC 9162 section 5.6 paragraph 8 permits it and v1's section 4.6 said the same), so the walk
learns the observed cap,
continues from the first index it did not receive, and stops only at the signed `tree_size`. A loop that read
a short response as exhaustion would report a 32-entry tree for a log whose captured head signs
872,937,158 entries, and its report would look complete. A **body that is not JSON, or JSON with no `entries`
array, is `UNREACHABLE` and not an empty range**: that distinction is all of I5's rule that a failed fetch
records the absence of a
fetch, and `document.get("entries", [])` is how a rate limiter's HTML page becomes "this log had nothing
there". And **completeness is a hash equality, not a count** - leaves 0..tree_size-1 whose Merkle Tree Hash
equals the signed root cannot be missing one, which is why one path can support an absence claim about
*position* while it can never support one about *content*.
`test_counting_entries_alone_never_declares_a_walk_complete` pushes one mutated leaf through every counter in
the report (right number of entries, right positions, no gaps, no failures) and only the root disagrees.

Two gap states came out of writing it wrong first. A position re-served with different bytes is `CONFLICT`,
which makes `complete` False even when the store happens to hold a whole tree: two versions of one position
is the state table's `DIVERGENT` case, and freezing is the prescribed behaviour. One entry whose base64 will
not decode costs exactly **one position** and the walk carries on - the first draft called that a conflict
too, which would have let a single malformed field freeze a healthy log. `may_claim_absent` answers False
unless the walk completed, and `test_no_absence_claim_survives_a_real_tree_size` runs it against Nimbus2027's
own accepted head, where two pages of real entries leave a gap of 872,937,094 entries and no index in that
tree can honestly be called absent.

Checking the citations against the record rather than trusting memory then corrected one claim made in that
same commit. RFC 9162 section 5.6 paragraph 9 **mandates** an empty `entries` array when skew leaves the log
with nothing in the requested range, and paragraph 7 makes a partial response a MUST where v1 only permitted
one. So `EMPTY_WITHIN_TREE` records two artifacts disagreeing - the accepted head and this response - rather
than a finding about the log, and the wording in `walk.py`, its test and this file was changed to match. The
state itself still earns its keep: an empty array is legal and is still not permission to call the walk
finished.

**Phase 2's exit criterion is not met, and closing the row does not change that.** "A walk of one live log
with its tree size matched against the log's own signed head" needs roughly 27 million requests at Google's
observed page size for this one log, and the fetcher that would issue them cannot run until the anchor
decision recorded in `AGENTS.md` and below is made by a named human. The heads in `tests/test_walk.py` are
signed by throwaway keys over production leaves, because no log will sign an arbitrary prefix on demand; that
makes the completeness *arithmetic* real and the *footing* synthetic, which is said here rather than in a
footnote.

**One phase 3 row landed early, because it is logic rather than infrastructure.** `states.py` is the section 8
table turned into code, and it needs nothing the fetch layer has to offer: it weighs artifacts that already
exist - accepted heads, walk reports, receipts, trust classes. The design decision is that **`assess` is the
only way to produce a state**. There is no argument that accepts `State.VERIFIED`, and `publishable`,
`supports_absence` and `alert` are derived rather than stored, because the way this fails in practice is not a
crash but a reporting layer that sets the field directly and gets it wrong quietly.

The precedence has two orderings that are decisions rather than facts, and each is defended in the module.
`UNREACHABLE` outranks `UNAUTHENTICATED`: a failed handshake also means the endpoint went unvalidated, so if
unauthenticated ranked higher, every timeout in the fleet would be reported as a possible interceptor and the
report would stop being believed when a real one appeared. `STALE` outranks `VERIFIED` even when the content
is corroborated by two classes, because the property at issue is currency and the only way to guarantee a
stale tree is never presented as current is to make staleness destroy the publishable state instead of
annotating it.

Two rules cost the most to encode and are the ones with tests attached. **"Never silently downgrade"** is
implemented as a cap, not a drop: a path that cannot prove its endpoint contributes no corroboration - so two
paths where one is unauthenticated reach `SINGLE_PATH`, never `VERIFIED` - and it raises an alert, because
*that* path disagreeing is what A2 looks like from inside this process, and the honest statement is "we cannot
tell whether the log equivocated or someone intercepted us". **"A freeze survives good news"**: a divergence
or a key change freezes publication, a later corroborated pass stays unpublished while the freeze is active,
and lifting it takes a `HumanDecision` naming a person and a date - refused when the name is blank, the note
too short to audit, or the timestamp has no zone. Clearing lifts the freeze and deliberately does not change
the state, so a `DIVERGENT` observation is never rewritten afterwards.

`test_a_gapped_walk_over_production_entries_supports_no_absence` composes this with the walk on the captured
Nimbus2027 bytes: the same log, the same head, the same single path - one pass with a gap refuses the absence
claim, the resume that closes the gap permits it. Nothing about the log changed between the two calls, only
what has been read of it, which is the entire content of I5.

What this row does **not** close: the phase 3 wiring of these states into a UI, and producing
`UNAUTHENTICATED` from DANE or DNSSEC failure. Here `authenticated` is an input the caller sets from what the
path itself validated; making that determination requires a DANE lookup in `namespy`. That project **is**
implemented - codec, iterative resolver, opt-in DNSSEC validation, DoT and DoH - and this document previously
said it "does not exist yet", which was wrong and is corrected here. What it lacks is the validation path: TLSA
is present as a record type (`namespy/enums.py:260`, RFC 6698 section 3) and nothing consumes it as DANE. The
state, and everything it forbids, is in place for when it does.

Two rules came out of the measurement and are now load-bearing in the code. A precert entry is attributed to
the leaf's `issuer_key_hash`, never to `chain[0]`: across 494 production precerts in five logs, 173 had a
Precertificate Signing Certificate first in their chain, and the corpus contains 13 such entries, each of
which the graph must place under the real CA. And a precert entry's *identity* comes from the leaf's
`TBSCertificate` rather than the stored precertificate, because RFC 6962 section 3.2 paragraph 9 rewrites the
issuer and Authority Key Identifier of that stored copy - keying on it would split one certificate into
several identities, which is the failure this row exists to prevent. Both are documented in
`ctspy/docs/interop.md`, which also records the two wrong answers held before these were right.

What the corpora do not settle: no entry in the prefix corpus embeds an SCT list, and none of the 53
SCT-bearing entries across the three windows has a twin logged under a different `TBSCertificate` spelling, so
folding one issuance's two spellings together remains untested on production bytes. What they *do* settle is
the shape of that gradient, because a third window at 25% depth separates a step from a slope: below the start
of the tree, **every logged certificate embeds SCTs** - 30 of 30 at 25%, 23 of 23 at 50%, 10 of 10 in the
Google log - while none of the 116 logged certificates in the prefix of the same log does. The change lands
somewhere between position 235 and 25% depth and then holds; the *why* is left unestablished rather than
narrated. A *completed* live walk remains gated on `cl.multi-path` and the
anchor decision.


## What is left, and what is blocking it

Six obligations remain open, and most of them wait on a decision or a dependency rather than on code. The
distinction matters: an obligation blocked on a decision has to say which decision and who makes it, or it
quietly becomes a permanent gap dressed as backlog.

| Obligation | Why it is not closed | What would close it |
| --- | --- | --- |
| `cl.multi-path` | Needs two paths with genuinely different properties, and the second vantage point costs money. A second query through the same resolver is not an independent witness, so a test written now would be theatre. | A configured second vantage - another network, another resolver - then `acquire/fanout` separating *refused on both* from *answered differently*. |
| `cl.dane` | DANE records live under DNS names, and `namespy` owns TLS and DNS names; a name layer built here would be a second one to keep honest. Still needs the anchor decision as well. | `namespy` exposing a DANE lookup, consumed behind the same state gate as everything else. |
| `cl.keyproof-consume` | Nothing in the workspace produces a `keyproof` artifact: `keyproof/` is a plan directory with no package. Consuming something that does not exist fixes its shape by accident. | The artifact, then `verify/denylist` makes an assertion unusable when its SPKI hash is listed. |
| `cl.self-transparency` | Largely wiring - `heads.py` already keeps a monotonic head store, and a checkpoint store is that discipline pointed at our own tree - but it needs somewhere to publish, which is infrastructure, not code. | Our own checkpoint served and mirrored elsewhere, with a test that a locally tampered checkpoint is caught by the mirror. |
| `cl.aup-review` | What we may fetch and republish is a contractual question about the log-list inclusion policy. No test can answer it. | A recorded review with a date, and the fetch layer's retention behaviour written to match what it concludes. |
| `cl.claims-discipline` | The discipline is enforced in code and tests - nothing claims "all certificates" - but the operator-facing copy has not been read against it by a person. | A copy review, recorded with who did it and when. |

Two of the six wait on the workspace rather than on this project: `cl.keyproof-consume` needs `keyproof`'s
artifact and `cl.dane` needs `namespy`. Neither should be invented ahead of its wave - writing a consumer for
an artifact that does not exist yet decides its interface by guesswork, which is what `PORTFOLIO.md` section 7
exists to prevent.

One thing the retraction has already paid for. `tools/corpus.py` had captured prefixes only, on the belief that
no log serves an inclusion proof by hash; every log asked has since served one that verifies (see
`ctspy/docs/interop.md`). The tool now asks it: `--prove-only` binds each peer entry to the head stored in that
peer's own block, after re-verifying that head against the key beside it, and the two Sectigo entries in the
corpus carry audit paths that `tests/test_entries.py` re-derives offline through `HeadStore.verify_inclusion`.
That gives `cl.inclusion` its first production anchor and turns the cross-log half of `cl.dedupe` from
positional matching into proved inclusion. It also caught a bug of its own: a leaf hash must be
percent-encoded in the query string, because the `+` in one of the two arrived as a space and the log answered
400 - a refusal that reads exactly like an endpoint that does not work.

## Known costs

One half-year Google log held about 242 million entries when measured on 2026-11-05, so
entries and certificates are different counts by design. **That 242 million does not reconcile with the heads
signed today** - Xenon2027h1 reports 751,798,397 and Argon2027h1 900,273,683 - and the difference is not
explained here, only flagged: `HARVEST-PLAN.md` treats `tree_size` as leaves because that is what it is, and if
the 242 million measured something else, the sentence above should say so. Per-log rate limits and whether public
archives
cover every currently usable log remain unmeasured; each is a phase-2 blocker rather than a footnote, and
`TRUST-MODEL.md` section 11 tracks them. The cardinality of the `cA=TRUE` layer is no longer one of them, and
what it turned out to be is that the question needed a second sample from the same log. `cl.cag-graph` measured
8 CA entries and 4 distinct issuers across a verified 236-entry Nimbus2027 prefix, recorded as "a ratio, not an
estimate". `tools/corpus.py --window` then proved a 64-entry slice at the midpoint of **that same log**: 0 CA
entries and **17 distinct issuers**; a third slice at 25% depth of the same log gives 6, so the count ramps
with depth - 4 at the start, 6 at 25%, 17 at 50% - rather than jumping once, though three points on one log
describe a direction and not a slope. Same operator, same log, same issuance population, with position the only
thing that differs - so the 4 measured how a log begins and could not be quoted as the size of the CA layer,
and the hedge attached to it was carrying far less than it appeared to. A second window at the midpoint of
Google's Xenon2027h1 corroborates the direction (20 issuers) but is not the controlled comparison, because
there operator and log change along with position; `tests/test_midwindow.py` keeps the two in separate tests so
a confounded number cannot be pooled with a clean one. Both samples are small - 64 and 236 entries out of
hundreds of millions - and no rate is claimed from either. Google answers 32 entries per
`get-entries` request however many are asked for (RFC 9162 section 5.6 paragraph 8 permits this), which sets
the walk's request count - and **the page size is per operator, not per protocol**: measured 2026-11-05 by
asking one log per operator for 4,096 entries, **Google and TrustAsia serve 32 while Cloudflare, DigiCert and
Sectigo serve 256** (the sweep is recorded in `ctspy/docs/interop.md`). Nimbus2027 is a Cloudflare log, so its
**877,250,294**-entry head is roughly **3.4 million requests**, while the same arithmetic on a Google half-year
(Xenon2027h1, 751,798,397 entries at 32) is **23.5 million**. Two figures sat on this line before that
measurement: about 7.6 million, which followed from neither input, and then 27.4 million, which divided a
Cloudflare tree by Google's page size. Both were arithmetic done on remembered constants.

`INCIDENT-CT-FORENSICS.md` records what happened when a real incident — the eMudhra intermediate key
compromise — was put to this tooling, and it settled two things that any future forensics ask has to live
with. A v1 tree leaf commits to the log's own submission timestamp, so a leaf hash is not computable from a
certificate: `get-proof-by-hash` proves possession of an entry you already have and can never answer "does
this log hold this certificate", which means an issuance question is answerable only from a store and not
from logs. And no anonymous bulk CT archive was reachable from here, so the walk's cost is not avoidable by
downloading instead.

## Captured ideas, not yet obligations

Recorded here so an idea does not rot in a conversation. Nothing below has an obligation id, and none should get
one until it has an owner and a decision attached - inventing an id is how a wish becomes fake backlog.

### Notifying subscribers about certificates for their hostnames

The shape people asked for: a user registers `example.com` and is told when a certificate appears in CT whose
identifiers fall under it, subdomains included. Two observations first, one encouraging and one not.

**Encouraging: the expensive part is the backfill, not the watching.** Monitoring a log means tailing past the
head it last showed us, and the fleet moves slowly relative to its size - one `ctspy` sweep watched a head go
from 3,024,290,326 to 3,024,290,413, which is 87 leaves across the whole round. Against a 537-million-request
backfill (`HARVEST-PLAN.md`), the steady-state cost of *keeping* an index current is a different order of
magnitude. A service that starts after the backfill is nearly free to run; getting to that point is the whole
bill.

**Not encouraging: this is not an empty space.** `PORTFOLIO.md` section 10 already records CertSpotter as alive
and priced at $15, $100 and $500 a month, with the limitation that it is *domain-scoped monitoring, not an
analysis surface*. So the demand is proven and the competition is live. What a substitute could add is the
thing nobody else attaches to a notification: **coverage and proof.** "This certificate matched your domain, it
is in log L at index I, here is the audit path under the head we journalled, and here are the logs we were not
able to read this hour" is a different product from an email with a hostname in it. The CA-scoped variant is
the one incident response actually wants - "tell me about anything issued by *these* key hashes" - which is
exactly the eMudhra query, needs no domain semantics at all, and reuses `issuer_key_hash` as the match key.

The questions to settle before this becomes anything:

1. **Does a subscriber have to prove control of the domain?** This is the load-bearing one, and the feature's
   value and its harm are the same property. CT data is public, but *aggregated, pushed notification* is a
   discovery channel: it tells the subscriber the moment an internal hostname like `vault-db.corp.example.com`
   gets a certificate, and it tells us - and their mail provider, and any proxy in between - that hostname too.
   Options run from "anyone may watch any name" (CertSpotter's posture) through a DNS-01 style control challenge
   to "watch only the registrable domain you proved". A wrong default here cannot be walked back after the first
   person is harmed by a notification we sent them.
2. **What does a match mean?** SANs only, or the common name too; `*.example.com` versus `example.com` versus
   every subdomain; which public-suffix list version decides where `example.co.uk` begins; IDNA and case
   folding. Every one of these has a defensible answer and a silent way to be wrong, and a subscription that
   silently under-matches is worse than no subscription because the user believes they are covered.
3. **Absence has to stay graded.** "No certificates matched your domain this week" is an absence claim over the
   logs we actually read, so it needs the `GapState` accounting beside it - and this is the copy most likely to
   overstate, because it is addressed to a paying customer who asked to be told. `cl.claims-discipline` applies
   to notification text with more force than it applies to a dashboard.
4. **One certificate, one notice.** The same certificate reaches several logs, and static-merge logs hold a leaf
   per submission, so de-duplication has to happen on identity (`TBSCertificate` digest, per the lesson in the
   CA-graph section) before anything is emailed.
5. **Retention and policy.** Storing subscribers' domains and their match history, and republishing log content
   in email, is squarely inside the question `cl.aup-review` has not answered yet.

**Dependency, stated plainly:** tailing is still fetching, so this waits on the same fetch layer and anchor
decision as everything else live. It cannot be built around `tools/corpus.py`, and pretending otherwise would
mean shipping a monitor whose transport policy was chosen by whichever HTTP client got imported.

## Not on this list, and why

Four things are deliberately absent, and each is absent for a reason that would break something else if it
were closed anyway.

- **The fetch layer** - transport policy, retries, rate-limit accounting, anchors and pins. It is missing by
  decision, not by oversight: `walk.py` takes a `Fetcher` seam that is a function, so the anchor question
  lands in one place instead of being answered implicitly by whichever HTTP client got imported. Answering it
  requires a named human to record what is trusted and where the pins live; until then the capture in
  `tools/corpus.py` stays a script, and a script is honest about being one.
- **Proofs for an arbitrary window of entries.** This bullet used to read "middle-window entries cannot be
  tied to a tree hash, because no deployed log serves inclusion-by-hash". That claim is retracted - asked at
  the endpoint RFC 6962 section 4.5 defines, every log served a path that verifies - and the corpus now acts
  on it: `tools/corpus.py --window` proves each entry in its slice into the tree individually. What remains
  unrepresented is the *span* rather than the kind: one 64-entry slice at the midpoint and a 236-entry prefix
  say nothing about the hundreds of millions of positions between them, and that is a choice about capture
  size, not a limit the deployment imposes.
- **A persistent entry store.** `EntryStore` is in-process and fine at 236 entries, and wrong at the 242
  million a half-year log holds. Persisting it is a real decision about retention and about what may be
  republished, so it waits for `cl.aup-review` rather than guessing at storage technology now.
- **SCT-aware deduplication.** SCT parsing lives in `ctspy`, and folding two spellings of one issuance
  together needs an entry carrying an SCT list *and* a twin logged under the other spelling. The middle windows
  supply the first - 53 logged certificates across three windows carry SCT lists, where none of the prefix's 116
  do - and no twin: every identity in every window is distinct. `EntryStats.sct_bearing` keeps that a number to
  check rather than a case quietly assumed away, and the window tests fail loudly if a future capture finally
  produces the collision.
