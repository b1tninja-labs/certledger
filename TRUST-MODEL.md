# Trust model: independent Certificate Transparency acquisition and publication

Status: **draft for review**, 2026-11-05. This document is the authority for build
order. Where a layer says it does not defeat an adversary, that adversary is either
accepted as residual risk or must be closed elsewhere, and the decision is recorded
rather than assumed.

## 0. Scope, and the question this answers

This covers the **acquisition and publication plane** of an independent CT service:
fetching log data, verifying it, storing it, analysing it, publishing claims. It
does not cover account security, billing, or hosting hardening.

The organising question is not "is the channel secure" but **"what must an attacker
control to make this service wrong, and would we notice?"** A service that audits
certificate authorities cannot depend on infrastructure those authorities are
embedded in. That is not hypothetical: during the eMudhra intermediate compromise of
October 2026 the compromised keys chained to roots trusted by four root programmes,
and Apple's own shipped `git`, `curl` and `python3` were still trusting those
certificates eight days after the first blocks, with `macOS 27.2` *undoing*
user-applied fixes. An auditor that inherits a platform trust store inherits its
incidents.

## 1. The system

Three components, separated because they fail differently.

1. **Acquisition.** Fetches STHs, checkpoints, tree entries and log lists from about
   a dozen log origins over explicitly named *paths* (section 7). Every response is
   stored as raw bytes with the path, timestamps and peer identity that produced it.
2. **Verification and store.** Verifies signatures against pinned log keys, enforces
   monotonic tree growth with consistency proofs, deduplicates by TBSCertificate
   hash, and retains original DER. The CA-layer graph (certificates with `cA=TRUE`)
   is held in full; the leaf layer is appended as it is observed.
3. **Publication.** Queries, dashboards and anomaly notices. Nothing reaches this
   component without the corroboration gate in I7.

## 2. Assets, and what "correct" means

| Asset | The failure being prevented |
|---|---|
| **Integrity** | A stored certificate, proof or tree head the log never signed. |
| **Completeness** | Entries that exist in a log but are missing from our copy, silently. This is the primary attack, not a secondary one. |
| **Freshness** | A valid but stale view presented as current. |
| **Provenance** | An observation we cannot attribute to a vantage point, which makes the claim unfalsifiable and therefore unpublishable. |
| **Credibility** | A published anomaly that turns out to be our own bug. Losing this once ends the service. |
| **Availability** | Being unable to fetch, or unable to afford fetching. |
| **User privacy** | A visitor querying a domain revealing who they are and what they own. |

What is **not** an asset: confidentiality of log data, which is public by design.
Treating it as confidential produces the wrong design.

## 3. Adversaries

Positions are stated as capability, not as identity. Several of these are
legitimate actors doing their jobs, which is exactly why they cannot be trusted with
our trust decisions.

**A1 - On-path network attacker.** An ISP, transit provider, enterprise edge, or
holder of BGP reach. Observes, drops, delays, redirects, and spoofs unauthenticated
name answers. Cannot forge a log signature. Wants to blind the auditor while
mis-issuance is live, or to make it serve garbage to its own users.

**A2 - Configuration attacker on our own host.** Anyone able to set an environment
variable, a DHCP lease, or an OS trust-store entry: a corporate image, a profile
script, a package-install hook, a LAN neighbour offering DHCP options. Strictly
weaker than host compromise and vastly more common. `SSL_CERT_FILE` replaces the CA
bundle we trust, `HTTPS_PROXY` relocates our connections, and the default HTTP
client obeys both without being asked. Proxy autodiscovery can also arrive via DHCP
option 252 and WPAD, which never became an RFC and is therefore invisible to anyone
reasoning from published standards alone.

**A3 - A CT log operator acting badly.** Compromised or malicious. Appends, withholds
entries, serves a stale but correctly signed tree, lies about `get-entries` ranges,
goes silent, or **equivocates**: divergent histories to different clients. Cannot
forge another log's signature. Wants a subtree to stay hidden.

**A4 - A CA outside policy.** Issues unlogged certificates, re-issues under a
compromised key, ignores name constraints or validity-period policy. The October 2026
incident published two deliberately unlogged chains precisely to identify clients
that do not enforce CT, which demonstrates both the technique and our ceiling:
**CT cannot see what was never logged.**

**A5 - A trust-anchor supplier under pressure.** The distributors of the log list and
of revocation information. A `log_list.json` fetched from a CDN with no SLA, whose
acceptable-use policy reserves the right to make unannounced changes to disrupt
unauthorised use, is a dependency on a party that can decide we are unauthorised.
Motivation may be perfectly legitimate; that does not make it ours.

**A6 - Naming and numbering attacker.** DNS forgery, DNSSEC stripping or algorithm
downgrade, NXDOMAIN-of-doom, prefix hijack of a log's address space. Wants us at an
impostor, or a healthy log that looks dead.

**A7 - Impostor and key-substitution attacker.** Registers a lookalike log, or gets a
key of ours accepted as a real log's. Succeeds only if we accept keys over a channel
A1-A6 control, which is why key distribution is a first-class problem here.

**A8 - Observer of our behaviour.** Traffic analysis of our fetches and our users'
queries: which domains we are auditing, who is checking their own certificates. Also
the overlooked one: a full-tree `get-entries` walk from a small stable set of source
addresses is an unmistakable signature.

**A9 - Supply chain.** A dependency, a build step, or a committed fixture. Wants the
verifier to accept a bad signature. A verifier whose trust decisions can be altered
by a transitive dependency has no trust decisions.

**A10 - Host compromise.** Reads our pins, rewrites our code, fabricates our logs.
Out of scope for transport design; see section 9 for what we do instead.

**A11 - Volume and legal adversary.** Scrapers imposing cost, and the exposure of
publishing "CA X issued Y" that turns out to be our own deduplication error.


## 4. Control layers

Four layers, deliberately ordered by leverage per week of effort. Each states what
it defeats and, more importantly, what it does not.

### L0 - CT-native verification. Cost: days.

Pin each log's public key out of band. Verify every STH and checkpoint signature.
Persist the last accepted STH per log and require growth with a valid consistency
proof (RFC 9162 section 2.1.1). Verify inclusion proofs for entries we publish. Keep
raw DER and verify against those bytes. Diff replicas acquired over different paths.

- **Defeats:** A3's forgery, staleness and equivocation (given a second replica);
  A7 entirely, provided the pinning event itself is clean; A9's "accept bad
  signature" objective, because verification is in-tree with no plugin surface.
- **Does not defeat:** A1/A2's omission attack on its own, A3's *withholding* unless
  a second path is also reading, A6's prefix hijack (availability only), A4's
  unlogged issuance (nothing in CT can see it), A8.
- This is the load-bearing layer. Signature verification is what makes the transport
  question second-order, and it must not wait on any of the layers below.

### L1 - Remove ambient trust. Cost: days.

Never call `load_default_certs()` or `set_default_verify_paths()`; load only our own
anchor file. `trust_env=False` on every client, and no proxy configuration read at
all. Resolve with our own code, connect by the address we resolved, and **assert the
peer address equals the one we chose**. Pin peer SPKI at the TLS layer. Record every
anchor-file change in a dated changelog.

- **Defeats:** A2 completely, which is the most likely and least glamorous adversary,
  and which today needs no access to our code at all - only to our environment. Also
  closes the "corporate image quietly MITMs the auditor" scenario.
- **Does not defeat:** A1 (still on path), A6 (still trusting whoever answered DNS
  before we connected), A5, A3, A8. Asserting the peer address proves *we reached the
  address we picked*, not that the name mapped to the right address - that is L2.
- Note the loop with the incident: the published Windows mitigation for the
  compromised intermediates writes into the same OS store that
  `load_default_certs()` reads on Windows. Opting out is not paranoia here, it is
  refusing to depend on a store that was demonstrably wrong for eight days.

### L2 - Own resolution, DNSSEC, DANE. Cost: weeks to months.

Our own resolver instead of `getaddrinfo`. DNSSEC validation ourselves rather than
believing a forwarder's `AD` bit. TLSA records (DANE, RFC 6698 as updated by RFC 7218,
RFC 7671 and RFC 8749) to authenticate log endpoints, so log TLS trust is answered by a
different anchor than the one currently on fire. Pinned root key set, rolled
deliberately.

- **Defeats:** A6's forgery and downgrade; A7's name-based imposture; and crucially
  it **breaks the circularity** of using the WebPKI to reach the logs that audit the
  WebPKI. It is also what turns L1's address assertion into a meaningful claim.
- **Does not defeat:** A6's *availability* attack - DNSSEC authenticates names, never
  delivery, and a path attacker can always deny resolution; A1's prefix hijack of
  already-correct addresses; A3; A4; A8. Deployment is a real constraint: TLSA use on
  log origins must be measured before it is relied on, and an unusable anchor is worse
  than a boring one.
- Where DNSSEC genuinely stops, our RPKI work (`rpkit`, `rtrkit`, `routevalid`) is the
  complement: routing authenticity is a different trust domain with a different root.

### L3 - Own transport diversity. Cost: months, and optional.

HTTP/3 and QUIC on our own stack, DNS over dedicated QUIC (RFC 9250, Proposed
Standard), unreliable datagrams for gossiping checkpoints between replicas.

- **Defeats:** middlebox and proxy interference that survives L1 because it lives
  below the application; adds a path class with different failure modes, which is
  what makes it worth anything.
- **Does not defeat:** anything cryptographic. The handshake is still OpenSSL unless
  TLS is reimplemented, and reimplementing TLS in Python is a bug farm with no
  threat-model payoff - the adversary is the same and the defect budget is not.
- Honest framing: L3 buys **diversity**, which is an availability and
  omission-detection property. It is listed last for that reason, and nothing in
  the first public release depends on it.


## 5. Invariants

These are mechanical rules, each enforceable in code, not aspirations.

- **I1 - No ambient trust.** No proxy environment variables, no OS trust store, no
  system resolver, no WPAD. Every anchor is a file in this repository with a date and
  a reason. If a value can be supplied by the environment, it is a bug.
- **I2 - Authenticity comes only from a log signature over a pinned key.** Transport
  success, TLS validity, and HTTP 200 are never evidence that content is genuine.
- **I3 - DER fidelity.** Verify signatures against the stored original bytes. Never
  re-encode an ASN.1 structure and verify that, and never let a codec that discards
  the original TLV stand in the verification path.
- **I4 - Monotonicity.** For a given log, reject a tree head smaller than the last one
  accepted, and require a consistency proof for every increase. A gap in our own
  record is an incident, not a detail.
- **I5 - Completeness discipline.** A single acquisition path may never support a
  "certificate is not in the log" claim. Absence is only ever asserted from a
  full-tree walk or from two or more replicas in different path classes.
- **I6 - Attribution.** Every stored object carries the path identifier, fetch time,
  response-bytes hash, and peer SPKI. An observation without provenance is a
  discrepancy to investigate, not data.
- **I7 - Corroboration gate.** Nothing is published as an anomaly unless it is seen on
  two independent path classes, the governing specification text has been fetched and
  cited with its errata checked, and a named test reproduces the finding.
- **I8 - Loud failure.** Unknown, unavailable, empty and zero are four distinct
  states with four distinct types. A missing value that defaults to something
  plausible is how an optional extension becomes load-bearing.
- **I9 - We are auditable too.** Our own published checkpoints are mirrored
  externally, so a third party can prove we edited history. An auditor that hides its
  own data has produced a new trust problem, not removed one.
- **I10 - Verification is not pluggable.** Signature and proof verification lives in
  tree with no runtime extension points and no third-party trust decisions.

## 6. Threat-to-control matrix

| Threat | Whom | Layer | Detected by | Residual |
|---|---|---|---|---|
| Forge a certificate or tree head | A3, A9 | L0 | Signature verification against pinned key | Key-compromise of a log |
| Serve a stale signed tree | A3, A1 | L0 | I4 monotonicity plus consistency proof | Only if our own record is wiped, see I9 |
| Withhold entries from one client | A3 | L0 + section 7 paths | Replica diff in different path classes | Subtree never fetched by anyone |
| Equivocate (fork) | A3 | L0 | Cross-replica and cross-log diff | Undetectable if we are the only viewer |
| Impostor log, key substitution | A7, A6 | L0 + L2 | Pinning event, TLSA, name validation | Poorly-anchored first pin |
| DNS forgery or downgrade | A6 | L2 | Own DNSSEC validation, not a forwarder's `AD` bit | Denial of resolution (availability) |
| Prefix hijack of a log | A1, A6 | not covered v1 | RPKI-based route validation (sibling project) | Accepted for v1 |
| `SSL_CERT_FILE` / `HTTPS_PROXY` anchor swap | A2 | L1 | I1 plus a test that sets them and asserts they are ignored | Host compromise |
| Corporate proxy inserted below the app | A2, A1 | L1, L3 | Peer-address assertion, SPKI pin | Requires L3 for full relief |
| Log-list or revocation-list manipulation | A5 | L0 mirrors, own archive | Diff of dated snapshots from multiple vantages | Slow, plausible change |
| Unlogged issuance | A4 | **unachievable in CT** | Only in-the-wild observation, a separate dataset | Stated publicly as a limit |
| Traffic analysis of our audit | A8 | L3 partly, batching | Not solved | Accepted, documented |
| Scraping and cost imposition | A11 | operational | Rate limits, budgets | Accepted |
| Wrong published claim from our bug | A11 | I7 gate | Corroboration plus named test | Reputation, permanent |
| Host compromise | A10 | out of scope | I9 transparency, reproducible builds | Accepted |


## 7. Path diversity

A **path** is a named, configured, attributable route to data, not a URL fetch. Each
carries an identifier, a *trust class*, a vantage (hosting provider, region,
autonomous system), its own anchors, and its own failure history.

| Path | Class | What it independently proves |
|---|---|---|
| P1 own recursive resolution from a pinned root key set | self | Name authenticity without any third party |
| P2 DNS over TLS to operator A, address given as a literal with pinned cert | name-third-party | A second opinion on names, no local resolver |
| P3 DNS over HTTPS or QUIC to operator B | name-third-party | A third name view from a different operator |
| P4 direct to the log origin, TLSA-verified | endpoint-pinned | Endpoint identity outside the WebPKI |
| P5 historical mirrors and public archives | out-of-band | That our own history is not edited; backfill |
| P6 HTTP/3 path, optional | transport-class | A path with different middlebox failure modes |

Rules that make the diversity real rather than decorative:

1. A publishable observation needs **two or more paths from two different classes**.
   Two paths through the same resolver operator are one path with extra steps.
2. At least one path used for completeness claims must **not traverse the local
   network at all** - a vantage in a different autonomous system. Otherwise A1 and A2
   can arrange for both of our "independent" views to be filtered identically, which
   is precisely the failure L0's replica diff is supposed to catch.
3. Every path records **proof it was not proxied**: the peer address it reached, and
   the absence of any proxy configuration in that request's context.
4. A path that has ever disagreed is demoted, and its history is kept.

The **acquisition receipt** is the output of this design and, incidentally, the part
no existing CT frontend publishes: for each object, path id, vantage, timestamp, raw
response hash, peer SPKI, and the verification results. A claim without one is
internal noise.

## 8. Disagreement and degraded modes

Data carries a state, and the state is shown to users rather than hidden behind a
successful-looking page.

| State | Meaning | Behaviour |
|---|---|---|
| `VERIFIED` | Signature valid, monotonic, corroborated | Publishable |
| `SINGLE_PATH` | Verified content, one path class only | Shown, never used for absence claims |
| `DIVERGENT` | Paths disagree on the same range | Freeze publication for that log, alert, keep fetching |
| `STALE` | No growth within budget, log reachable | State it; never present as current |
| `UNREACHABLE` | Fetch failed on all paths | Record absence of *fetch*, never absence of *entry* |
| `UNAUTHENTICATED` | Could not validate names or endpoint | Internal only; may not support any public claim |

Rules:

- **Never silently downgrade.** Failing DNSSEC validation, or TLSA being absent, moves
  data to `UNAUTHENTICATED`. It does not fall back to an insecure path with a log
  line. An auditor that quietly degrades has no security properties to describe.
- A key or log-list change **freezes publication** and requires an explicit human
  decision with a dated note. No automated re-trust, because A5's most realistic
  attack is a change that looks entirely routine.
- Rate-limit and cost pressure are modelled as `UNREACHABLE`, and the walk resumes
  with a recorded gap; the gap is part of the completeness record.
- Disagreement is itself publishable data. Two logs giving different answers about the
  same certificate is a finding, and it is the sort of finding only an independent
  acquirer can make.


## 9. Out of scope, accepted, and unachievable

Recorded so that nobody later mistakes silence for coverage.

- **Host compromise (A10) is out of scope.** Pins are readable, code is writable, and
  our own logs are forgeable by anyone with root. The mitigations that actually apply
  are reproducible builds, publishing our own checkpoints so edits are provable (I9),
  and hoping someone else re-implements the verifier. Transport and DNS work does
  nothing here and must not be sold as if it did.
- **Unlogged issuance (A4) is unachievable through CT.** The October 2026 incident's
  own diagnostics relied on chains that were never logged. Detecting that needs
  in-the-wild observation of deployed certificates, which is a different dataset with
  different costs and a different legal profile. We may add it later; CT alone cannot
  claim it, and the site will not imply "every certificate ever issued".
- **Routing attacks (A1, A6) are deferred.** Validated route-origin information is the
  right answer and belongs to the `rpkit` and `rtrkit` work, not to v1 of this.
- **Traffic analysis (A8)** is mitigated by batching, shared fetches and vantage
  rotation, not solved. Users' queries are separated from ours as far as possible.
- **Legal and reputational exposure (A11)** is not a technical layer. It is handled by
  the I7 gate, by publishing method alongside every claim, and by naming the
  erratum-checked specification each anomaly rests on.
- **Quantum and cryptanalytic breaks** of log signatures are outside this model. A log
  key compromise is treated as an incident class in its own right: pinned keys make it
  detectable and dated, which is the most v1 can offer.

## 10. Build order derived from this model

Each phase names the adversary it newly defeats, so that ordering is a consequence of
the model rather than a preference.

| Phase | Work | New coverage | Exit test |
|---|---|---|---|
| **0** | L1 ambient-trust removal: own anchors only, `trust_env=False`, no proxy read, own resolution call, peer-address assertion, raw DER retained | A2 | A test sets `HTTPS_PROXY` and `SSL_CERT_FILE` and proves they are ignored; a test proves the peer address is asserted; a test proves verification uses stored bytes |
| **1** | L0 core: pinned log keys, STH and checkpoint verification, monotonicity with consistency proofs, inclusion proofs, receipt schema | A3 forgery and staleness, A7 | Injected fixtures for a stale tree, a bad proof and a wrong key all rejected; receipts written for every object |
| **2** | Budgeted full-tree walk, dedup by TBSCertificate hash, CA-layer graph | Completeness for logs we have walked | A walk of one live log with its tree size matched against the log's own signed head; CA-graph counts reconcile |
| **3** | P2/P3 name paths plus TLSA verification, disagreement states wired through to the UI | A6, and makes L1's assertion meaningful | An impostor endpoint with a valid WebPKI chain but failing TLSA lands in `UNAUTHENTICATED` and is unpublishable |
| **4** | Second vantage in another ASN; P1 own recursive validator; P5 archive backfill | A1 and A2's correlated-filtering attack, A5 history edits | A single-path absence claim is refused by I5; a mirror diff runs clean |
| **5** | L3 HTTP/3 and DoQ paths, checkpoint gossip over datagrams | Middlebox survival, diversity | A fetch succeeds with the TCP paths blocked |

**Nothing in phases 3 to 5 blocks the first public release.** The CA-graph analysis
from phase 2 is publishable, is what crt.sh cannot answer, and needs no own-stack
work at all. If effort is scarce, the correct sequence is 0, 1, 2, then the analysis,
and then a hard look at whether phase 4's own recursive validator is worth its cost
versus two well-chosen third-party paths.

## 11. Not yet verified

Written down because a trust model with quiet assumptions is worse than a short one.

- RFC 7673 (DANE TLSA with SRV), RFC 9250 (DNS over dedicated QUIC) and RFC 6698
  (DANE TLSA) are all confirmed Proposed Standards and current; 6698 was published
  2012-08 and carries no verified errata with one on file. **6698 is not
  self-contained**: it is updated by RFC 7218, RFC 7671 and RFC 8749, so an L2
  implementation built from 6698 alone would get the certificate-usage and matching
  semantics wrong. Those three updates have been identified but not yet read here,
  and the erratum on 6698 has not been opened.
- **Witness quorums are not standardised.** RFC 6962 defines Monitor (section 5.3) and
  Auditor (section 5.4) roles and treats absence from monitors' copies as the
  misbehaviour signal, but witness aggregation lives in later drafts. Do not describe
  it as a standard property of CT.
- **CT has never been an IETF Standard.** RFC 6962 was Experimental and is now
  **Obsolete**; its replacement RFC 9162 (CT version 2.0, 2021-12, one erratum on file)
  is **also Experimental**. Everything in this model therefore rests on a protocol whose
  authors did not claim standards-track maturity, and on a version-1 wire format that
  deployed logs still speak while the current document describes version 2. That is a
  fact about the design space to state to users, not to paper over. Both documents must
  be re-checked with `errata` before any claim cites them: 6962 carries one verified
  erratum.
- **TLSA deployment on log origins is unknown.** L2's DANE value depends on it and must
  be measured before it is relied on. If deployment is thin, P1 becomes more
  important, which changes phase 4's cost-benefit.
- **CA-layer cardinality is estimated, not measured**: the claim that the `cA=TRUE`
  layer is orders of magnitude smaller than the leaf layer needs a number from a real
  walk. Leaf volume is bounded below by one half-year log holding about 242 million
  entries, which is why deduplication and partitioning precede any storage decision.
- **Per-log rate limits and walk cost are unmeasured**, as is whether public archives
  cover every currently usable log. Both affect phase 2 feasibility directly.
- Third-party DoH and DoT providers' terms of use for automated auditor traffic are
  unread. A path we are not permitted to use is not a path.
- The incident facts used here come from the published incident page alone and have
  not been independently confirmed: eight compromised intermediates versus sixteen
  blocked items, the two unlogged diagnostic chains, and the timeline of blocks.
- Chrome's log-list acceptable-use policy permits use by CT monitors and auditors but
  forbids using the list to drive CT enforcement in non-Chrome clients without written
  permission, and reserves unannounced changes. This document treats that as a design
  constraint requiring legal review before launch, not as a footnote.

