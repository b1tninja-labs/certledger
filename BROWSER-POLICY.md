# Who decides "trusted" and "logged" — and what that does to our universe

Research notes, 2026-11-06. Sources read this session: Chrome's CT policy and log-list pages
(`googlechrome.github.io/CertificateTransparency/ct_policy.html`, `…/log_lists.html`), MDN's Certificate
Transparency page, and the machine-readable lists themselves — `log_list.json` v3, `all_logs_list.json` v3 and
`log_list.json` v2, fetched live and hashed. Everything marked *measured* comes from those fetches; the rest is
quoted or attributed. This document exists because two of our claims — "every globally trusted CA" and "every
certificate logged to a live CT log" — borrow definitions we do not own, and one turned out to be understated by
about a fifth on the day we wrote it down.

## 1. "Trusted" is not one set, and CT enforcement follows each client's own set

The parties deciding whether a root is trusted are not us and not each other: Mozilla's Root CA Program, Apple's
trust store, Microsoft's Trusted Root Program, and Google's own root store, coordinated through CCADB.
`trustatlas` exists because those sets measurably differ — the first join found **29 anchors shared between certifi
and this machine's store, 91 bundle-only, 45 store-only** — and the policy pages say why that matters rather than
merely existing:

- Chrome evaluates CT against **"all publicly-trusted TLS certificates"**, i.e. certificates chaining to the roots
  Chrome ships, enforced *during certificate validation*.
- MDN: **"Firefox desktop, starting from version 135, and Firefox for Android, starting from version 145, require
  CT log inclusion for all certificates issued by certificate authorities in Mozilla's Root CA Program."** Note the
  scoping: Firefox's obligation is defined by *its own program membership*, not by certificate lifetime and SCT
  counts in Chrome's manner. The older framing — "Firefox does not enforce CT" — is out of date (page current as of
  2026-07-20).
- MDN: **"Apple requires a varying number of SCTs in order for Safari and other servers to trust server
  certificates."**

Consequence: **there is no single "publicly trusted" set to make a claim about.** Any sentence of that shape names
a program, and the artifact carrying it names the snapshot of that program's list it used. That argues for
trustatlas publishing per-program anchor sets and never a union of them.

## 2. Two lists, and the 13.6 billion leaves only one of them shows

The log-list page describes both documents (the rules that make membership in one of them meaningful are §4):

- **`log_list.json`** — *"contains logs that are Qualified, Usable, or Retired as of when the list was generated.
  These logs are those included in the Chrome browser for evaluating compliance."*
- **`all_logs_list.json`** — *"contains all logs known to and tracked by the Chrome team, including the logs in
  `log_list.json`, logs that are Pending or Retired, as well as additional logs that have not applied for inclusion
  in Chrome's log list."*

Measured at list version **96.2**:

| Document | Logs | Operators | States present |
| --- | --- | --- | --- |
| v3 `log_list.json` | 26 | 11 | usable 21, readonly 2, retired 3 |
| v3 `all_logs_list.json` | **45** | 13 | usable 21, readonly 2, retired 3, **rejected 9**, **no state 10** |
| v2 `log_list.json` | **97** | 10 | usable **47**, qualified **43**, retired 7 |

Two things fall out before we get to the number. The documentation and the data disagree on state names: the page
says `log_list.json` holds Qualified/Usable/Retired, while v3 publishes usable/readonly/retired and never
`qualified` — which appears only in v2. **That reading is scoped to one array and §7 shows where it breaks.**
And **v2 and v3 disagree about the fleet** (47 usable vs 21; 97 logs vs 26), with no v2 log absent from a v3
document, so the difference is membership semantics rather than staleness. A client reading the wrong schema does
not fail; it reports a different fleet. Everything counted in this section is the `logs` array, which turns out to
be about half the world.

**The number.** The 19 logs present in `all_logs_list.json` and absent from `log_list.json` carry **13.63 billion
leaves**, and **15 of 19 still answer `get-sth`** (probed individually, 2-way concurrency):

| Group | Reachable | Leaves | Character |
| --- | --- | --- | --- |
| `rejected`, the whole **2026h1 generation** — DigiCert Sphinx2026h1, Wyvern2026h1; Sectigo Elephant-, Mammoth-, Sabre-, Tiger2026h1 | 6 | **6.52B** | **publicly-trusted production issuance**, invisible to the enforcement list |
| `rejected`, unreachable | 0 | unknown | Google Argon2026h1, Xenon2026h1 (HTTP 404); Let's Encrypt Oak2026h1 (no connection) |
| no state, real logs | 2 | 0.08B | Google Daedalus 46.9M, Google Submariner 37.0M — the first generation |
| `log_type: test` | 7 of 8 | 7.02B | Crucible, Testtube, Dumbo, Solera×3, Tigger×2 — never publicly trusted, out of scope for these claims |

So the 33.83B-leaf fleet that `HARVEST-PLAN.md` sizes on **understates the universe an "every certificate logged"
claim needs by ~6.6B leaves — about 19%**, i.e. ~40.4B. The missing part is not historical residue: it is
year-old production issuance from four of the largest CAs, sitting in logs that are online *today*. Three of the
rejected logs are already gone, and v3 publishes no final tree head for `rejected` entries — only `readonly` ones
carry one — so for the dead ones we do not even know where their trees ended.

**Whether a lost log's certificates survive elsewhere is now measured rather than hoped, and the answer is
per-era — which is the part that bites.** Between two *live* logs of different operators, overlap ran 51-78% in a
2025 window, **34.06%** in a June-2026 window and **13.33%** in an April-2026 window (`Wyvern2026h2` ×
`Argon2026h2` each time): the same two operators, three answers, so no single percentage describes the fleet and no
fleet factor belongs in a publication. For the rejected `2026h1` generation the copies are not in a
surviving partner at all. Over the whole common interval of a window on 2026-06-01, `DigiCert Wyvern2026h1`
(`rejected`) shared **0 of 69** entries with `Google Argon2026h2` (live) — **≤ 4.3% at 95%**, the rule of three on
a census rather than a sample — and 0 of 69 with its own live sibling `Wyvern2026h2`, reproduced at `0 of 35`
(≤ 8.6%) on 2026-04-15. What it *does* share is
**91.19% with `DigiCert Sphinx2026h1`**, another `rejected` log.

So that era's certificates have **one copy, kept twice, in two logs Chrome already marks `rejected`** — while the
operator-distinct partner logs, `Google Argon2026h1` and `Xenon2026h1`, are already `404`. Chrome requires SCTs
from **two distinct operators**, and that requirement is exactly why a certificate's witnesses live in two
different operators' hands: when one operator deletes a generation, the other side can become the only surviving
record. **Log loss is recoverable only where a partner log of the same era survives** — a per-era question, not a
fleet constant, and my earlier framing that duplication makes loss broadly recoverable was too comfortable.

## 3. Provenance and permission, both already stated by the publisher

*Measured:* `log_list.sig` and `all_logs_list.sig` each exist and are **512 octets**; `log_list.zip` (the list with
its signature, bundled) is 13,635 octets. The page confirms the purpose: *"Chrome also signs these lists … to
facilitate offline verification of the contents using a published public key."* So a snapshot of the list is
verifiable years later without trusting whoever served it — the same property we want for anchors and STHs, and one
reason to store the signature beside the bytes rather than the bytes alone.

The list carries conditions, and they are unusually specific:

- Purpose: *"for the purposes of certificate submitters (such as certification authorities) and **CT monitors and
  auditors** wishing to remain compatible with, or investigate the contents of, the CT and WebPKI ecosystems."*
  That is our standing, and it is permitted.
- Limit: *"Chrome's CT log lists may **not be used to facilitate CT enforcement in TLS clients other than Chrome**
  without explicit written permission from Chrome's CT team."*
- Risk: *"Google must be able to make changes to the CT log lists in response to incidents … including **unannounced
  changes to the log list to disrupt unauthorized use**."*
- Reliability: *"offered without SLA or availability guarantee"*, consumers are *"encouraged to cache recent
  versions"*, and changes are announced on `ct-policy@`.

Read together these say: journal the lists ourselves, keep the signatures, treat any single fetch as a snapshot of
a moving document rather than a reference, and keep `trustatlas` and `certledger` on the monitoring-and-auditing
side of the line — a viewer that shows what Chrome required at a given list version, never a client that enforces.

**The key has been found and the signatures verified.** `log_list_pubkey.pem` (served beside the lists, RSA-4096,
exponent 65537, DER fingerprint `f1d8b68e50210d8e73d9a3e97f571773c52d7f28c0b1a71beee81d8562e6fd85`) validates both
`.sig` documents over the bytes exactly as served — confirmed twice, once with `cryptography` and once with a
stdlib `pow()` implementation of RSASSA-PKCS1-v1_5/SHA-256 (`ctspy/loglist.py`, tested offline against a captured
snapshot in `ctspy/tests/fixtures/loglist/`). Two consequences:

- **The signed bytes are the signed bytes.** Folding `\n` to `\r\n`, or dropping the trailing newline, breaks the
  signature. On Windows a text-mode write re-translates newlines, so a journal that opens a file without `b`
  produces snapshots that can never be verified. `tools/log_list_journal.py` writes binary everywhere and a test
  pins the newline case.
- **A key fetched next to the data proves consistency, not authenticity.** Verifying with a key from the same
  origin shows a document and a signature belong together — worth a great deal across a journal's own history —
  but a substituted key would verify its own forgery. Spotting that needs the fingerprint pinned out of band, so
  the journal takes `--expect-key-sha256` and records `pinned: false` rather than implying more than it has.
  **This is the anchor decision the project has been carrying: it needs a human to choose where the pin lives.**


## 4. What Chrome actually requires, stated exactly

States a log can hold: **Pending, Qualified, Usable, ReadOnly, Retired, Rejected**.

Embedded SCTs (the `SignedCertificateTimestampList` X.509v3 extension) satisfy the policy when *all* of:

1. at least one embedded SCT from a log that was **"Qualified, Usable, or ReadOnly at the time of check"**;
2. embedded SCTs from **at least N distinct logs** that were **"Qualified, Usable, ReadOnly, or Retired at the time
   of check"**, where **N = 2 for a certificate lifetime ≤ 180 days, N = 3 for > 180 days**;
3. among those, **"at least two SCTs must be issued from distinct CT log operators as recognized by Chrome"**, and
   **"log operator uniqueness is defined as having separate entries within the operators section of
   `log_list.json`"**.

SCTs delivered over TLS need at least two, from Qualified/Usable/ReadOnly logs, from two distinct operators. Four
details are load-bearing for anything we publish:

- **Two different clocks.** State is judged *at time of check*, but an SCT's operator is judged **at issuance**:
  "each SCT's log operator is determined to be the operator at the time of SCT issuance, by comparing the SCT
  timestamp against the `previous_operators` timestamps". *Measured:* `previous_operators` appears on **0 of 45**
  logs today, so this is latent — but operator identity is time-dependent, and a store keying "distinct operators"
  off a snapshot will be wrong the first time a log changes hands.
- **The Retired rule.** "an SCT must have been issued before the log's Retired timestamp, if one exists. Chrome uses
  the **earliest** SCT among all SCTs presented to evaluate CT compliance against CT log Retired timestamps." A
  certificate's compliance can therefore hinge on which SCT happens to be earliest — which is a fact about the
  presenting server, not about the certificate.
- **OCSP-stapled SCTs are legacy:** "In versions prior to version 148, Chrome also accepts SCTs embedded in stapled
  OCSP responses." Treating stapled OCSP SCTs as current evidence diverges from Chrome 148+.
- **Non-compliance is not mis-issuance:** "The issuance of certificates that are not CT compliant is not considered
  mis-issuance or a violation of Chrome's root program; such certificates will simply fail to validate." Same
  asymmetry `INCIDENT-CT-FORENSICS.md` reached from the other side: absence of a log entry is not evidence about
  issuance, and here Chrome says absence of compliance is not evidence about issuance either.

**The 70-day timeout.** *"Chrome will enforce CT so long as the `log_list_timestamp` of the freshest version of the
log list Chrome stores is within the past 70 days (10 weeks)… If the installed version of Chrome has not applied
security updates and has been unable to obtain an updated CT log list from the Component Updater for 70 days or
more, then CT enforcement will be disabled."* The stated purpose is ecosystem-side — newly qualified logs must
become usable within a fixed window — and the operational consequence for us is that the list is not a background
constant: it is an active dependency, refreshed **daily**.

## 5. What this changes, and what is still unknown

1. **The fleet universe is `all_logs_list.json`, not `log_list.json`.** The enforcement list is the right input for
   "does this certificate satisfy Chrome's policy" and the wrong input for "what has been logged": it omits 19 logs
   and 13.63B leaves, 6.52B of them publicly-trusted production issuance from the rejected 2026h1 generation. The
   harvest should walk `log_list.json` ∪ `all_logs_list.json` ∪ v2, tagging every entry with the state and the list
   version that produced it. This replaces sequencing item 4 in `HARVEST-PLAN.md`, which assumed the historical
   universe would have to be reconstructed — it is published.
2. **A closed log publishes a seal — but it is a lower bound, not a completion proof.** `readonly` entries carry
   `final_tree_head` (a `tree_size` and `sha256_root_hash`) and a timestamp. *Measured against the logs themselves:*
   Sectigo Mammoth2026h2 is sealed at **57,634,084** and serves exactly **57,634,084** ✔; Sectigo Sabre2026h2 is
   sealed at **68,732,791** and serves **68,732,793**, and the two extra entries carry leaf timestamps
   **2025-11-11T02:23:18Z** and **2025-11-11T05:01:07Z** — about **54 days after** the list's `readonly` timestamp of
   **2025-09-18T17:20:00Z** for that log. That timestamp is identical on both logs, which suggests list-recording
   time rather than the instant issuance stopped. So the seal is a cross-check worth keeping (it caught a 2-leaf
   divergence that nothing else would have surfaced) and **not** an acceptance criterion: "walked entirely" has to
   mean "reached the head the log itself signs", with any disagreement against the seal recorded as an observation
   rather than repaired. No seal exists at all for `rejected` logs.
3. **Watch `tree_size`, not the head timestamp.** Both frozen logs were still signing brand-new STHs an hour before
   the probe (2026-11-06T22:24:33Z and 22:23:24Z) over trees that gained nothing for a year. A journal keyed on head
   *timestamp* would report a healthy fleet; keyed on *tree size* it reports two closed logs. Any staleness alarm has
   to be built on the second.
4. **Journal the lists, not just the heads.** Two documents and two signatures, fetched daily, are a few tens of
   kilobytes — the same order as the STH journal, the same rationale (today's membership is tomorrow's history), and
   it is the only defence against a document that may change "unannounced" and is offered "without SLA". Every
   coverage claim then names the list version it was evaluated against: *as of log list 96.2, 21 usable + 2
   readonly* is checkable; "there are 23 logs" is not.
5. **We are inside the permission and outside the prohibition.** Monitoring and auditing are named uses; using the
   lists to enforce CT in a non-Chrome client is not, absent written permission. `trustatlas` renders what a policy
   required at a given version — it must not become a validator, and the redistribution posture for anything derived
   from these lists should say so in the artifact.
6. **Test logs are a separate universe and must be labelled, not silently mixed.** 7.02B leaves sit in
   `log_type: test` logs that will never be publicly trusted. A store that ingests them without a flag will produce
   "certificate issued by a trusted CA" claims that are false by construction.

**Still unread, and where they matter:** the *Chrome CT Log Policy* (`log_policy.md` — the requirements placed on
operators, and the standard a log fails to meet before Chrome Retires it); the published **log list schema**
(`log_list_schema.json`, to know which fields are normative rather than incidental) and
`operator_list_schema_v1.json`, an operator-list document this project has never looked at; `mmd_monitor_root.crt`,
a certificate the same repo publishes for the MMD monitor; Apple's CT log program, since Apple's "varying number"
is a different shape of obligation; and CCADB's `include`/`monitor` preference mechanism, which is where a root
stops being trusted in Firefox independently of whether its certificates remain valid. The lifecycle explainer is
**no longer unread** — see §6.

## 6. The lifecycle document, and the one place the fleet breaks its contract

`log_states.md` in the same repo defines the state machine
`PENDING → QUALIFIED → USABLE → READONLY → RETIRED → REJECTED` and, unusually for this kind of page, states who is
obliged to do what in each state. Five sentences change what can be claimed:

1. **`Rejected` is the planned-expiry path, not the punishment path.** A log transitions to `Rejected` *"if all
   certificates contained therein are expired or if it is past the end of their certificate expiry range specified
   in their CT log application. Notably, the … transition is not used as a more severe response to a CT log's
   compliance issues."* That is what the trees showed in §2 — both DigiCert `2026h1` logs ending at exactly
   2026-06-30T23:59:58Z, the end of a declared range — so in a coverage claim `rejected` means *out of scope by
   plan* and carries no implication about conduct.
2. **`Retired` conflates misbehaviour with shutdown.** Logs become `Retired` *"if they demonstrate a serious or
   sustained pattern of … compliance issues, **or if the log operator ceases operation** … Due to the inability
   for Chrome to distinguish between intentional and accidental non-compliance, such issues are treated as highest
   possible severity."* A `retired` log is not evidence of wrongdoing, and anything written about one has to say
   that Chrome's own state machine cannot tell the two apart.
3. **`Retired` means the data is expected to vanish.** *"Once a CT log becomes `Retired`, there are no longer any
   expectations that it continues operation. Log operators are encouraged, **but not required**, to keep `Retired`
   CT logs running for a time sufficient for log monitors to fully ingest the log."* That clause is the loss budget
   in one sentence — and it is why all three `retired` logs in the enforcement list were already unreachable when
   `HARVEST-PLAN.md` probed them. It is also a promise a monitor can only keep by ingesting early.
4. **A `ReadOnly` log publishes a size it promises not to exceed**, *"to signal that this log should not grow past
   this point. To help ensure this behavior, CT monitors should continue monitoring `ReadOnly` logs until they
   become `Retired` or `Rejected`."* Two obligations land on us: keep watching closed logs, which is the
   head-advancement watch rule `HARVEST-PLAN.md` derived on its own, and treat the published number as a bound.
5. **The 70-day timeout is the mechanism, not just the safety valve.** A `Qualified` log becomes `Usable` once
   every enforcing client knows about it — *"either by Chrome clients updating … or by older clients becoming 10 or
   more weeks out-of-date and thus disabling CT enforcement"* — which is §4's window seen from the other side.
   `Usable` itself *"is not a state that is specifically recognized by Chrome clients and is functionally equivalent
   to `Qualified` and `ReadOnly`."*

**One measurement breaks the contract in point 4.** Sectigo Sabre2026h2 is `readonly` with a published final tree
size of **68,732,791** and is serving **68,732,793**; the two extra entries carry timestamps
**2025-11-11T02:23:18Z** and **05:01:07Z**, about **54 days after** the list stamped that log `readonly`. Either the
log issued SCTs after asserting it would stop, or the list's timestamp records when Chrome noted the change rather
than when it took effect — and the other sealed log points the second way: `Mammoth2026h2`'s own last leaf is
2025-09-18T15:34:02Z, 1h46m *before* the 17:20:00Z `readonly` stamp it shares with Sabre, and its tree matches its
seal exactly.
That distinction cannot be settled from outside, and it does not change the observable: **a published bound that
the served tree exceeds is exactly what a monitor exists to notice.** So the watch rule is not "trust the seal" but
"compare the seal against the head every day and keep the record of the disagreement" — which is what
`tools/log_list_journal.py` and a head journal together make cheap.

## 7. The list has two arrays, and I had been reading one of them

`log_list_schema.json` requires each operator to carry **both** `logs` (RFC 6962, with `url`) and **`tiled_logs`**
(the Static CT API, with `submission_url` and `monitoring_url` and no `url`). Every count in §§1-6 above comes from
`logs` alone.

| Array | `log_list.json` | `all_logs_list.json` | states seen |
| --- | --- | --- | --- |
| `logs` | 26 | 45 | usable, readonly, retired, rejected, none |
| `tiled_logs` | **63** | **109** | usable 22, **qualified 41**, pending 4, rejected 5, none 37 |

Four operators — **Microsec, GoDaddy, HARICA and SwissSign** — run **no RFC 6962 log at all**. They exist in the
list only as tiled logs, so a fleet assembled from `logs` does not merely undercount them: it reports that they are
not there. `qualified` and `pending` are ordinary in this array, which is why §2's "v3 never says `qualified`" had
to be scoped to the array it was read from.

Measured the same afternoon by fetching each tiled log's `<monitoring prefix>/checkpoint` — 93 of 109 answered, the
rest returned 404/403/429 or timed out:

| State | Logs answering | Leaves |
| --- | --- | --- |
| `usable` | 22 | **14.05B** |
| no state | 13 production | 9.09B |
| `rejected` | 5 | 5.09B |
| `qualified` | 32 | 0.44B |
| **production total** | | **28.67B** |
| `log_type: test`, excluded | 21 | 3.77B |

The largest single tiled log measured is `Google CoachAndHorses2026h2` at **4.67B leaves with no state in either
list**; `Google Arche2026h1` is 2.87B the same way, and IPng's `rejected` Gouda2026h1 and Halloumi2026h1 hold
1.55B and 1.47B and are still serving.

**What that does to the sizing.** The `logs`-array universe of §2 was ~40.4B leaves. Add the reachable production
tiled fleet's 28.67B and the universe is **~69B leaves — roughly double** what `HARVEST-PLAN.md` sized on. The
caveats carry over and one is new: reachable, not distinct; a floor, since 16 tiled logs did not answer; and
**cross-protocol duplication is unmeasured**, so nobody can yet say how many of those 28.67B leaves are
certificates already witnessed in an RFC 6962 log. With the 13-51% cross-operator spread of §2 as the only guide,
the honest position is that the spine and DER figures move by up to about 2× and have to be re-derived rather than
scaled.

**Two probes I got wrong before this one, recorded because they were the tempting findings.** I first fetched
`<monitoring>/tile/heads/master` — a path I assumed rather than looked up — and got 404 from Google and most
others, which would have been written up as "the tiled fleet is not serving". The specification serves the head at
**`<monitoring prefix>/checkpoint`**; with the right path Google's ParcelYard2026h2 answers with 1.64B leaves. Then
I parsed the checkpoint as `size<space>hash` on one line and reported **0.000B reachable for all 109**, because the
format puts origin, tree size and root hash on **separate lines**. A third trap a parser has to survive: Let's
Encrypt and IPng include a `grease.invalid` provenance line — a deliberately bogus signature — so a checkpoint
reader must ignore keys it does not recognise rather than reject the document. Both failure modes produced a
clean, quotable, false result; the numbers above are from the third attempt.
