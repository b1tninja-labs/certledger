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
`qualified` — which appears only in v2. And **v2 and v3 disagree about the fleet** (47 usable vs 21; 97 logs vs 26),
with no v2 log absent from a v3 document, so the difference is membership semantics rather than staleness. A client
reading the wrong schema does not fail; it reports a different fleet.

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

The consolation comes from the duplication measurement: cross-operator overlap ran **51-78%** between DigiCert and
Google logs, so a lost log's certificates are largely, not wholly, present in a partner log. **Log loss is
recoverable-partial**, and the dedup numbers are what make that a checkable claim rather than a hope.

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

**Still unread, and where they matter:** the *CT Log Lifecycle Explainer* (the criteria for becoming Qualified, and
what makes Chrome Retire a log — the difference between the h1 generation's `rejected` and a `retired` log is the
distinction between delisted-by-plan and withdrawn-for-cause); the *Chrome CT Log Policy*; the published **log list
schema** and signing public key (we need the key to verify a snapshot offline); Apple's CT log program, since Apple's
"varying number" is a different shape of obligation; and CCADB's `include`/`monitor` preference mechanism, which is
where a root stops being trusted in Firefox independently of whether its certificates remain valid.
