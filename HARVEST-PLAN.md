# Harvesting CT: what is perishable, what is merely expensive

Written 2026-11-05, to answer a specific question: **how long are the original CT logs available**, and what
should start being collected before the answer becomes "no longer". Everything numeric below was measured the
day of writing from this machine unless stated otherwise; the arithmetic is computed by a script, not by hand,
because hand arithmetic has already produced two wrong figures on this project's roadmap (see
`ROADMAP.md` and section 10 of `PORTFOLIO.md`).

The stated goal — *every certificate issued by every globally trusted CA* — is restated honestly at the end.
Parts of it are collectable; parts of it are not collectable by CT at any price.

## What the record says about retention

**There is no retention obligation in CT.** `grep` for `retain`, `retention`, `delete` or `archive` across
RFC 6962 and RFC 9162 returns **nothing**. The only relevant normative text is RFC 9162 section 4.13, "Shutting
down a log", and it is a **SHOULD**, with four steps:

1. Make it known out-of-band that the log will be frozen.
2. Stop accepting submissions (return `shutdown`).
3. After the MMD from the last submission passes, issue a **final STH** and publish it as a log parameter; the
   log's private key may then be destroyed.
4. "**Keep the log running until the certificates in all of its entries have expired or exist in other logs.**"

That terminus is the whole answer to the question. A log's data is expected to remain reachable only until its
content is either **expired or duplicated elsewhere** — which is a reasonable rule for clients verifying SCTs,
and is *not* a rule that preserves the historical record for anyone doing later analysis. A 2013-era log whose
certificates all expired years ago is, under section 4.13, free to stop.

## What is actually reachable, measured today

`log_list.json` v3 lists **26** logs across 11 operators: **21 usable, 2 readonly, 3 retired**.

| Probe | Result |
| --- | --- |
| Logs answering `get-sth` | **23 of 26** |
| The 3 retired logs | **all unreachable** — `Let's Encrypt Oak2026h2` and both "bogus placeholder" test logs refused the connection entirely |
| Logs serving their own index 0 | **22 of 26** (the 23rd, TrustAsia HETU2027, answered `429` — rate limited) |
| `get-anchors` | **served by nobody.** RFC 9162 section 5.7 defines `GET <base>/ct/v2/get-anchors`; Cloudflare answers **403** and Google **404** on that v2 path, and every v1 path 404s. **RFC 6962 has no such message at all** |

Two conclusions follow, and they point in opposite directions:

- **While a log is live, it serves its whole history.** Every answering log handed back index 0. There is no
  evidence of partial retention — a log is available or it is gone.
- **Gone means gone.** The one recently-retired real log in the list (`Oak2026h2`) is *already* unreachable. One
  sample, so not a rate — but it is the direct measurement of the window, and it is small.

Also worth naming: **there is no search-by-issuer message in the API.** RFC 9162 section 5 offers submit,
`get-sth`, consistency proof, inclusion by leaf hash, `get-entries`, and the v2-only anchors. Combined with the
possession-not-membership property recorded in `INCIDENT-CT-FORENSICS.md`, that means the goal set can only be
built by **reading everything and filtering afterwards**. There is no shortcut query.

## The perishable artifact is not the entries — it is the signed heads

Entries are as durable as the operator's goodwill. **Signed tree heads are not recoverable retroactively at
all**: a head is a statement about the tree *at a moment*, and the moment passes. Section 4.13 step 3 exists
precisely because clients need to audit a log while it is alive; nothing lets you ask later what head a log
published in March.

So the cheapest, highest-value collection is not the 190 TB walk. It is the **STH journal**: poll every log on a
fixed interval, keep every head, and chain consecutive heads with consistency proofs.

- Cost: 23 logs x 24 heads/day x ~700 bytes = **~0.4 MB/day**. Terabytes of entries can wait; heads cannot.
- What it buys: fork detection over the whole fleet (a head that cannot be made consistent with its predecessor
  is the evidence, and `ctspy` already verifies both consistency and inclusion), a monotonic spine for every
  future completeness claim, and the ability to prove years later that a log committed to a given root at a
  given time.
- **Why it does not need the anchor decision.** Recording a signature is not accepting it. The journal stores
  *assertions with timestamps* — the whole point is to keep evidence about logs we are not relying on. The
  anchor and pin decision gates *trusting* a log's current head to publish completeness claims; it does not
  gate writing down what the log said. Monitoring is also exactly the use the log-list policy permits (the
  contractual question in `PORTFOLIO.md` section 9 item 2 is about *republishing* and about driving enforcement
  in non-Chrome clients).
- Hardening worth doing at write time: S3 Object Lock (WORM) on the journal prefix turns "we recorded this"
  into "we recorded this at T and cannot have rewritten it", which is the difference between a log file and
  evidence.

The second-cheapest perishable collection is **the beginning of every log**: index 0 outward for a bounded slice.
Early content is where uniqueness is highest (early logs held issuance nobody else saw), it is where section
4.13's "all expired" excuse bites first, and a few thousand entries per log is gigabytes, not petabytes.

## The size of the whole corpus, computed from measured inputs

Summing the `tree_size` each live log signed today, applying the page size that operator was observed to serve,
and the bytes-per-entry observed in the same responses:

| Operator | Observed entries/response | Leaves (billions) | Requests (millions) | Wire volume (TB) |
| --- | --- | --- | --- | --- |
| Google | 32 | 8.17 | 255.2 | 59.2 |
| TrustAsia | 32 | 6.63 | 207.3 | 26.7 |
| Cloudflare | 256 | 7.64 | 29.8 | 50.6 |
| Sectigo | 256 | 6.19 | 24.2 | 41.4 |
| DigiCert | 256 | 5.20 | 20.3 | 12.3 |
| **Live fleet total** | | **33.83** | **536.9** | **190.3** |

Three caveats that change what those numbers mean:

- **Cloudflare's counts are witness leaves, not certificates.** Static-merge logs add a leaf per submission, so
  one certificate submitted to several logs appears repeatedly; `ctspy/docs/interop.md` records a 6.7-billion-entry
  tree holding a far smaller set of merged entries. The requests are still real even where the yield is not.
- **190 TB is JSON wire cost, not storage.** Responses are base64 (about 1.33x inflation) and `extra_data` repeats
  the same issuer chains across thousands of entries. Deduplicated by certificate, with chains stored once and
  keyed by hash, the durable footprint should be a fraction of the transfer — order 30-40 TB, to be measured on
  the first real slice rather than promised now.
- **429 is the binding constraint, not capacity.** One modest probe was rate-limited. Sized on bandwidth alone,
  this becomes a crawler that gets itself blocked and then reports its holes as absence.

The number to hold onto: **537 million requests**, of which 462 million belong to Google and TrustAsia serving
32 at a time. Assuming everybody caps at 32 predicts 1,057 million — twice the real figure, and the entire
difference is one measurement per operator.

**Corrected the same day, in the direction of "this is not a constant."** `ctspy/tools/page_caps.py` asked all 23
usable logs for 16, 64, 256 and 1024 entries from one offset and recorded what came back. Entries per response
ranged from **1 to 250**, and the spread *within* an operator exceeded the spread *between* them: Google served 6,
22, 30 and 32 across its four logs; DigiCert served 1 on one log and 222 on another; the same log asked again ten
minutes later returned 6 where it had returned 8. What held steady was the **response size per entry — 4,528 to
8,200 bytes, median about 6.5 KB** — because `extra_data` carries the issuer chain. The ceiling is therefore on
bytes, entries-per-response describes that day's entries as much as the operator's configuration, and 537M is one
sample of a moving quantity: the same arithmetic on the later sustained pages gives **~1.6B requests**.

The estimate that survived is the one that does not depend on page size at all: **~207 TB of JSON responses** at
the measured bytes per entry, against 190 TB from the earlier route. Two measurements 9% apart, on a quantity that
is stable precisely because it is counted in bytes. So size the walk in bytes and in the request rate operators
tolerate, and treat the request count as the thing they ration rather than a capacity to plan against — TrustAsia
answered `429` on two of its four probe steps at four-way concurrency.

## Deployment shape: Fargate in production, the same image locally

The constraint is that a harvest task must be **restartable, idempotent, and provably what it claims**. That
yields a small, boring architecture.

**Local (Docker Compose).** Three services: `harvest` (the Python fetcher — the *same image* Fargate runs),
`minio` (S3 API, so storage code never grows an "if local" branch), and `schedule` (a timer standing in for
EventBridge). One bind-mounted volume for segments. No database, no queue, no framework. If local cannot reach
the same code path as the task, local is a lie.

**Production (Fargate).**

| Piece | Shape |
| --- | --- |
| Harvest task | Stateless, one `(log, start, end)` range per task, taken from a ledger of work. Ephemeral storage is capped near 10 GB, so segments are **streamed to S3 with multipart uploads and never accumulated**. Spot capacity: a reclaimed task loses one range and re-runs it. |
| Work ledger | Ranges with per-range state. This is `GapState` in disguise and should be the *same* representation, so the crawler's bookkeeping and the completeness claims are one thing that cannot drift apart. |
| STH journal | Separate task, 15-60 min schedule, S3 prefix under Object Lock. Runs forever, whatever the budget says. |
| Verifier task | Separate role with no write access to raw. Re-verifies sampled slices against journalled heads using `ctspy`, in-tree, per I10 (verification is not pluggable). |
| Rate handling | Per-operator concurrency ceiling, exponential backoff honouring `Retry-After`, and a distinct ledger state for "refused because we asked too hard", so throttling never becomes an unrecorded hole. |
| Identity | A `User-Agent` with contact details. Crawling a public good anonymously and at scale is how the ecosystem gets nice things withdrawn. |

**Segment layout.** `s3://<bucket>/<log-key-id>/<start:012d>-<end:012d>.jsonl.gz` plus a sibling `.meta.json`
holding the requested range, entries actually returned, SHA-256 of the raw response, `retrieved_at`, the log's
head at fetch time, and the task identity. That is the provenance contract `trustatlas/PLAN.md` already
specifies — one contract, both consumers, and an artifact whose recorded command must reproduce its bytes.

**Cost** is stated here in TB-months on purpose: ~190 TB transferred, order 30-40 TB resident. Pricing must be
checked at purchase rather than quoted from this document. Inbound transfer is free and requests are not the
expensive part, so the decision turns on the resident storage class and on how much raw text is worth keeping.

## Sizes, tiers, and the query path (measured 2026-11-05)

Measured over 125 real DER blobs (certifi's bundle plus this workspace's fixtures — mean **1,050 bytes** each) with
zstd, because the intuitive answer — certificates are text-ish, they will compress — is wrong, and the wrongness is
load bearing.

| Measured | Result |
| --- | --- |
| signature + SPKI as a share of a certificate | **median 62%** (range 28%-79%) |
| zstd-19, one frame per certificate | **1.14×** |
| zstd-19, all certificates as a single stream | **1.40×** |
| zstd-19, per certificate with a trained 16 KB dictionary | **1.50×** |
| zstd-12 on a column of SHA-256 digests | 64,000,000 → **64,001,477** |
| spine `leaf_hash` column | **32.00 B/leaf**, irreducible |
| spine `issuer_key_hash`, **sorted** | **0.003 B/leaf** |
| spine `issuer_key_hash`, unsorted | **2.047 B/leaf** |
| spine timestamp + leaf_index deltas | ~**0.000 B/leaf** |

*How these were measured:* inputs were certifi's `cacert.pem` (120 blocks) plus this workspace's five DER
fixtures; `zstd` at level 19 for the certificate rows and level 12 for the megabyte-scale columns; the spine
columns from 2,000,000 synthetic rows, seed 20261105, 300 distinct issuer keys in 100,000-row runs, leaf hashes from
`random.randbytes` so the column is genuinely incompressible. A CRL and a defect fixture are excluded from the
signature-share statistic (124 of 125 parsed): the CRL fixture is the single blob `parse_certificate` refuses, and
that is the decoder working, not a gap in the measurement.

**Certificates are deduplicable, not compressible.** A median 62% of every certificate is a signature and a public
key — random bytes by construction — so the ceiling on *distinct* certificates is about 1.5×, and per-record
compression is the worst case at 1.14×. The savings are in layout and in not storing the same thing twice:
**sorting the issuer-key column is worth 680×, which is more than any compressor will ever return.**

**The thing that answers queries is about a terabyte.** At 33.83B leaves the spine — leaf hash, log, leaf index,
timestamp, issuer key — is **1.08 TB**. Full DER for every leaf is **35.5 TB** before deduplication, which lands on
this document's "order 30-40 TB resident" from an independent direction. The 190 TB figure stays wire cost.

**Provability and interpretability are different tiers, and only one of them may be sampled.** RFC 9162 §2.1.2 gives
the algorithm for checking a list of entries against a signed tree head, and it opens by naming the precondition:
"When a client has a complete list of entries from 0 up to tree_size - 1". It also needs only
`HASH(0x00 || entries[i])` per entry — the **leaf hashes**, not the certificates. (RFC 6962 §2.1 defines the same
construction for the v1 logs still in service, `MTH(D_n) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`; 6962 is itself
obsolete, superseded by 9162, so the successor is what to cite.) That makes the ~1.1 TB hash spine the artifact that
buys coverage claims, and it is cheap enough to keep complete and hot forever. The DER is what lets anyone say
something about a certificate's *content*, and selectiveness there is a policy decision that must be recorded in the
artifact's coverage metadata: a store that kept every tenth certificate can answer questions about what it kept and
nothing else. So **age-tier whole closed windows, never sample inside one** — a partial leaf-hash set cannot
recompute a root, and the window's claim would die silently rather than fail loudly.

### Tiers, with the rules that actually bind

Read off AWS's own storage-class table rather than from memory — which matters, because the "140 KB minimum billable
object size for Deep Archive" figure in circulation is not what the current table says:

| Class | Minimum duration | Per-object overhead | First byte |
| --- | --- | --- | --- |
| Glacier Deep Archive | **180 days** | **+40 KB metadata** (32 KB at DA rate, 8 KB at Standard) | hours |
| Glacier Flexible Retrieval | **90 days** | **+40 KB metadata** | minutes to hours |
| Glacier Instant Retrieval | 90 days | **128 KB minimum billable object size** | milliseconds |
| Intelligent-Tiering | — | objects **under 128 KB never auto-tier** (always Frequent rates) plus a per-object monitoring charge | tier-dependent |

The binding constraint is therefore **object count, not gigabytes**, and it bites twice. Writing 33.83B one-object-
per-leaf entries would cost roughly **$152,000 in write operations alone** at R2's published $4.50 per million, and
40 KB of archive metadata on a 1 MB object is 4% of the object. At 1-4 GB per object both effects vanish
(0.001%-0.004%), which turns the `<start>-<end>` segment layout above from a style choice into a requirement: a
segment that happens to be one page is a disaster. The pack is also the **restore unit**, because the archive
classes restore whole objects — so 1-4 GB is the granularity at which an audit reads, and the offset index carried
in the spine is what lets a single record be pulled with an HTTP range request and nothing restored at all.

**Lifecycle rules beat Intelligent-Tiering here**, precisely because the access pattern is known: harvest data is
written once, read perhaps, never read again on schedule. IT exists for unknown patterns and charges per object to
discover what we already decided.

**Egress, not storage, is what a public artifact pays.** R2 publishes **free egress** at $0.015/GB-month Standard
($0.01 IA, plus $0.01/GB retrieval, 30-day minimum duration); AWS charges egress per GB and its numbers render
dynamically, so they belong in a purchase decision rather than in this document — the same reason the figures here
are TB-months. That produces a design bar rather than a vendor choice: **a dataset nobody can mirror is not an
artifact.** A 1.1 TB spine is mirrorable by one person over a home connection in hours; a 35.5 TB DER tier by an
institution; a 190 TB JSON archive by nobody, which makes it private in practice whatever the licence claims.

### Where Athena fits, and where squashfs does not

Athena bills **$5.00 per TB scanned**, and its own pricing example confirms that partitioning, compression and
columnar layout all reduce what is billed. Worked against the sizes above: a full spine scan is **$5.40**, a
log-and-month slice is around **$0.01**, the whole DER tier is **$178**, and the raw 190 TB JSON would be **$950**
per query. That makes Athena the right tool for *counting the world* — a scheduled audit re-deriving coverage
numbers for a few dollars a month — and the wrong tool for the hot question. "Is fingerprint F in log L, and what
did CA X issue in March" is a key-to-posting-list lookup, and a scan engine holds no index for it. So the answer
path stays sorted columnar segments plus a sparse offset index served by range requests, and both consumers read the
**same files** — which is what keeps the artifact shippable instead of becoming a database somebody has to operate.

**squashfs is the wrong tool for the store and a good tool for the bundle.** Its image must be built whole: there is
no cheap append, so a 33-billion-record growing dataset means rebuilding images, and its compression runs per block
over what are, for us, small records — the 1.14× case measured above rather than the columnar one. Where it belongs
is shipping a bounded, read-only corpus: a per-snapshot trust-anchor bundle, a conformance corpus, Android's
one-PEM-per-file directory — one file, one checksum, mountable and greppable instead of 500,000 small files to
unpack. Same reasoning as the pack above, opposite conclusion, because the access pattern differs.

### Still unmeasured, in the order it would be worth measuring

- **Log-to-log duplication: first numbers, and they are not one number.** `ctspy/tools/duplication_probe.py`
  sampled the tail of six logs (1,024 entries each) and joined on the entry's own bytes, not the leaf hash — which
  differs per log by construction (RFC 6962 section 3.4 puts the log's timestamp in the leaf). **Within a log: no
  repeats at all** — 1,024 distinct entries out of 1,024 in each of the six, so static-merge redundancy is not what
  the DER tier is paying for in these windows. **Between logs it depends entirely on the CA**: Sectigo's
  Mammoth2026h2 and Sabre2026h2 shared **31.7% of entries** in their common interval (325 of 1,024; 1,963 leaves
  collapsing to 1,638 distinct, a **1.2×** deduplication), while DigiCert's two Wyvern logs shared **zero**, as did
  DigiCert against Google Argon2027h1 (**1.0×**). That is consistent with a browser policy requiring two SCTs from
  two *operators* — two logs of one operator buys nothing, so DigiCert does not duplicate across its own pair while
  Sectigo does anyway. Two honest limits: the windows are seconds wide, and pairs whose spans failed to overlap
  reported `no common interval`, which is an artifact of sampling logs sequentially rather than a fact about them.
  So the DER tier's deduplication factor is **operator-specific and currently bounded near 1.0×–1.2×**, not a fleet
  constant. Settling it needs the concurrent (or timestamp-seeked) version of the probe, and Cloudflare's Nimbus
  logs, which were not among the six and are where static-merge would show up if it shows up at all. The byte-level
  versus key-level trap still stands: 29 anchors are shared between certifi and this machine's store *by key* while
  all 125 fingerprints differ.
- **Whether the spine answers the first claims.** If the question is "did CA X issue this", 1.1 TB is enough and the
  DER tier may start selective; if it is "what does this certificate say", the tier order flips. Cheaper to decide
  now than after 40 TB exists.
- **The polite rate that is actually tolerated per operator**, which is a wall-clock constraint on 537M requests and
  has nothing to do with storage. It stays the reason the STH journal goes first.

## Sequenced, so that "start gathering" can mean today

1. **STH journal on.** Hours of work, ~0.4 MB/day, needs no anchor decision, republishes no certificate content,
   and is monitoring-only — the use the log-list policy already permits. Every day it is off is a set of heads
   nobody can recover.
2. **A preservation pass over the beginnings** of the 23 answering logs: a bounded slice each, gigabytes.
3. **The page-size survey done properly** — several observations per log rather than one per operator — so the
   sizing rests on measurement instead of five samples. **Done 2026-11-05** (`ctspy/tools/page_caps.py`, all 23
   usable logs, four ask sizes each), and it broke the assumption above rather than confirming it: entries per
   response ranged 1 to 250 and moved between two runs of the same log, while bytes per entry held at 4.5–8.2 KB.
   The survey's value was to replace the request-count estimate with a byte-count estimate, not to refine the
   former.
4. **Enumerate the delisted logs.** The current list cannot report logs that already left it; the historical
   universe has to be reconstructed from Chromium's own history of the log list. Until then the fleet total above
   means "logs that still exist", which understates what has already been lost.
5. **Then the walk**, log by log and budget by budget, publishing coverage as it goes.

## The goal, restated against what is collectable

*Every certificate issued by every globally trusted CA* is three different objectives:

- **Every certificate logged to a live CT log** — collectable: 537M requests, tens of TB resident.
- **Every certificate issued** — not collectable. Unlogged issuance is invisible by construction, and
  `INCIDENT-CT-FORENSICS.md` shows why no query rescues that.
- **Every code-signing certificate** — not in CT at all. Two of the eight compromised eMudhra keys were
  code-signing CAs, which is exactly this hole.

"Every globally trusted CA" needs a source too, and it cannot be the logs: **`get-anchors` is served by nobody**
and RFC 6962 defines no equivalent, so the anchor set must come from the store catalogs `trustatlas` is designed
to build. The two projects close a loop — `trustatlas` defines the scope, this collects the population, and SPKI
SHA-256 is the join between them.

## Unverified

- Page sizes: one observation per operator, from index 0. 32 and 256 are observed caps, not proven maxima.
- Retired-log reachability: one real retired log, already unreachable. That is a data point, not a rate.
- The 30-40 TB deduplicated figure: untested. Measuring it is the first job of the preservation pass.
- Whether delisted-but-still-serving logs exist. Step 4 is that check, and it may find nothing or a great deal.
