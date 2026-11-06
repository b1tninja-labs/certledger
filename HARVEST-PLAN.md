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

Four caveats that change what those numbers mean:

- **The fleet total is the enforcement list's fleet, and that list is 19% short.** `log_list.json` carries 26 logs;
  Chrome's `all_logs_list.json` carries **45**, and the 19 it alone shows hold **13.63B leaves**, of which **6.52B**
  are publicly-trusted production issuance in the rejected 2026h1 generation (15 of the 19 still answer `get-sth`).
  Counting only usable+readonly gives 33.83B where the population is nearer **40.4B**. See `BROWSER-POLICY.md` §2.

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

### Two logs have stopped issuing — and the list says `readonly`, which I first misread as `usable`

Asking every listed log for the timestamp of its own newest leaf — the fleet's present defined by the logs rather
than by a clock — gives a **median head age of 0.0012 days and a spread of 414 days**, because two Sectigo logs
have stopped:

| Log | Newest leaf | Age | Tree size | List state | List seal |
| --- | --- | --- | --- | --- | --- |
| Sectigo Mammoth2026h2 | 2025-09-18T15:34Z | **414.31 days** | 57,634,084 | `readonly` | 57,634,084 ✓ matches |
| Sectigo Sabre2026h2 | 2025-11-11T05:01Z | **360.75 days** | 68,732,793 | `readonly` | 68,732,791 — **serves 2 more** |

Every other log's newest leaf was within 40 minutes of the probe; 22 of 23 answered at all. Three consequences.
**The live fleet is 20 logs, not 23** — "answers `get-sth`" measures availability, not issuance, and the walk
budget should follow the logs that are actually issuing. **These two need one finite pass and no watching**: their
trees are fixed at 126M leaves between them, about 2% of the Sectigo row in the table above, so they are cheap to
close out entirely. And **key on `tree_size`, never on the STH timestamp**: both frozen logs were signing fresh
heads an hour before the probe, so a staleness alarm built on head timestamps would have called them healthy.

This section originally described both logs as listed `usable`. That was wrong, and the correction matters more
than the error: `BROWSER-POLICY.md` §5 shows the list carries a `final_tree_head` per closed log, and my
`usable_logs()` helper deliberately folds `readonly` into the fleet for interop sweeps, which is fine for asking
"does the fleet answer" and misleading for asking "what does the list claim". Checking the seal against the served
tree is what turned a misread into two findings — Mammoth matches its seal exactly, and Sabre serves **two entries
beyond** a seal the list stamped 54 days before those entries were created.

### What period each log can witness

`tools/duplication_probe.py --era` asks each log for the timestamp of its first and its newest leaf — two requests
per log, and the only honest way to state what a log covers, since `get-entries` is indexed and never timed.
Measured at list v96.2, live logs abbreviated:

| Log | State | Tree | First leaf | Newest leaf |
| --- | --- | --- | --- | --- |
| DigiCert Wyvern2026h1 | `rejected` | 1.22B | 2024-07-02T01:49:08Z | **2026-06-30T23:59:58Z** |
| DigiCert Sphinx2026h1 | `rejected` | 1.10B | 2024-07-18T18:39:30Z | **2026-06-30T23:59:58Z** |
| Sectigo Sabre2026h1 | `rejected` | 88.7M | 2024-06-26T11:44:54Z | 2025-11-11T08:06:10Z |
| Sectigo Mammoth2026h1 | `rejected` | 65.2M | 2024-06-26T11:44:42Z | 2025-09-18T15:17:27Z |
| Sectigo Mammoth2026h2 | `readonly` | 57.6M | 2024-06-26T11:46:31Z | 2025-09-18T15:34:02Z |
| Sectigo Sabre2026h2 | `readonly` | 68.7M | 2024-06-26T11:46:37Z | 2025-11-11T05:01:07Z |
| DigiCert Wyvern2026h2 | `usable` | 2.21B | 2024-07-18T18:39:30Z | live |
| DigiCert Wyvern2027h1 | `usable` | 434.8M | 2025-09-10T10:41:55Z | live |
| Google Argon2026h2 | `usable` | 3.49B | 2024-06-13T10:43:47Z | live |
| Google Argon2027h1 | `usable` | 901.6M | 2025-07-31T18:09:26Z | live |
| TrustAsia log2026a | `usable` | 3.02B | 2024-04-30T07:49:47Z | live |

Three things this says that no field of the list does:

- **`rejected` is not always withdrawal for cause.** Both DigiCert logs stop at *exactly*
  2026-06-30T23:59:58Z — a handover on the half-year boundary, visible in the trees and not in prose. That answers
  a question `BROWSER-POLICY.md` §5 had left open pending the lifecycle explainer, at least for this generation.
- **A `readonly` timestamp is when Chrome recorded a state, not when issuance stopped.** Mammoth2026h1's last leaf
  (15:17:27) sits two hours *before* the 17:20:00Z stamp carried by its sealed sibling, and Sabre2026h1 kept
  issuing until 2025-11-11T08:06:10Z while Sabre2026h2's own last two entries are stamped 02:23 and 05:01 that
  same morning. The list's clock and the log's clock are different instruments.
- **The rejected generation's era is not orphaned.** `Wyvern2027h1` (from 2025-09-10) and `Argon2027h1` (from
  2025-07-31) both cover the DigiCert logs' final months, so a live witness exists in time. Whether it holds the
  *same certificates* is a content question, and it is the one that decides whether the extra 6.5B leaves enlarge
  the archive or merely restate it.

One more observation, labelled as weak: first-leaf timestamps repeat across logs — `Sphinx2026h1` and
`Wyvern2026h2` share 2024-07-18T18:39:30Z exactly, and all four Sectigo logs begin within 115 seconds of each other
on 2024-06-26. Identical first leaves suggest a shared submission stream at inception, but one instant is not a
fan-out measurement, and the pairs below are what a fan-out measurement looks like.

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

  A second run, this time fetching the logs **concurrently**, reproduced the two findings that matter and killed the
  method. Sectigo's pair shared **29.3%** (was 31.7%) — so same-operator fan-out is real and repeatable — while
  Google's own Argon2026h2 and Argon2027h1 shared **zero** across 164 and 208 entries in a common window, exactly as
  the two-SCTs-from-two-operators policy predicts. **Every cross-operator pair still came back `no common
  interval`**, and the reason is now visible rather than mysterious: the logs' growth rates span five orders of
  magnitude, so a tail of 512 leaves covers 2.7 s in DigiCert Wyvern2027h1 and 1,055 s in Sectigo Mammoth2026h2, and
  whichever log finished its pages last has its window entirely outside the other's. Comparing logs therefore needs
  every log seeked to **one agreed timestamp**, not to its own head — the tail method cannot be repaired by
  concurrency alone. Measured rates from the same run, which the walk budget needs independently of that: about
  190 leaves/s (DigiCert Wyvern2027h1), 43-48 (the two Google Argon logs), 27 (DigiCert Wyvern2026h2), 22
  (TrustAsia log2026b), 0.49 (Sectigo Mammoth2026h2) and near zero (Sectigo Sabre2026h2, whose last 512 leaves span
  53 days — a standby, not a log to walk). TrustAsia refused **both** of its logs at four-way concurrency after
  four attempts each, which the tool now records as a hole rather than grinding against; that ceiling, not
  bandwidth, is what the harvest schedule has to respect.

  **A third run seeked each log to one agreed instant, and it worked** — binary-searching `get-entries` for the
  index of a timestamp, anchored on the **median log head** rather than the host clock or the oldest head (both of
  which put the window in the wrong place: the oldest-head version landed in September 2025 because of the stale
  Sectigo logs above). Measured on the same cross-operator pair twice: **DigiCert Wyvern2026h2 shared 50.9% of its
  window with Google Argon2026h2** (302 of 593) in the present, against **77.7%** in a September 2025 window. So
  cross-operator fan-out is real, large, and **variable** — call it half to three-quarters — while same-operator
  pairs sit near zero (DigiCert's own pair and Google's own pair both shared nothing) except Sectigo's, at ~30%.
  Two things must not be read off this run. The aggregate "fleet factor" printed **1.06×**, which is meaningless:
  it was computed over a 3.459 s interval that four logs happened to share, and it averaged in the near-zero
  same-operator pairs that dilute exactly the signal being looked for. And **both Cloudflare logs returned NO
  DATA** — not because the seek failed but because their leaf timestamps trail the present by about 50 minutes, so
  a window centred on "now" quietly drops the static-merge logs, which are the one place intra-log duplication
  would still turn up. Anything that wants Cloudflare in the comparison needs a window measured in each log's own
  recent issuance, not in wall-clock seconds.

  What the numbers do support is the sizing decision. Intra-log duplication is **zero in every log that returned
  data across all four runs** — 21 log samples from tails and seeked windows alike — so a log's leaves are distinct
  entries; cross-operator duplication runs **half to three-quarters**, so
  the fleet's 33.83B leaves are on the order of **17-21B distinct certificates** rather than 33.83B, and the DER
  tier is **~18-22 TB rather than 35.5 TB**. That is the only large saving available in the blob tier, it comes
  from deduplication rather than compression, and it is bounded above by the logs never sampled here.
  **This estimate now needs re-running over the enlarged universe** — the ~40.4B leaves of `BROWSER-POLICY.md` §2
  rather than 33.83B. Whether it moves is an inference, not a measurement: the rejected 2026h1 leaves come from the
  same issuers adjacent in time, so they should dedup *better* than the fleet average, which is why the dedup factor
  stays an output of the harvest rather than an input to sizing.

**Cross-generation duplication, measured the same afternoon** (`--at` mode). The enlarged universe only matters if
the `rejected` logs hold certificates nobody else holds. One 60-second window on 2026-06-01, with both sides of
every comparison covering the whole interval they share:

| Comparison | Sampled | Shared | Reading |
| --- | --- | --- | --- |
| `Sphinx2026h1` × `Wyvern2026h1` — both `rejected`, one operator | 352 / 346 | **321 = 91.19%** | one copy, kept twice |
| `Wyvern2026h1` × `Wyvern2026h2` — `rejected` × live, one operator | 69 / 1,484 | **0** | ≤ 4.3% at 95% |
| `Wyvern2026h1` × `Argon2026h2` — `rejected` × live, other operator | 1,096 / 69 | **0** | ≤ 4.3% at 95% |
| `Wyvern2026h2` × `Argon2026h2` — live × live, the control | 784 / 1,074 | **267 = 34.06%** | the detector fires |

1. **The rejected leaves are not rejected certificates.** The DigiCert pair is ~91% self-duplicate, so its 2.32B
   leaves are roughly **1.2B distinct certificates** (Sectigo's two `rejected` logs add ~0.15B leaves and probably
   much the same story, untested). Enlarging the universe by 19% grows the spine by close to that and the DER tier
   by a good deal less — which is the sizing answer, and it is a measurement rather than the earlier guess that
   duplication would absorb the difference.
2. **Those certificates are nowhere else.** Zero shared entries with the same operator's live sibling *and* zero
   with a live Google log says the `rejected` pair is the surviving record of that era. The logs where the
   operator-distinct SCTs of that era would sit — `Google Argon2026h1`, `Xenon2026h1` — are already `404`. Chrome's
   two-operator rule is what produced the arrangement, so the same rule that makes a certificate provable is what
   left one copy.
3. **Preservation order flips.** A `rejected` log holding unique content outranks a live log that will still be
   there next quarter, and its tree is finite and already known (1,217,972,030 and 1,100,493,968 leaves), so it is
   a bounded job rather than an open watch. Step 2 of the sequence should take these two first.

What is *not* published from that run is the aggregate it also prints (a fleet factor of 1.1751×). It is a
property of which logs were sampled and at what rates — the same run's pairs differ by an order of magnitude — and
reporting it as a constant would repeat the mistake this tool has already made once with a "fleet factor". The
capture lives in `tests/fixtures/duplication-cross-generation.json` with `tests/test_duplication_capture.py`
asserting the four facts, because the logs it measured can be deleted and the claim should not have to be re-made
to survive.
- **Whether the spine answers the first claims.** If the question is "did CA X issue this", 1.1 TB is enough and the
  DER tier may start selective; if it is "what does this certificate say", the tier order flips. Cheaper to decide
  now than after 40 TB exists.
- **The polite rate that is actually tolerated per operator**, which is a wall-clock constraint on 537M requests and
  has nothing to do with storage. It stays the reason the STH journal goes first.

## Sequenced, so that "start gathering" can mean today

1. **STH and log-list journal on.** Hours of work, ~0.4 MB/day of heads plus ~170 KB of lists, needs no anchor
   decision, republishes no certificate content, and is monitoring-only — the use the log-list Acceptable Use Policy
   names explicitly ("CT monitors and auditors"). Four documents a day: `log_list.json`, `all_logs_list.json` and
   both 512-octet signatures, so membership is verifiable later without trusting whoever served it. Record
   **`tree_size` rather than head timestamp** as the advancement signal — closed logs keep signing fresh heads over
   dead trees (`BROWSER-POLICY.md` §5). Every day this is off is a set of heads *and a fleet membership* nobody can
   recover.
2. **A preservation pass over the beginnings** of the 23 answering logs: a bounded slice each, gigabytes.
3. **The page-size survey done properly** — several observations per log rather than one per operator — so the
   sizing rests on measurement instead of five samples. **Done 2026-11-05** (`ctspy/tools/page_caps.py`, all 23
   usable logs, four ask sizes each), and it broke the assumption above rather than confirming it: entries per
   response ranged 1 to 250 and moved between two runs of the same log, while bytes per entry held at 4.5–8.2 KB.
   The survey's value was to replace the request-count estimate with a byte-count estimate, not to refine the
   former.
4. **Enumerate the delisted logs — answered by measurement 2026-11-06, no archaeology needed.** Chrome publishes
   `all_logs_list.json` alongside the enforcement list: 45 logs vs 26, the extra 19 holding **13.63B leaves**, with
   **15 still answering `get-sth`** and 4 already gone (`Google Argon2026h1`, `Google Xenon2026h1`,
   `Let's Encrypt Oak2026h1`, `Google Solera2026h1`). Six of them are the rejected 2026h1 generation carrying
   **6.52B leaves of publicly-trusted issuance** — one year old, online today, and absent from the list every
   browser-facing tool reads. The walk must therefore take the union of `log_list.json`, `all_logs_list.json` and v2,
   record the state and list version each entry came from, and treat unreachable rejected logs as the loss budget
   they now are. Journaling both lists and both signatures daily costs tens of kilobytes and is the only way a later
   coverage claim can say what the world looked like when it was made (`BROWSER-POLICY.md` §2–§3).
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
- Retired-log reachability: the 3 `retired` logs in v3 are all unreachable, and 4 of the 19 logs absent from the
  enforcement list are unreachable too. Still a sample, not a rate — but the denominator is now published.
- The 30-40 TB deduplicated figure: untested. Measuring it is the first job of the preservation pass.
- ~~Whether delisted-but-still-serving logs exist.~~ Answered: **15 of 19 still serve**, holding 13.63B leaves
  between them (`BROWSER-POLICY.md` §2). Whether the rejected logs' certificates are already wholly present in other
  operators' logs is not answered, and the 51-78% cross-operator overlap says the answer is "mostly, not entirely".
