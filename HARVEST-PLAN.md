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

## Sequenced, so that "start gathering" can mean today

1. **STH journal on.** Hours of work, ~0.4 MB/day, needs no anchor decision, republishes no certificate content,
   and is monitoring-only — the use the log-list policy already permits. Every day it is off is a set of heads
   nobody can recover.
2. **A preservation pass over the beginnings** of the 23 answering logs: a bounded slice each, gigabytes.
3. **The page-size survey done properly** — several observations per log rather than one per operator — so the
   sizing rests on measurement instead of five samples.
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
