# CT forensics for a compromised intermediate: what the record can and cannot answer

Written 2026-11-05 while assessing whether this workspace could answer questions raised by the
[eMudhra intermediate CA compromise](https://emudhra.we-have-a-problem.com/) write-up (Dennis Jackson's
site; reporter "Wayne"; original report to the root programs 2026-10-17).

This is a findings document, not a plan. Everything below was measured on 2026-11-05 from this machine
unless a line says otherwise. Where a claim is bounded, the bound is stated because an unbounded version of
it is what got this repository into trouble before.

## What the write-up says, and what reproduced

The claim: private keys of **eight eMudhra intermediate CA certificates** are compromised, and the keys were
generated so badly that **anyone can recover them from the certificate itself** — so the exposure dates from
certificate creation (April 2025), not from any break-in date. Revocation and root-program blocks are
described with per-program dates.

I re-derived the published data instead of trusting the page. From its `impacted-intermediates.json` and
`roots.json`:

| check | result |
| --- | --- |
| SHA-256 of certificate DER vs published `sha256` | 20/20 match |
| SHA-256 of issuer SPKI vs published `spki_sha256` | 20/20 match |
| Signatures on the 16 intermediates, checked against their stated issuers | 16/16 verify |
| Distinct compromised keys | **8** |
| Compromised key roles | 6 TLS (`EM DV/OV/EV TLS CA - G3B/G3C`) + **2 code-signing** (`EM OV CS CA - G3B/G3C`) |
| Certificates per key | 2 — original (`notBefore 2025-04-30`, `ecdsa-with-SHA384` under an eMudhra root) and a **cross-sign dated 2025-05-14 issued by `AAA Certificate Services`** (Comodo/Sectigo) |

The cross-sign is the analytically load-bearing fact and it is nearly invisible in the prose: the blast radius
is not eMudhra's own roots, it is **Comodo's AAA root**, which is in almost every trust store. That is why the
site's Android guidance tells users to disable *AAA Certificate Services* and warns it may break unrelated
sites.

One note for us specifically: all 16 certificates are **P-384 / SHA-384** (and one of their roots is a
SHA-1-signed 2004 certificate), which `ctspy` deliberately does not verify — its verifier is P-256/SHA-256
only, correct for CT log signatures and wrong for X.509 chains. Chain validation, if we ever need it, belongs
in `pkix`/`asn1core`, not there.

## The query predicate

RFC 6962 §3.2 ¶8 defines `issuer_key_hash` as the SHA-256 of the issuer's public key over its
`SubjectPublicKeyInfo` DER — exactly the attribution key `certledger`'s CA graph already uses for
pre-certificates. The eight hashes to search for:

```text
EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105  EM DV TLS CA - G3B
43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B  EM OV TLS CA - G3B
E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41  EM EV TLS CA - G3B
49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F  EM DV TLS CA - G3C
63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8  EM OV TLS CA - G3C
5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0  EM EV TLS CA - G3C
EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6  EM OV CS CA - G3B
92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30  EM OV CS CA - G3C
```

## The finding that reframes the question: a log cannot be asked whether it holds a certificate

The obvious move — for each of the 23 usable logs, ask `get-proof-by-hash` for the intermediate's leaf hash
and read "every log says not found" as a strong absence claim — **does not work, and not for operational
reasons but by the protocol's design.**

A v1 tree leaf is `version ‖ leaf_type ‖ uint64 timestamp ‖ entry_type ‖ signed_entry ‖ CtExtensions`
(RFC 6962 section 3.4 paragraph 5, which defines `MerkleTreeLeaf` with the single `timestamped_entry(0)` leaf
type; RFC 9162 obsoletes that document and replaces `MerkleTreeLeaf` with `TransItem` for v2 — section 1.3 —
while every capture in this repository is a v1 tree, parsed as such by `ctspy.sth.SignedTreeHeadV1`). The
`timestamp` is the **log's own** submission time, chosen when the entry was accepted. So the leaf hash is not
a function of the certificate: two logs holding the same certificate have different leaves, and nobody
outside a log can compute the hash that log used.

I found this by being wrong first. A hand-built leaf (`version ‖ entry_type ‖ 3-byte length ‖ DER`) was
compared against the leaf octets a production log had actually served, stored in our corpus, and disagreed —
the stored bytes carry an 8-byte timestamp where my construction had the certificate. What makes that
comparison legitimate is RFC 6962 section 4.6 paragraph 7: `get-entries` returns `leaf_input` as "the
base64-encoded MerkleTreeLeaf structure", so those bytes are the tree's own leaf and not a rendering of it.
The self-check existed for exactly this reason and it fired before any conclusion was drawn. Without it I
would have queried 23 logs with a hash that cannot match anything and reported "no issuance found".

The consequences are the important part:

- `get-proof-by-hash` is a **possession** proof, not a membership query. It works only for an entry whose
  timestamped leaf you already have — from the log itself (`get-entries`), or rebuilt from an SCT, since an
  SCT carries the timestamp.
- "Was anything issued by this CA?" is therefore answerable **only from a store**: a full log walk, an
  archive, or somebody's index. Never from the logs.
- The verification direction we can build is the one nobody else offers: given a certificate *and its SCTs*,
  `ctspy.sct.parse_list` recovers each SCT's timestamp, the leaf can be rebuilt, and that log can be asked
  for an inclusion proof — turning "an index has a row" into "this log signed a tree containing this entry".
  That is the differentiated capability, and it is the concrete next build.

## What an index actually returned, and how much that is worth

`crt.sh` with `?q=<CA name>&output=json` and **no** `exclude=expired`: forged 2025 certificates would be
short-lived and expired by now, so filtering expired certificates out would hide exactly what is being looked
for.

| CA | rows | certificates it issued, per the index |
| --- | --- | --- |
| `EM DV TLS CA - G3B` | 3 | 0 |
| `EM OV TLS CA - G3B` | 2 | 0 |
| `EM EV TLS CA - G3B` | 2 | 0 |
| `EM DV TLS CA - G3C` | 2 | 0 |
| `EM OV TLS CA - G3C` | 2 | 0 |
| `EM EV TLS CA - G3C` | — | **HTTP 502** |
| `EM OV CS CA - G3B` | 2 | 0 |
| `EM OV CS CA - G3C` | 2 | 0 |
| *control* `EM DV TLS CA - G3A` | 4 | **2** |
| *control* `EM OV TLS CA - G3A` | 4 | **2** |
| *control* `EM EV TLS CA - G3A` | — | **HTTP 502** |
| *control* `EM OV CS CA - G3A` | 4 | **2** |
| *control* `EM DV CS CA - G3A` | — | **HTTP 502** |
| *control 2* `EM DV TLS CA - G3A-1` | 2 | 0 |

The control does establish that `q=` matches **issuers** and not merely subjects: the uncompromised sibling
G3A series returns certificates it issued, so the zeros above are not simply a wrong query.

The control is also **weaker than it first looked**, and this is the part that keeps the conclusion small.
The children it found are themselves CA certificates (`EM DV TLS CA - G3A-1`), and when that child is queried
in turn it shows no leaves either. I have not established that this query surfaces forged *leaf* certificates
at all. So what is defensible is: this index reports no issuance by seven of the eight compromised CAs, and
the query is capable of returning issued certificates. It is not: CT contains no issuance by the compromised
keys.

Two further bounds. Three of the fourteen queries in the table failed with HTTP 502 and a single successful
query took up to 24.8 s, so the instrument is slow and intermittently broken; and one third-party index is one
path, which is exactly what TRUST-MODEL I7 forbids leaning on for an absence claim.

The write-up's reassurance — "there are no entries in the certificate transparency logs for these
intermediates in that period" — is the same class of statement. It is very likely right for the clients it
names, and its strength is entirely a function of coverage that no public page can document and that we could
not verify from here.

**Code signing is outside CT entirely.** Two of the eight compromised keys are code-signing CAs. "Must be
logged" governs TLS server authentication; a forged Authenticode signature will not appear in a CT tree no
matter how complete the sweep. The site's own Windows mitigation blocks Schannel *and Authenticode*, so the
exposure is acknowledged there, but the CT-based reassurance does not reach half the compromised keys. For
those the only instruments are CRL/OCSP (both revoked, reason `ca_compromise`) and whether a client checks.

## What we hold, and what it proved

`certledger`'s verified fixtures — the 236-entry Nimbus2027 prefix, three proved mid-tree windows and two
Sectigo peers: **430 entries** (250 pre-certificates, 180 X.509) — were run against the eight hashes: **zero
hits**. Out of well over a billion entries across 23 logs, that zero means nothing. It is recorded only so
that nobody later mistakes it for a finding. Incidentally, one chain certificate in the corpus trips
`cryptography`'s warning for a non-positive serial number, which RFC 5280 disallows — worth pinning as an
interop data point in its own right.

## Bulk sources: what I could actually reach

The "just download an archive" instinct behind a lot of CT planning did not survive contact with the network:

| source | result |
| --- | --- |
| GCS buckets `google-ct-logs`, `chrome-ct-source`, `google-pki-ct-logs` | **404** — not publicly present |
| GCS bucket `ct-logs` | **401** — exists, not public |
| crt.sh front page | no dump/bulk/CSV/API link in 5.9 KB of HTML |
| crt.sh `?CAId=<id>&output=json` | `Unsupported output type: json`; the HTML view timed out at 24 s |
| HTML search engine from this machine | blocked |

There is no free bulk path from here. Realistic options, in cost order: a per-CA index query (works, slow,
one path, leaf coverage unproven); an account-backed dataset such as Censys, CertSpotter or Rapid7 (needs
credentials and an answer to `cl.aup-review`); or the full walk, at roughly 7.6M requests per half-year Google
log using the 32 entries per request measured from this network — gated on the fetch layer and the anchor
decision, as it has been all along.

## Prerequisites, ranked

To enumerate issuance by a compromised intermediate:

1. Decide the corpus source. This is the blocker, not code.
2. A persistent store keyed `issuer_key_hash → (log, index, leaf hash)`. `EntryStore` is in-process and sized
   for hundreds of records; an incident corpus is millions. This is the deferred persistent entry store.
3. The anchor decision: which logs, pinned to which heads. Absence claims are worthless without it.
4. Per-log coverage accounting (`GapState` over every unfetchable range) shipped *with* any "we found nothing".
5. SCT-based verification of whatever candidates turn up, so a result is evidence rather than a row in
   somebody else's database.

For a public web interface, building another CT search engine is a poor bet: indexing is a commodity with
decade-old incumbents, and I measured one of them timing out during this work. The defensible shape is a
**verifier** — submit a chain or DER, answer "does it chain to a blocklisted key, via which cross-sign, and is
there a signed tree that commits to it" — plus per-log coverage reports. Prerequisites before that is honest
rather than pretty: the store, the anchor decision, and `cl.claims-discipline`, because a public page is
precisely where "all certificates" language creeps in. A multi-user service also makes the server's vantage
the only witness, which is what `cl.multi-path` (a second vantage, i.e. money) exists to break.

## Not established here

Whether the compromised keys were ever used; whether any un-logged certificate exists (CT cannot see one, by
construction); what fraction of any index's contents matches the predicate; and any code-signing exposure. The
first two are outside what CT can answer at all. The last two are within reach and still to be done.

## References

- The incident write-up: <https://emudhra.we-have-a-problem.com/>, and its machine-readable
  `impacted-intermediates.json` (16 certificates: names, subjects, serials, SHA-256, SPKI SHA-256, SKI/AKI,
  validity, revocation, PEM) and `roots.json` (4 roots with per-program inclusion status). All 20 PEMs
  re-parsed and re-hashed locally; all 16 signatures checked against their stated issuers.
- RFC 6962 (EXPERIMENTAL, 2013-06, now obsolete) §3.2 ¶8 for the definition of `issuer_key_hash`; §3.4 ¶5 for
  the `MerkleTreeLeaf` structure; §4.6 ¶7 for `leaf_input` being the encoded tree leaf.
- RFC 9162 (EXPERIMENTAL, 2021-12), which obsoletes RFC 6962, §1.3 for `MerkleTreeLeaf` being replaced by
  `TransItem`.
- `ctspy/docs/interop.md`, item 3, for the fleet-wide inclusion-proof result and the retraction that preceded
  it. The evidence is reproducible: `tools/fetch_evidence.py inclusion_sweep()` writes
  `fixtures/production-inclusion.json`, and `tests/test_production_inclusion.py` re-verifies it offline. This
  document's "possession, not membership" distinction is about exactly that capability.


