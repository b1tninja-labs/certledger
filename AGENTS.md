# Instructions for coding agents

**Phase 0 landed on 2026-11-05, and phases 1 and part of 2 have landed since.** This directory is a package -
`certledger/`, `anchors/`, `keys/`, `tests/` and a `pyproject.toml` - because `PORTFOLIO.md` section 7
schedules "certledger phases 0 and 1" inside wave 1. `ROADMAP.md` says exactly what is closed, what is open,
and what it waits on; the fetch layer still waits on a human anchor decision, and the package still does not
reach the network itself. `walk.py` carries the completeness discipline in code: an unread range is recorded
as *unfetched* and never as *absent*, and completeness is the stored leaves' tree hash equalling the signed
root - so do not simplify `WalkReport.complete` or `may_claim_absent` into a comparison of counts.
`states.py` holds the section 8 state machine, and `assess` is the only way to produce a state: publication is
gated by derivation (`publishable`, `supports_absence`), never by a field a caller sets, and a freeze outlives
every subsequent good pass until a `HumanDecision` naming a person and a date clears it.

The rest of this file is unchanged, because none of it is affected by there being code.

## Finding work

If the person gave you a task, do that task.

If you arrived with nothing to do, run this from this directory:

    python ../sdk-forge/loop.py pickup --who <your name> --project certledger

Its output is your assignment: one row, already claimed for you, with what to build, the commands that prove
it and the ways to end it. The board decides the order of work, so the row it gives you is the row to work,
even if it is in another project. `NO WORK` is a real answer: ask the person what to work on.

Without the workspace beside this repository, read `.forge/packet.md` if it exists. If it does not, ask what
to work on.

## Read in this order

1. `TRUST-MODEL.md` - adversaries, what each control layer defeats, and what it explicitly
   does not. This is the authority on security properties.
2. `PLAN.md` - components, objects, the acquisition loop, the path interface, and what is
   deliberately not built.
3. `ROADMAP.md` - obligations, each naming the adversary it closes, with a named test.

When they disagree, the trust model wins on security properties and `ROADMAP.md` wins on
protocol facts. Neither wins on sequencing: that is `D:\code\PORTFOLIO.md`.

## Specification discipline

`rfclib` is the source of truth for what the documents say. Two traps specific to this
project, both already paid for once:

- **RFC 6962 is Obsolete.** It was Experimental and was obsoleted by **RFC 9162 (CT version
  2.0, 2021-12), which is also Experimental** - CT has never been an IETF Standard. The
  deployed wire format at logs is version 1, so v1 text stays operationally relevant, but a
  citation must say which version it means. Check with `rfclib.info("RFC9162")` and
  `rfclib.errata("RFC9162")` before writing a row, not after.
- **Chrome's log list is licensed, not free to use.** `rfclib` will not tell you this: the
  acceptable-use policy permits monitor and auditor use, forbids driving CT enforcement in
  non-Chrome clients without written permission, and reserves unannounced changes. Legal
  review is a launch gate.

Use `rfclib.read("RFC9162§2.1.1", view="normative")` for the consistency-proof wording
rather than reproducing it from memory, and `rfclib.cite(...)` in the commit message so the
citation is checkable.

## Invariants the code must not trade away

These are the ones an agent is most likely to "simplify" into a bug:

1. **No ambient trust.** Never `load_default_certs()` or `set_default_verify_paths()`; never
   read proxy or certificate-store environment variables; every client built with
   environment trust disabled, because the defaults honour `HTTPS_PROXY` and `SSL_CERT_FILE`.
2. **Authenticity comes only from a log signature over a pinned key.** A successful fetch, a
   valid TLS chain and an HTTP 200 are not evidence that content is genuine.
3. **Verify over stored original bytes.** Never over a re-encoding.
4. **Tree heads never shrink.** A smaller head than the pinned one stops the run and pages;
   it is not clamped, corrected or retried away.
5. **Absence needs corroboration.** No single path may ever support a "not in the log" claim.
6. **Every object carries a receipt.** An observation without a path, vantage and peer
   identity is not publishable data.
7. **Never silently downgrade.** A failed DNSSEC or TLSA check moves data to
   `UNAUTHENTICATED`, which is unpublishable - it does not fall back with a log line.
8. **Never claim "all certificates".** Unlogged issuance is invisible to CT by construction;
   the limit is stated in trust model §9 and obligation `cl.claims-discipline` protects it.

## Evidence fixtures are opt-in, and they are evidence

`tests/fixtures/*` is gitignored with per-file `!` re-inclusions, because the directory also holds
throwaway keys and derived manifests that must never be committed. A new fixture is therefore **silently
ignored until it is re-included in `.gitignore`**, and a test written against it passes locally and fails in
a fresh clone. Add the `!` line in the same commit as the fixture, and say in the comment above the list why
the file counts as evidence rather than build output.

The distinction the list defends: a fixture is evidence when it cannot be regenerated - its bytes are bound
to a signed tree head that no longer describes the log's current tree. `entry-corpus.json` (prefix, bound by
a consistency proof) and `midwindow-corpus.json` (proved slices from two tree midpoints, written by
`tools/corpus.py --window`) both qualify; anything a test can create at runtime stays ignored.
