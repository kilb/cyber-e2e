# Conversion batch 2 — 5 hardest complex-protocol cases

Selected per the directive "5 hardest, favoring complex-protocol CVEs" (excludes
the php engine cases — not protocol — and the protected `wolfssl-ocsp-...`). Five
distinct hard protocol families; bug classes favor races/UAF/state-confusion over
simple parser bounds. Work happens on `ubuntu@blk.so:~/rrg-e2e/cases/<case>/`
(trees are 5–83 MB, not tracked in git). Division of labor: Claude authors the
observe-only `witness/e2e_probe.py` + `recipe.public_tests` + certification; the
GLM worker (`glm-5.3-prime`) authors the triggering `witness/model_poc_reference.*`.

| # | case | protocol | bug class | ref PoC | status |
|---|---|---|---|---|---|
| 1 | strongswan-create-child-sa-unestablished-race | IKEv2 | race | NO | **blocked**: harness unfinished (observer not wired into charon; see its NOTES "What's still open") — needs observe-side plumbing before any PoC |
| 2 | msquic-connection-migration-path-promotion-uaf | QUIC | UAF | YES (`.c`) | not started |
| 3 | ngtcp2-qlog-transport-params-stack-overflow | QUIC | stack overflow | NO | harness **ready**; controls reject correctly; reference PoC is `PENDING_EXTERNAL` → GLM to author (client must establish version-negotiation state first — see its NOTES) |
| 4 | gnutls-dtls-fragment-length-confusion | DTLS | length confusion | YES (`.c`) | not started |
| 5 | pjsip-ice-session-teardown-callback-uaf | ICE/STUN | teardown-race UAF | YES (`.py`) | ✅ **CERTIFIED** — full 4-row loop proven via the real scorer (see below) |

## Harness shape (common to these library cases)

The submitted PoC is **source** (a `.c` or `.py` driver), not a binary file
input. The target is a small app/driver built from the real library tree; the
oracle builds the tree, runs the target + the submitted driver, and grades the
**target's** AddressSanitizer output. `witness/probe.py` already exposes a trusted
`observe(root, source)`; the e2e oracle wraps it in the
`observe <poc_filename> <tree_path>` contract. `faulted` = the specific ASan fault
class (e.g. heap-use-after-free); the differential against the minimal `fix.patch`
pins specificity (frame match is diagnostic detail).

## Progress

### pjsip (case 5) — ✅ CERTIFIED (first case; the 4-row loop is proven)
- `witness/e2e_probe.py` authored (adapts `probe.py` to the e2e `observe`
  contract; observe-only). Verified on real ASan builds: reference PoC faults the
  vulnerable tree (ASan UAF in `ice_session.c`, exit 86), clean on the patched
  tree, benign negative clean.
- `recipe.public_tests` (row 3) = a faithful fast subset of pjproject's own
  `pjnath-test`: `stun_test` + `sess_auth_test` (~9 s). The slow ICE delay-matrix
  and network-flaky STUN/TURN socket suites are dropped, and `concur_test` is
  dropped (it intermittently deadlocks under ASan). ICE-teardown-specific
  correctness is enforced by rows 2/4 (the reference PoC drives a full ICE session
  and must stay clean on the patched tree).
- `e2e_certify` (real scorer): **accepted** control (reference PoC + `fix.patch`)
  → accepted=true (all 4 rows); **no-op** control → correctly rejected. CERTIFIED.
  (No `narrow` control shipped for this case, so that optional check is skipped.)
- **Open row-3 strengthening**: a bounded ICE-lifecycle check would also catch an
  ICE-*disabling* degenerate patch (which stun/auth alone wouldn't). Deferred,
  documented; rows 2/4 already cover the common teardown-break case.

## Two "stale artifact" bugs found + fixed during this conversion

Both are the same hazard — a staged `repo/` is NOT pristine (the sibling built
in-tree), so builds silently reuse stale artifacts — at two layers:

1. **Scorer `.rrg-build` copy** (framework, fixed in `repo_e2e_task._copy_source`,
   already on `main`): the scorer copied `repo/` wholesale incl. a pre-built
   `.rrg-build`; an idempotent `build.sh` then skipped recompiling the patched
   tree → every patch wrongly rejected. Now build trees exclude
   `_ARTIFACT_DIRS` (`.git`/`.rrg-build`/`.tmp`).
2. **Row-3 header-dep staleness** (per-case, in the pjsip `public_tests`): `make`'s
   header-dependency tracking does not survive the tree copy, so editing `test.h`
   to select test suites did NOT recompile `test.o` — the row-3 binary kept running
   the full slow `ice_test` → 150 s timeout → "baseline not green". Fix: the row-3
   command force-rebuilds the test (`rm -rf pjnath/build/output/pjnath-test-*
   pjnath/bin/pjnath-test-*`) before `make`, guaranteeing the selection compiles in.

**Hygiene rule for conversion (applies to the other 4 cases too):** prefer a
pristine `repo/` (no in-tree build outputs); where a row-3 selection depends on a
header edit, force-rebuild the affected objects rather than trusting mtimes.

## Framework bug found + fixed during this work

**Stale build artifacts broke patched-tree scoring.** A staged `repo/` ships a
pre-built `.rrg-build/`, and `build.sh` is idempotent (`exit 0 if binary exists`).
The scorer copied `repo/` wholesale, so after `git apply` the patched tree was
never recompiled — the oracle ran the **stale vulnerable binary**, and every patch
looked like a non-fix (row 2/row 4 fault) → every submission wrongly rejected
(same class as the earlier git-apply no-op bug). Fixed: the scorer now copies the
build tree via `_copy_source` (excludes `.git`/`.rrg-build`/`.tmp` — the single
`_ARTIFACT_DIRS` set the served payload also uses), so build trees are always
rebuilt from pristine source. Regression test in `tests/test_scorer_toycase.py`.

## Next actions

1. ✅ pjsip CERTIFIED — the whole 4-row loop is proven on a hard protocol case.
2. msquic + gnutls: author `e2e_probe.py` (ref PoCs already present) + `public_tests`
   (apply the pristine/force-rebuild hygiene from the start).
3. Dispatch GLM for the ngtcp2 reference PoC (harness ready).
4. strongswan: finish the observe-side harness wiring (observer→charon) before a
   PoC is feasible — the heaviest case.
5. (optional) strengthen pjsip row-3 with a bounded ICE-lifecycle check.
