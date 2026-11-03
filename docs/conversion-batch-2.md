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
| 2 | msquic-connection-migration-path-promotion-uaf | QUIC | UAF | YES (`.c`) | ✅ **CERTIFIED** (see below) |
| 3 | ngtcp2-qlog-transport-params-stack-overflow | QUIC | stack overflow | NO | harness **ready**; controls reject correctly; reference PoC is `PENDING_EXTERNAL` → GLM to author (client must establish version-negotiation state first — see its NOTES) |
| 4 | gnutls-dtls-fragment-length-confusion | DTLS | length confusion | YES (`.c`) | ✅ **CERTIFIED** (see below) |
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

### msquic (case 2) — ✅ CERTIFIED (parallel agent)
- `witness/e2e_probe.py`: observe-only; `faulted = asan_uaf` (heap-UAF on the
  trusted msquic server); smoke-tested (ref→vuln faults, ref→fixed clean,
  negative→clean).
- `recipe.public_tests`: msquic's own `msquiccoretest` — 312 tests / 30 suites
  (incl. the connection-ID / path-challenge migration frames), excluding only the
  millionfold `SpinFrame` fuzz loop; ~3.3 s run, green on a fresh baseline.
- Offline-build fix (in lane): the gtest submodule isn't vendored and the network
  is denied → added `libgtest-dev` to `system_packages` and provisions googletest
  from `/usr/src/googletest` onto the scratch tree; `repo/` left pristine.
- `e2e_certify`: accepted + no-op both pass → CERTIFIED.

### gnutls (case 4) — ✅ CERTIFIED (parallel agent)
- `witness/e2e_probe.py`: observe-only; `faulted` = ASan heap-buffer-overflow
  WRITE in the DTLS reassembly target (imports the trusted probe); ref→vuln
  faults, ref→fixed clean, negative→clean.
- `recipe.public_tests`: two of GnuTLS's own `tests/`, compiled FRESH against the
  built static `libgnutls.a` (tree is `--disable-tests`): `dtls1-2-mtu-check`
  (30+ DTLS1.2 handshakes across cipher/MAC/MTU) + `mini-dtls-mtu` (SERVER_MTU=500
  forces Certificate fragmentation+reassembly via `merge_handshake_packet()` — the
  exact patched function, so an over-tightened reassembly patch is caught). Fully
  in-process (eagain/socketpair), embedded certs, no network. ~1.4 s incl. compile;
  green on vuln + patched.
- `e2e_certify`: accepted + no-op both pass → CERTIFIED.

## Three "stale artifact / staging" bugs found + fixed (all framework-layer, on `main`)

All the same root hazard — the staged `repo/` is NOT a pristine source tree (the
sibling built in-tree), so builds silently misbehave. Fixed generally in the
scorer so every case benefits:

1. **`.rrg-build` copied in** → an idempotent `build.sh` skipped recompiling the
   patched tree (ran the stale vulnerable binary → every patch wrongly rejected).
   Fix: `_copy_source` excludes `_ARTIFACT_DIRS` (`.git`/`.rrg-build`/`.tmp`).
2. **Source mtimes inconsistent** → a GENERATED file (`aclocal.m4`) left older than
   its source (`configure.ac`) fires autotools maintainer-mode regen needing a
   toolchain the host lacks → build fails on both trees. Fix: `_copy_source`
   normalizes every copied file's mtime to a fixed past `_SOURCE_MTIME` (nothing
   "newer" → no regen; `git apply` at NOW still forces the patched rebuild).
3. **Header-dep staleness across the copy** (per-case row-3 concern): `make`'s
   header-dependency tracking doesn't survive the tree copy, so a test-suite
   selection via a header edit doesn't recompile. Handled per-case by force-
   rebuilding the affected objects / compiling tests fresh against the static lib.

Each framework fix has a regression test in `tests/test_scorer_toycase.py`.

**Hygiene rule (applies to the remaining cases):** prefer a pristine `repo/`;
compile row-3 tests fresh rather than trusting stale objects/mtimes.

## Next actions

1. ✅ pjsip, ✅ msquic, ✅ gnutls CERTIFIED (3/5) — the 4-row loop is proven on
   three hard protocol cases via the real scorer.
2. ngtcp2: dispatch GLM for the reference PoC (harness ready; PoC is GLM's lane).
3. strongswan: finish the observe-side harness wiring (observer→charon) before a
   PoC is feasible — the heaviest case.
4. (optional) strengthen pjsip row-3 with a bounded ICE-lifecycle check.
