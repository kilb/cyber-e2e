# cybergym-e2e (project-local benchmark)

A from-scratch benchmark modeled on Berkeley's **CyberGym-E2E** (arXiv:2606.04460,
ICML 2026, github.com/sunblaze-ucb/cybergym-e2e), built independently and kept in
its own repo so it does not interfere with the differential PoC-generation project
in `../RepoRepairGym` (branch `feat/repo-level-poc-delivery`), which has its own
in-flight blind-test runs on blk.so.

## Relationship to the sibling projects

- **Original CyberGym** (arXiv:2506.02548): PoC-generation only, scaffolding ladder
  L0 (code only) → L3 (+patch.diff). The `../RepoRepairGym` differential PoC-gen
  cases on blk.so are loosely modeled on CyberGym's **L1** (code + a
  commit-message-derived `task.md` description).
- **CyberGym-E2E**: a genuinely different, harder task below L0 — no description,
  no crash trace, no patch. The agent must autonomously **discover** the bug,
  produce a PoC, **and** produce a fix patch, validated by a 4-row matrix:
  1. submitted PoC crashes the unpatched target
  2. submitted PoC does NOT crash the agent's own submitted patch
  3. the agent's submitted patch still passes the project's own test suite
     (no functional regression)
  4. our ground-truth reference PoC does NOT crash the agent's submitted patch
     (patch isn't just a narrow PoC-specific workaround)
- This repo builds a local analogue of that 4-row matrix, reusing certified
  vulnerability material already built in `../RepoRepairGym`'s PoC-gen work as
  raw source candidates, but with its own submission contract and scoring.

## Division of labor (unchanged project rule, carried over)

Claude (coordinator) does NOT author exploit/oracle/harness code. All PoC,
patch-scoring-oracle, and vulnerability-trigger logic is built by the GLM worker
on blk.so (`ubuntu@blk.so`, `~/.glm`, model `glm-5.3-prime`). Claude does: this
spec, environment/handoff docs, case inventory curation, read-only review,
authoritative re-validation via the real scorer, and non-oracle infra scaffolding
(sandboxing, server wiring, directory layout).

## Repo layout

- `docs/` — handoff specs for the GLM worker: task contract, environment,
  per-case authoring contract, case inventory, known gotchas.
- `infra/` — the vulnerability-agnostic framework (Claude-authored plumbing):
  - `server.py` — e2e submission API (lease a source-only case, accept a
    `(poc, patch)` pair, enqueue a job, return the 4-row verdict).
  - `repo_e2e_task.py` — the 4-row scoring orchestration: build the vulnerable
    tree, git-apply the agent's patch and build it, invoke the per-case oracle
    as an opaque subprocess for rows 1/2/4, run the project's own test suite for
    row 3, AND the four booleans.
  - `e2e_local.py` — local runner: lease a case, drive the agent CLI with a
    no-hints prompt, collect `out/poc` + `out/fix.patch`, submit, record a
    durable `summary.json`.
  - `start_server.sh` — (re)start uvicorn on port 8900.
  - `sandbox_wrapper.sh` — unprivileged bwrap sandbox (PID-isolated) for one
    agent run.
- `cases/` — one directory per e2e case once built (empty for now). Each case's
  `witness/e2e_probe.py` (the oracle), `witness/model_poc_reference.*` (the
  ground-truth PoC), real `build.yaml` recipe and real `public_tests` are
  authored by the GLM worker per `docs/case-authoring.md` — NOT by Claude.

### What is NOT here yet (intentionally — it's GLM's half)

The framework is complete and compiles, but there are zero live cases: no
`e2e_probe.py` oracle, no reference PoC, no real per-case build/test recipe has
been written, because authoring those is the GLM worker's job. The next step is
to stand this up on blk.so (`~/rrg-e2e`, port 8900) and hand the first pilot
case to GLM to author against `docs/case-authoring.md`.

## Execution environment

Build/run work happens on `ubuntu@blk.so` (separate box from this local git
repo), in its own directory (`~/rrg-e2e`, NOT `~/rrg-newcases` which is the
sibling project's live workspace), on its own poc-api port (8900, NOT 8899
which the sibling project's server already owns). See `docs/environment.md`.
