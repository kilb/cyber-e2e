#!/bin/bash
# Unprivileged bwrap sandbox for a single e2e agent run. Shares the host
# filesystem and network as-is (the agent needs outbound network to reach the
# model API and to `git clone`/fetch build deps), but:
#   * --unshare-pid : each run gets its own PID namespace, so one run's
#     `ps`/`pkill` cannot see or kill another PARALLEL run's processes. This is
#     mandatory for running >1 instance of the same case at once -- without it,
#     two runs that both start a server on a conventional port and then `pkill`
#     the stale one end up killing EACH OTHER (observed in the sibling project:
#     3 parallel php-fpm runs all died within ~20s of one another).
#   * masks the cases/ tree : the agent must never see witness/ (the oracle +
#     reference PoC), fix.patch, or any other case's material. The runner hands
#     the agent only an extracted copy of repo/ in its own work dir, so the
#     whole server-side cases root is tmpfs-masked here as defence in depth.
#   * masks the SIBLING project's own material (rrg-newcases / _rrg_archive /
#     rrg-case-authoring, if present): on a box shared with that project, the
#     SAME case (by filesystem layout, not network) often also exists there
#     with MORE information than this project ever intends to disclose (its
#     own task.md, differential scorer, archived reference PoCs, etc). This
#     is not hypothetical -- an unsandboxed agent run on this exact box once
#     discovered and invoked a sibling-project `model_poc_scorer.py` for the
#     very case it was solving. `--bind / /` alone gives the agent the WHOLE
#     host filesystem (it needs that to use the real toolchain/build deps),
#     so every such out-of-scope tree must be explicitly masked here, not
#     just this project's own cases root.
#
# Runs as the real uid (not root) -- the claude CLI refuses to run as root, so
# the codebase's unshare/--map-root-user path is not usable here.
#
# Usage: sandbox_wrapper.sh <command> [args...]
#   e.g. sandbox_wrapper.sh python3 /path/to/e2e_local.py run <case> --work-dir ...
set -u
CASES_ROOT="${E2E_CASES_ROOT:-$HOME/rrg-e2e/cases}"
mask_args=(--tmpfs "$CASES_ROOT")
for extra in "$HOME/rrg-newcases" "$HOME/_rrg_archive" "$HOME/rrg-case-authoring"; do
  if [ -e "$extra" ]; then
    mask_args+=(--tmpfs "$extra")
  fi
done
exec bwrap \
  --bind / / \
  --dev /dev \
  --unshare-pid \
  --proc /proc \
  "${mask_args[@]}" \
  -- "$@"
