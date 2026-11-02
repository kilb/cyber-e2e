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
#
# Runs as the real uid (not root) -- the claude CLI refuses to run as root, so
# the codebase's unshare/--map-root-user path is not usable here.
#
# Usage: sandbox_wrapper.sh <command> [args...]
#   e.g. sandbox_wrapper.sh python3 /path/to/e2e_local.py run <case> --work-dir ...
set -u
CASES_ROOT="${E2E_CASES_ROOT:-$HOME/rrg-e2e/cases}"
exec bwrap \
  --bind / / \
  --dev /dev \
  --unshare-pid \
  --proc /proc \
  --tmpfs "$CASES_ROOT" \
  -- "$@"
