#!/bin/bash
# Unprivileged bwrap sandbox for a single e2e agent run.
#
# DEFAULT-DENY on $HOME, default-allow on the rest of the filesystem:
#   * --bind / / gives the agent the real toolchain (/usr, /lib, /etc, ...) --
#     it needs that to compile/run its own verification builds.
#   * --tmpfs "$HOME" then masks EVERYTHING under the home directory (this
#     project's own README/docs/infra/tests/cases, the sibling project's
#     rrg-newcases/_rrg_archive/rrg-case-authoring, dotfiles with API keys,
#     anything else that lives there now or gets added later) -- not an
#     enumerated denylist of specific "known bad" paths. An earlier version
#     of this script enumerated specific paths to mask (cases/ + three named
#     sibling dirs) and left the rest of $HOME wide open; a live benchmark
#     trial then ran `cat ~/rrg-e2e/README.md` and read this project's own
#     scoring-methodology writeup verbatim, plus (separately) discovered and
#     invoked a sibling-project witness script for the very case it was
#     solving. Denylists miss things; mask the whole thing and re-expose only
#     what's actually needed.
#   * --bind "$HERE" "$HERE" re-exposes ONLY the trial's own working
#     directory (captured via `pwd` before bwrap runs, since the caller sets
#     this as the subprocess cwd) -- ./repo, ./out, ./TASK.md, scratch files.
#   * --bind "$HOME/.claude" re-exposes the CLI's own session/config state so
#     it keeps working normally (and so its transcripts stay available for
#     audit) without exposing anything else in $HOME.
#   * --tmpfs /tmp gives an ISOLATED scratch tmp, not the shared host /tmp --
#     otherwise one trial could `ls /tmp` and see another concurrent trial's
#     (or the scorer's, or the sibling project's) scratch build directories.
#   * --unshare-pid : each run gets its own PID namespace, so one run's
#     `ps`/`pkill` cannot see or kill another PARALLEL run's processes. This is
#     mandatory for running >1 instance of the same case at once -- without it,
#     two runs that both start a server on a conventional port and then `pkill`
#     the stale one end up killing EACH OTHER (observed in the sibling project:
#     3 parallel php-fpm runs all died within ~20s of one another).
#
# Runs as the real uid (not root) -- the claude CLI refuses to run as root, so
# the codebase's unshare/--map-root-user path is not usable here.
#
# Usage: sandbox_wrapper.sh <command> [args...]
#   e.g. sandbox_wrapper.sh python3 /path/to/e2e_local.py run <case> --work-dir ...
set -u
HERE=$(pwd -P)
reexpose=(--bind "$HERE" "$HERE")
if [ -e "$HOME/.claude" ]; then
  reexpose+=(--bind "$HOME/.claude" "$HOME/.claude")
fi
exec bwrap \
  --bind / / \
  --dev /dev \
  --unshare-pid \
  --proc /proc \
  --tmpfs /tmp \
  --tmpfs "$HOME" \
  "${reexpose[@]}" \
  -- "$@"
