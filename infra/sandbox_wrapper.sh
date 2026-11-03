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
#   * the CLI's OWN state dir ($HOME/.claude) is given a FRESH, EMPTY,
#     per-trial directory (under $HERE, so it's still on-disk afterward for
#     audit) rather than the real shared one. A prior version of this script
#     bound the real `$HOME/.claude` in read-write -- undoing the default-deny
#     fix for the one path it explicitly carved out, since on a box used for
#     other projects too that directory holds OTHER projects' own session
#     transcripts (named after their own cases) and the CLI's stored
#     credentials file. The trial's own transcript still gets written
#     (into this fresh dir) and is still inspectable afterward; nothing
#     cross-project is exposed either way.
#   * --tmpfs /tmp gives an ISOLATED scratch tmp, not the shared host /tmp --
#     otherwise one trial could `ls /tmp` and see another concurrent trial's
#     (or the scorer's, or the sibling project's) scratch build directories.
#   * --unshare-pid : each run gets its own PID namespace, so one run's
#     `ps`/`pkill` cannot see or kill another PARALLEL run's processes. This is
#     mandatory for running >1 instance of the same case at once -- without it,
#     two runs that both start a server on a conventional port and then `pkill`
#     the stale one end up killing EACH OTHER (observed in the sibling project:
#     3 parallel php-fpm runs all died within ~20s of one another).
#   * the ENVIRONMENT handed to the sandboxed process is rebuilt from an
#     explicit ALLOWLIST of name patterns (generic shell/locale vars, proxy
#     vars, and the model-routing vars a `source ~/.<model>` dotfile sets --
#     ANTHROPIC_*/CLAUDE_*/DEEPSEEK_*/OPENROUTER_*), not the caller's full
#     `os.environ` passed through unfiltered. The filesystem mask above says
#     nothing about this: the launcher process's own environment (e.g. an
#     `E2E_API_KEY` the operator exported for the scoring server, or stray
#     credentials from an unrelated tool) was otherwise inherited verbatim by
#     the sandboxed agent, which (since this sandbox does not --unshare-net)
#     can reach that scoring server directly over loopback. `PWD`/`OLDPWD`
#     are dropped unconditionally too (they'd reveal the harness's own path
#     layout, not just this trial's). This is deliberately an ALLOWLIST (same
#     lesson as the filesystem fix above): naming specific vars to BLOCK is
#     exactly the enumeration mistake that already failed twice today.
#
# Runs as the real uid (not root) -- the claude CLI refuses to run as root, so
# the codebase's unshare/--map-root-user path is not usable here.
#
# Usage: sandbox_wrapper.sh <command> [args...]
#   e.g. sandbox_wrapper.sh python3 /path/to/e2e_local.py run <case> --work-dir ...
set -u
HERE=$(pwd -P)
CLAUDE_HOME="$HERE/.sandbox-claude-home"
mkdir -p "$CLAUDE_HOME"

# The `claude` CLI binary itself lives under $HOME (`~/.local/bin/claude`, a
# symlink into `~/.local/share/claude/...`), which the $HOME tmpfs-mask below
# also hides -- discovered by the sandboxed agent immediately failing with
# "execvp claude: No such file or directory". Re-expose exactly those two
# paths (not all of `~/.local`, which also holds the sibling project's own
# CLI tools) read-only, so the agent CLI can still find and run itself.
cli_reexpose=()
if [ -e "$HOME/.local/bin/claude" ]; then
  cli_reexpose+=(--ro-bind "$HOME/.local/bin/claude" "$HOME/.local/bin/claude")
fi
if [ -e "$HOME/.local/share/claude" ]; then
  cli_reexpose+=(--ro-bind "$HOME/.local/share/claude" "$HOME/.local/share/claude")
fi

setenv_args=()
while IFS='=' read -r -d '' name value; do
  case "$name" in
    PATH|HOME|LANG|LC_*|TERM|TMPDIR|TZ|SHELL|USER|LOGNAME| \
    ANTHROPIC_*|CLAUDE_*|DEEPSEEK_*|OPENROUTER_*| \
    HTTP_PROXY|HTTPS_PROXY|http_proxy|https_proxy|NO_PROXY|no_proxy)
      setenv_args+=(--setenv "$name" "$value")
      ;;
  esac
done < <(env -0)

exec bwrap \
  --bind / / \
  --dev /dev \
  --unshare-pid \
  --proc /proc \
  --tmpfs /tmp \
  --tmpfs "$HOME" \
  --bind "$HERE" "$HERE" \
  --bind "$CLAUDE_HOME" "$HOME/.claude" \
  "${cli_reexpose[@]}" \
  --clearenv \
  "${setenv_args[@]}" \
  -- "$@"
