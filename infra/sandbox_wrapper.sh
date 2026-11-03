#!/bin/bash
# Unprivileged bwrap sandbox for a single e2e agent run.
#
# FALLBACK path, for a host without (working) Docker-network isolation. The
# PRIMARY path, when Docker is available, is `DockerBackend.run_agent()` in
# e2e_exec.py: a real `docker run` on an `--internal` network whose only
# reachable peer is the firewall-proxy container -- genuine network-level
# enforcement, not the cooperative HTTP_PROXY convention this script still
# relies on (see the "Does NOT --unshare-net" note below). Use this script
# only when that path isn't available.
#
# DEFAULT-DENY on the ENTIRE filesystem, not just $HOME: there is no
# `--bind / /` at all. Nothing exists inside the sandbox unless it's
# explicitly named below:
#   * a fixed set of system directories (/usr, /bin, /sbin, /lib, /lib32,
#     /lib64, /etc, /opt -- whichever exist) read-only, for the real
#     toolchain (compilers, standard libs, python, make, git, ...). If
#     $E2E_SANDBOX_ROOTFS is set (a directory exported from this case's own
#     per-case Docker image via DockerBackend.export_rootfs -- the SAME
#     minimal `system_packages`-only image already built for the scoring
#     step), these come from THERE instead of the live host: a
#     case-specific-minimal toolchain with none of a shared host's other
#     baggage (another project's own installed tools, etc.), without
#     actually running the agent inside `docker run` (which would need its
#     own, separately-solved network story to still reach the egress-
#     firewall proxy). Falls back to the live host's own system directories
#     when unset, so this script still works standalone / without Docker.
#   * the trial's own working directory (captured via `pwd` before bwrap
#     runs, since the caller sets this as the subprocess cwd), read-write.
#   * a FRESH, EMPTY, per-trial `~/.claude` (under the trial's own work dir,
#     so it's still on-disk afterward for audit) in place of the real
#     shared one, so the CLI's own session/config bookkeeping keeps working
#     without exposing OTHER projects' session transcripts or the CLI's
#     stored credentials (both of which live in the real, shared
#     `~/.claude` on a box used for more than one project).
#   * the `claude` CLI binary itself (`~/.local/bin/claude`, a symlink into
#     `~/.local/share/claude/...`), read-only, specifically those two paths
#     -- not all of `~/.local`, which also holds unrelated tools (e.g. a
#     sibling project's own CLI).
#   * /dev, a namespaced /proc, an isolated /tmp (its own tmpfs, not the
#     shared host one -- otherwise one trial could `ls /tmp` and see
#     another concurrent trial's, or the scorer's, scratch directories).
#
# This replaced an earlier version that did `--bind / /` (share the whole
# real root) and then `--tmpfs "$HOME"` to mask just the home directory.
# That caught the two concrete leaks found live that way (this project's own
# README/docs, a sibling project's trees -- both under $HOME on this box),
# but left every OTHER top-level directory (/opt, /srv, /mnt, /data, another
# user's /home/<other>, whatever else exists on a given host, now or later)
# exposed by default, unaudited, simply because nothing had looked there
# yet. Not sharing the root at all removes the need to enumerate what's
# "safe" out there: nothing exists in the sandbox unless named here.
#
#   * --unshare-pid : each run gets its own PID namespace, so one run's
#     `ps`/`pkill` cannot see or kill another PARALLEL run's processes. This is
#     mandatory for running >1 instance of the same case at once -- without it,
#     two runs that both start a server on a conventional port and then `pkill`
#     the stale one end up killing EACH OTHER (observed in the sibling project:
#     3 parallel php-fpm runs all died within ~20s of one another).
#   * the ENVIRONMENT handed to the sandboxed process is rebuilt from an
#     explicit ALLOWLIST of name patterns (generic shell/locale/proxy vars,
#     and the model-routing vars a `source ~/.<model>` dotfile sets --
#     ANTHROPIC_*/CLAUDE_*/DEEPSEEK_*/OPENROUTER_*), not the caller's full
#     `os.environ` passed through unfiltered -- an `E2E_API_KEY`-style
#     secret, or `PWD`/`OLDPWD` revealing the harness's own path layout,
#     would otherwise reach the sandboxed process verbatim. Deliberately an
#     allowlist, not a blocklist of specific names to drop: naming things to
#     BLOCK is the same enumeration mistake the filesystem fix above moved
#     away from.
#
# Does NOT --unshare-net: the agent needs outbound network to reach the
# model API, through the egress-firewall proxy when one is configured via
# HTTP_PROXY/HTTPS_PROXY -- a COOPERATIVE layer only (see e2e_firewall.py's
# own module docstring for the network-level enforcement this still lacks).
# Filesystem and network containment are separate concerns; this script only
# ever claimed the former.
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

# Real toolchain: allowlist specific system directories, not the whole root.
# Source them from $E2E_SANDBOX_ROOTFS (a case-specific-minimal exported
# image) when set, else the live host.
ROOTFS="${E2E_SANDBOX_ROOTFS:-}"
sys_binds=()
for d in /usr /bin /sbin /lib /lib32 /lib64 /etc /opt; do
  if [ -n "$ROOTFS" ]; then
    src="$ROOTFS$d"
  else
    src="$d"
  fi
  if [ -e "$src" ]; then
    sys_binds+=(--ro-bind "$src" "$d")
  fi
done

# The `claude` CLI binary itself lives under $HOME -- re-expose exactly
# those two paths (not all of `~/.local`) read-only.
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
    HTTP_PROXY|HTTPS_PROXY|http_proxy|https_proxy|ALL_PROXY|all_proxy|NO_PROXY|no_proxy)
      setenv_args+=(--setenv "$name" "$value")
      ;;
  esac
done < <(env -0)

exec bwrap \
  --dev /dev \
  --unshare-pid \
  --proc /proc \
  --tmpfs /tmp \
  "${sys_binds[@]}" \
  --bind "$HERE" "$HERE" \
  --bind "$CLAUDE_HOME" "$HOME/.claude" \
  "${cli_reexpose[@]}" \
  --clearenv \
  "${setenv_args[@]}" \
  -- "$@"
