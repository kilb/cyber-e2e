# Execution environment

## Where the work happens

All build/run/sandbox execution happens on `ubuntu@blk.so` (not this local
machine, which only holds this git repo as the source of truth). Use a
directory **separate from the sibling project's live workspace**:

- Sibling project (do NOT touch, do NOT reuse its port): `~/rrg-newcases`,
  poc-api on `127.0.0.1:8899`, has in-flight blind-test runs as of
  2026-11-02.
- This project's directory on blk.so: `~/rrg-e2e` (create fresh).
- This project's poc-api port: **8900** (8899 is owned by the sibling
  project; do not collide).

## Model/agent access

- GLM worker: `ubuntu@blk.so`, `source ~/.glm`, model id `glm-5.3-prime`,
  invoked via the `claude` CLI (`claude --model glm-5.3-prime ...`) exactly
  as the sibling project does.
- Claude (coordinator) does not author harness/oracle/PoC/patch-scoring code.
  That is GLM's job, same division of labor as the sibling project.

## Sandboxing

See `infra/sandbox_wrapper.sh.template`. Key lesson carried over from the
sibling project: bwrap here does NOT isolate network or filesystem (only
PID, via `--unshare-pid`) -- it shares the host's `/` and network as-is. This
means:

- Two parallel runs of the SAME case can still collide on a fixed TCP port if
  the case's own build/test harness binds one (e.g. a webserver, an FPM pool,
  a daemon listening on a conventional port). `--unshare-pid` stops them from
  being able to `pkill` each other, but it does NOT stop EADDRINUSE. If a case
  needs true parallel instances, either randomize the port per run-dir, or run
  multiple rounds of the same case sequentially instead of in parallel.
- Give each run its own `TMPDIR` (`<workspace>/.tmp`), never the host's shared
  `/tmp` -- a prior project (the sibling repo, and before it `rrg-poc`) hit a
  real cross-session file collision (`/tmp/poc.c`) from not doing this.

## Known gotchas inherited from the sibling project (apply here too)

- After editing a server's case registry (e.g. adding a new case to a `CASES`
  tuple), the already-running server process does **not** pick up the change
  until restarted. A stale `/health` case count causes confusing
  `unknown case_id` 404s on submission. Always restart the server after a
  registry edit.
- A live job store on a long-running api server can have a TTL/cap --
  querying an old `job_id` can 404 with `unknown job_id` well after the job
  actually completed. The durable authoritative record is the run's own
  `summary.json` (or whatever this project's equivalent local trusted-harness
  output is), not the live job endpoint, for anything older than ~20 jobs.
- `ssh ... 'bash some_long_monitor.sh'` launched as a background task can drop
  with exit code 255 after hours (ssh channel drop), which is NOT a real
  failure -- re-probe directly via a fresh ssh call (check the run's own pid
  file / summary file) rather than trusting the monitor task's own exit
  status. Add `-o ServerAliveInterval=30 -o ServerAliveCountMax=20
  -o TCPKeepAlive=yes` to reduce (not eliminate) the drop rate.
- A launch command that backgrounds a `setsid` child routinely exceeds a
  120s foreground tool timeout and gets auto-moved to a background task --
  this is fine, the `setsid` child survives independently; just confirm (via
  a separate ssh probe) that the child is alive, then stop the now-redundant
  wrapper task.
