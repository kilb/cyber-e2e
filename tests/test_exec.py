"""Execution-backend tests.

Host backend runs for real. For the Docker backend this sandbox has no registry
access, so we validate it two ways without a real container: a RECORDER shim pins
the exact `docker build` / `docker run` argv + image memoization, and an EXECUTOR
shim runs the backend's constructed commands on the host to exercise the full
scorer-through-DockerBackend flow. A real-container test is included but skips
when no base image is available offline.
"""
import json
import os
import subprocess

import pytest

import e2e_exec
import repo_e2e_task as scorer

SUBMITTED_POC = b"\x40\x00\x00\x00" + b"A" * 64

_RECORDER = """#!/usr/bin/env python3
import sys, os, json
with open(os.environ["SHIM_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
if sys.argv[1:2] == ["build"]:
    sys.stdin.read()
sys.exit(0)
"""

# Translates `docker build` -> no-op and `docker run ... IMAGE CMD...` -> run CMD
# on the host with the given -w cwd and -e env (so the full flow can be exercised).
_EXECUTOR = """#!/usr/bin/env python3
import sys, os, subprocess
a = sys.argv[1:]
if a[:1] == ["build"]:
    sys.stdin.read(); sys.exit(0)
if a[:1] == ["run"]:
    a = a[1:]; env = dict(os.environ); cwd = None; i = 0
    while i < len(a):
        t = a[i]
        if t == "--rm": i += 1
        elif t in ("--network", "--user", "-v"): i += 2
        elif t == "-e":
            k, _, v = a[i + 1].partition("="); env[k] = v; i += 2
        elif t == "-w": cwd = a[i + 1]; i += 2
        elif t.startswith("cybergym-e2e-planb:"): i += 1; break
        else: i += 1
    sys.exit(subprocess.run(a[i:], cwd=cwd, env=env).returncode)
sys.exit(2)
"""


def _shim(tmp_path, body, name):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    p.chmod(0o755)
    return str(p)


def test_host_backend_runs(tmp_path):
    be = e2e_exec.HostBackend()
    tree = tmp_path / "t"
    tree.mkdir()
    r = be.run_shell("echo hi > marker && echo out", cwd=tree, env={}, timeout=30)
    assert r.returncode == 0 and "out" in r.stdout and (tree / "marker").exists()


def test_docker_prepare_argv_and_memoize(tmp_path, monkeypatch):
    log = tmp_path / "shim.log"
    monkeypatch.setenv("SHIM_LOG", str(log))
    docker = _shim(tmp_path, _RECORDER, "docker")
    be = e2e_exec.DockerBackend(base_image="ubuntu:24.04", network="none", docker=docker)
    e2e_exec._image_cache.clear()
    be.prepare({"system_packages": ["gcc", "make"]})
    calls = [json.loads(l) for l in log.read_text().splitlines()]
    assert calls[0][0] == "build" and "-t" in calls[0]
    # a second prepare with the same spec must reuse the cached image (no 2nd build)
    be2 = e2e_exec.DockerBackend(base_image="ubuntu:24.04", network="none", docker=docker)
    be2.prepare({"system_packages": ["make", "gcc"]})  # order-independent
    builds = [c for c in (json.loads(l) for l in log.read_text().splitlines()) if c[0] == "build"]
    assert len(builds) == 1

    tree = tmp_path / "tree"
    tree.mkdir()
    be.run_shell("make all", cwd=tree, env={"TMPDIR": str(tree / ".tmp")}, timeout=30)
    run = [c for c in (json.loads(l) for l in log.read_text().splitlines()) if c[0] == "run"][0]
    uid_gid = f"{os.getuid()}:{os.getgid()}"
    assert run[:4] == ["run", "--rm", "--network", "none"]
    assert "--user" in run and uid_gid in run
    assert "-w" in run and str(tree.resolve()) in run
    assert any(a == f"TMPDIR={tree / '.tmp'}" for a in run)
    assert run[-3:] == ["sh", "-c", "make all"]


def test_score_toycase_via_docker_shim(tmp_path, toycase):
    # executor shim runs the backend's commands on the host -> validates the whole
    # scorer-through-DockerBackend flow (prepare + run_shell + run_oracle + mounts/env).
    docker = _shim(tmp_path, _EXECUTOR, "docker")
    e2e_exec._image_cache.clear()
    be = e2e_exec.DockerBackend(base_image="ubuntu:24.04", network="none", docker=docker)
    res = scorer.score_repo_e2e(toycase, SUBMITTED_POC, (toycase / "fix.patch").read_bytes(),
                                tmp_path / "w", timeout=300, backend=be)
    assert res.accepted, (res.reason, res.detail)
    assert res.detail["row1_poc_faults_vulnerable"] is True
    assert res.detail["row4_reference_clean_on_patch"] is True


def _base_image_available(img="ubuntu:24.04"):
    try:
        return subprocess.run(["docker", "image", "inspect", img],
                              capture_output=True, timeout=30).returncode == 0
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.skipif(not _base_image_available(), reason="no base image available offline")
def test_real_docker_scores_toycase(tmp_path, toycase):
    be = e2e_exec.DockerBackend(base_image="ubuntu:24.04", network="none")
    res = scorer.score_repo_e2e(toycase, SUBMITTED_POC, (toycase / "fix.patch").read_bytes(),
                                tmp_path / "w", timeout=1200, backend=be)
    assert res.accepted, (res.reason, res.detail)


def test_bench_fresh_context_threads_backend(tmp_path, toycase):
    import e2e_bench
    import e2e_results as R
    docker = _shim(tmp_path, _EXECUTOR, "docker")
    e2e_exec._image_cache.clear()
    bf = lambda: e2e_exec.DockerBackend(docker=docker)  # noqa: E731

    def good_solver(bundle, model, work):
        return SUBMITTED_POC, (bundle / "fix.patch").read_bytes(), {"solve_s": 1.0}

    store = tmp_path / "t.jsonl"
    e2e_bench.run_benchmark(
        bundles=[toycase], models=["m"], n_trials=1, solver=good_solver,
        store=store, work_root=tmp_path / "w",
        score_context=e2e_bench.fresh_context(300, bf), timeout=300)
    trials = R.load_trials(store)
    assert trials and all(t["verdict"] == "PASS" for t in trials), trials
