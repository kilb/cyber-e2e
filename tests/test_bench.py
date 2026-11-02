"""Multi-trial benchmark-runner tests: full solver -> scorer -> store -> aggregate
stack, exercised locally with injected solvers against the toy case."""
import e2e_bench
import e2e_results as R

SUBMITTED_POC = b"\x40\x00\x00\x00" + b"A" * 64


def good_solver(bundle, model, work):
    return SUBMITTED_POC, (bundle / "fix.patch").read_bytes(), {"solve_s": 0.1, "agent_rc": 0}


def nonapplying_solver(bundle, model, work):
    return SUBMITTED_POC, b"not a patch\n", {"solve_s": 0.1, "agent_rc": 0}


def boom_solver(bundle, model, work):
    raise RuntimeError("agent exploded")


def test_bench_all_pass(tmp_path, toycase):
    store = tmp_path / "trials.jsonl"
    recs = e2e_bench.run_benchmark(
        bundles=[toycase], models=["fake-good"], n_trials=2,
        solver=good_solver, store=store, work_root=tmp_path / "w", timeout=180)
    assert len(recs) == 2
    trials = R.load_trials(store)
    assert len(trials) == 2 and all(t["verdict"] == "PASS" for t in trials)
    assert all(t["poc_sha256"] and t["patch_sha256"] for t in trials)
    cm = R.aggregate(trials, ks=(1, 2))["by_case_model"][0]
    assert cm.pass1 == 1.0 and cm.successes == 2


def test_bench_failures_recorded(tmp_path, toycase):
    store = tmp_path / "trials.jsonl"
    e2e_bench.run_benchmark(
        bundles=[toycase], models=["fake-bad"], n_trials=2,
        solver=nonapplying_solver, store=store, work_root=tmp_path / "w", timeout=180)
    trials = R.load_trials(store)
    assert all(t["verdict"] == "FAIL" for t in trials)
    assert all(t["rows"].get("patch_applies") is False for t in trials)


def test_bench_solver_error_is_error_trial(tmp_path, toycase):
    store = tmp_path / "trials.jsonl"
    e2e_bench.run_benchmark(
        bundles=[toycase], models=["boom"], n_trials=1,
        solver=boom_solver, store=store, work_root=tmp_path / "w", timeout=180)
    trials = R.load_trials(store)
    assert len(trials) == 1 and trials[0]["verdict"] == "ERROR"
    assert "agent exploded" in trials[0]["error"]
    # error excluded from pass-rate denominator
    cm = R.aggregate(trials)["by_case_model"][0]
    assert cm.n_error == 1 and cm.n_valid == 0 and cm.pass1 == 0.0
