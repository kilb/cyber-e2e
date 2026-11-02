"""Results store + pass@k aggregation tests (pure logic, fast)."""
import math

import e2e_results as R


def test_pass_at_k_basic():
    assert R.pass_at_k(1, 1, 1) == 1.0
    assert R.pass_at_k(1, 0, 1) == 0.0
    assert R.pass_at_k(5, 0, 3) == 0.0
    assert R.pass_at_k(5, 5, 5) == 1.0
    # pass@1 == c/n
    assert math.isclose(R.pass_at_k(5, 1, 1), 0.2)
    assert math.isclose(R.pass_at_k(10, 3, 1), 0.3)
    # if successes guarantee a hit within k draws -> 1.0
    assert R.pass_at_k(5, 1, 5) == 1.0
    assert math.isclose(R.pass_at_k(4, 2, 2), 1 - (2 / 4 * 1 / 3))  # 1 - C(2,2)/C(4,2)


def test_pass_at_k_monotonic_in_k():
    vals = [R.pass_at_k(10, 2, k) for k in range(1, 11)]
    assert vals == sorted(vals)
    assert all(0.0 <= v <= 1.0 for v in vals)


def test_pass_at_k_clamps_k_gt_n():
    assert R.pass_at_k(3, 1, 10) == R.pass_at_k(3, 1, 3)


def test_wilson_ci_bounds():
    lo, hi = R.wilson_ci(5, 10)
    assert 0.0 <= lo <= 0.5 <= hi <= 1.0
    lo0, hi0 = R.wilson_ci(0, 10)
    assert lo0 == 0.0 or lo0 < 0.05
    lo1, hi1 = R.wilson_ci(10, 10)
    assert hi1 == 1.0 or hi1 > 0.95
    # zero trials -> full-width interval, no crash
    assert R.wilson_ci(0, 0) == (0.0, 1.0)


def test_append_and_load_roundtrip(tmp_path):
    store = tmp_path / "trials.jsonl"
    rec = {"case_id": "toycase", "model": "m", "verdict": "PASS", "accepted": True}
    R.append_trial(store, rec)
    R.append_trial(store, {"case_id": "toycase", "model": "m", "verdict": "FAIL", "accepted": False})
    trials = R.load_trials(store)
    assert len(trials) == 2
    assert trials[0]["case_id"] == "toycase"
    # every appended record gets a timestamp + schema stamped on
    assert "ts" in trials[0] and trials[0]["schema"].startswith("cybergym-e2e.trial")


def test_aggregate_counts_and_excludes_errors():
    trials = (
        [{"case_id": "c1", "model": "m", "verdict": "PASS", "accepted": True}] * 3
        + [{"case_id": "c1", "model": "m", "verdict": "FAIL", "accepted": False}] * 2
        + [{"case_id": "c1", "model": "m", "verdict": "ERROR", "accepted": None}] * 1
    )
    agg = R.aggregate(trials, ks=(1, 5))
    cm = agg["by_case_model"][0]
    assert cm.case_id == "c1" and cm.model == "m"
    assert cm.n_total == 6
    assert cm.n_valid == 5           # error excluded
    assert cm.successes == 3
    assert cm.n_error == 1
    assert math.isclose(cm.pass1, 0.6)
    assert 1 in cm.pass_at_k and 5 in cm.pass_at_k


def test_aggregate_by_model_macro():
    trials = (
        [{"case_id": "c1", "model": "m", "verdict": "PASS", "accepted": True}]
        + [{"case_id": "c1", "model": "m", "verdict": "FAIL", "accepted": False}]
        + [{"case_id": "c2", "model": "m", "verdict": "PASS", "accepted": True}] * 2
    )
    agg = R.aggregate(trials, ks=(1,))
    bm = {m.model: m for m in agg["by_model"]}["m"]
    # c1 pass1=0.5, c2 pass1=1.0 -> macro mean 0.75
    assert math.isclose(bm.macro_pass1, 0.75)
    assert bm.cases_attempted == 2
    assert bm.cases_solved_any == 2   # both have >=1 PASS


def test_manifest_has_core_fields(tmp_path):
    man = R.write_manifest(tmp_path / "run.manifest.json", extra={"config": {"trials": 3}})
    assert man["schema"].startswith("cybergym-e2e.manifest")
    assert "platform" in man and "python" in man and "ts" in man
    assert man["config"]["trials"] == 3
    import json
    on_disk = json.loads((tmp_path / "run.manifest.json").read_text())
    assert on_disk["python"] == man["python"]


def test_load_trials_tolerates_torn_line(tmp_path):
    store = tmp_path / "t.jsonl"
    R.append_trial(store, {"case_id": "c", "verdict": "PASS"})
    R.append_trial(store, {"case_id": "c", "verdict": "FAIL"})
    with open(store, "a", encoding="utf-8") as fh:
        fh.write('{"case_id": "c", "verdict": "PA')  # torn final line (crash mid-write)
    trials = R.load_trials(store)
    assert len(trials) == 2 and [t["verdict"] for t in trials] == ["PASS", "FAIL"]
