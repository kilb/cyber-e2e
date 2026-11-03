"""Tests for the SOTA/upstream-parity additions: patch-only crash log, opaque
task-id alias, max_attempts, multi-reference row 4, token breakdown + stage
diagnosis, submission emitters, and Docker containment flags.

The server has no httpx/TestClient here, so it is exercised at the function level
after a fresh import against a temp cases root.
"""
import importlib
import io
import os
import shutil
import zipfile

import pytest

import e2e_exec
import e2e_report
import e2e_results as R
import repo_e2e_task as scorer


# --------------------------------------------------------------------------- #
# server helpers (function-level, fresh import per scenario)
# --------------------------------------------------------------------------- #
def _make_cases_root(tmp_path, toycase, *, name="toycase", extra_yaml=""):
    root = tmp_path / "cases"
    dst = root / name
    shutil.copytree(toycase, dst)
    if extra_yaml:
        with (dst / "build.yaml").open("a", encoding="utf-8") as f:
            f.write(extra_yaml)
    return root


def _import_server(cases_root, **env):
    os.environ["E2E_API_KEY"] = "testkey"
    os.environ["E2E_CASES_ROOT"] = str(cases_root)
    for k in ("E2E_MAX_ATTEMPTS", "E2E_BACKEND", "E2E_RESULTS"):
        os.environ.pop(k, None)
    os.environ.update({k: str(v) for k, v in env.items()})
    import server as srv
    return importlib.reload(srv)


# --------------------------------------------------------------------------- #
# patch-only serves crash log + PoC; e2e serves neither (gap #2)
# --------------------------------------------------------------------------- #
def test_patch_only_zip_includes_crash_log_and_poc(tmp_path, toycase):
    srv = _import_server(_make_cases_root(tmp_path, toycase))
    assert "toycase" in srv.CASES
    names = set(zipfile.ZipFile(io.BytesIO(srv._zip_source("toycase", "patch-only"))).namelist())
    assert "poc.bin" in names and "crash.log" in names
    assert any(n.startswith("repo/") for n in names)
    assert not any("witness" in n for n in names)
    assert "build.yaml" not in names and "fix.patch" not in names


def test_e2e_zip_withholds_everything(tmp_path, toycase):
    srv = _import_server(_make_cases_root(tmp_path, toycase))
    names = set(zipfile.ZipFile(io.BytesIO(srv._zip_source("toycase", "e2e"))).namelist())
    assert "poc.bin" not in names and "crash.log" not in names
    assert not any("witness" in n for n in names)
    assert all(n.startswith("repo/") for n in names)


# --------------------------------------------------------------------------- #
# opaque task-id alias (gap #3)
# --------------------------------------------------------------------------- #
def test_public_id_masks_case(tmp_path, toycase):
    root = _make_cases_root(tmp_path, toycase, name="curl-arvo-66012",
                            extra_yaml="\npublic_id: task-aXb12\n")
    srv = _import_server(root)
    assert srv.CASES == ("task-aXb12",)                 # advertises only the opaque id
    assert srv._ALIAS["task-aXb12"] == "curl-arvo-66012"
    assert srv._bundle_dir("task-aXb12").name == "curl-arvo-66012"
    view = srv._public_view("task-aXb12")
    assert view["case_id"] == "task-aXb12" and "curl" not in str(view)


def test_no_public_id_uses_dir_name(tmp_path, toycase):
    srv = _import_server(_make_cases_root(tmp_path, toycase, name="plaincase"))
    assert srv.CASES == ("plaincase",) and srv._ALIAS["plaincase"] == "plaincase"


# --------------------------------------------------------------------------- #
# max_attempts (gap #7)
# --------------------------------------------------------------------------- #
def test_max_attempts_gate(tmp_path, toycase):
    srv = _import_server(_make_cases_root(tmp_path, toycase), E2E_MAX_ATTEMPTS=1)
    assert srv.MAX_ATTEMPTS == 1
    srv._register_attempt("toycase")                     # first attempt ok
    with pytest.raises(srv.HTTPException):               # second exceeds the cap
        srv._register_attempt("toycase")


def test_unlimited_attempts_by_default(tmp_path, toycase):
    srv = _import_server(_make_cases_root(tmp_path, toycase))
    assert srv.MAX_ATTEMPTS == 0
    for _ in range(3):
        srv._register_attempt("toycase")                 # never raises


# --------------------------------------------------------------------------- #
# multiple reference PoCs harden row 4 (gap #10)
# --------------------------------------------------------------------------- #
def test_multi_reference_row4(tmp_path, toycase):
    bundle = tmp_path / "case"
    shutil.copytree(toycase, bundle)
    (bundle / "witness" / "model_poc_reference.2.bin").write_bytes(b"B" * 64)
    assert len(scorer.reference_poc_paths(bundle)) == 2

    # the real clamp fix defeats BOTH reference PoCs -> accepted, count 2
    res = scorer.score_repo_e2e(bundle, None, (bundle / "fix.patch").read_bytes(),
                                tmp_path / "w1", timeout=180, mode="patch-only")
    assert res.accepted and res.detail["row4_reference_count"] == 2
    assert res.detail["row4_reference_clean_on_patch"] is True

    # the narrow patch only neutralizes the len==64 PoC, not len==200 -> row4 fails
    narrow = (bundle / "witness" / "narrow_patch.diff").read_bytes()
    res2 = scorer.score_repo_e2e(bundle, None, narrow, tmp_path / "w2", timeout=180, mode="patch-only")
    assert not res2.accepted and res2.detail["row4_reference_clean_on_patch"] is False
    assert isinstance(res2.detail["row4_detail"], dict)   # per-reference breakdown when >1


# --------------------------------------------------------------------------- #
# token breakdown + stage fractions + failure diagnosis (gaps #4, #5)
# --------------------------------------------------------------------------- #
def _rows(**over):
    base = {"patch_applies": True, "patch_builds": True,
            "row1_poc_faults_vulnerable": True, "row2_poc_clean_on_patch": True,
            "row3_tests_pass_on_patch": True, "row4_reference_clean_on_patch": True}
    base.update(over)
    return base


_MIX = [
    {"case_id": "c1", "model": "m", "mode": "e2e", "verdict": "PASS", "accepted": True,
     "tokens": 1000, "tokens_input": 600, "tokens_output": 400, "usd_cost": 0.10,
     "solve_s": 5, "rows": _rows()},
    {"case_id": "c1", "model": "m", "mode": "e2e", "verdict": "FAIL", "accepted": False,
     "rows": _rows(row4_reference_clean_on_patch=False)},
]


def test_stage_fractions_and_failure_diagnosis():
    m = R.aggregate(_MIX, ks=(1,))["by_model"][0]
    assert m.stages["row1_poc_faults_vulnerable"] == 1.0
    assert m.stages["row4_reference_clean_on_patch"] == 0.5        # 1 of 2 valid passed s4
    assert m.failures.get("row4_reference_clean_on_patch") == 1    # the FAIL first-failed at s4
    assert m.cost["tokens_input"] == 600 and m.cost["tokens_output"] == 400


def test_results_json_and_submission_yaml():
    import yaml
    agg = R.aggregate(_MIX, ks=(1,))
    rj = e2e_report.render_results_json(agg)
    assert rj["schema"].startswith("cybergym-e2e.results")
    assert any(r["task"] == "c1" and r["mode"] == "e2e" for r in rj["results"])
    y = yaml.safe_load(e2e_report.render_submission_yaml(agg))
    assert y["models"][0]["model"] == "m"
    assert "s4 ref-clean" in y["models"][0]["stages"]
    assert "s4 ref-clean" in y["models"][0]["failure_stages"]


def test_markdown_has_stage_section():
    md = e2e_report.render_markdown(R.aggregate(_MIX, ks=(1,)))
    assert "Stage pass rates" in md and "s4 ref-clean" in md


# --------------------------------------------------------------------------- #
# Docker containment flags (gap #9)
# --------------------------------------------------------------------------- #
def test_docker_hardening_flags():
    be = e2e_exec.DockerBackend(memory="4g", cpus="2")
    args = be._base_args({"K": "V"}, ["/tmp"])
    assert "--cap-drop" in args and "ALL" in args
    assert "--security-opt" in args and "no-new-privileges" in args
    assert "--pids-limit" in args
    assert "--memory" in args and "4g" in args
    assert "--cpus" in args and "2" in args
