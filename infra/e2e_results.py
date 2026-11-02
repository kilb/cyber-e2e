"""Durable results store + pass@k aggregation for cybergym-e2e.

The authoritative record of a benchmark run is an append-only JSONL file: one
line per trial, written the moment the trial is scored, so a crash or an expired
server job never loses a result (the environment docs warn the live job store is
lossy -- this file is the trusted record).

Aggregation turns that log into the numbers a benchmark reports:
  * pass@1  (= mean success rate) with a Wilson score confidence interval
  * pass@k  via the unbiased Chen-et-al. (HumanEval) estimator
  * per (case, model), and per model (macro-averaged over cases)

Trials with verdict "ERROR" (infra/scorer failures, not agent-attributable) are
counted and reported separately but excluded from pass-rate denominators.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path

TRIAL_SCHEMA = "cybergym-e2e.trial/v1"


# --------------------------------------------------------------------------- #
# statistics
# --------------------------------------------------------------------------- #
def pass_at_k(n: int, c: int, k: int) -> float:
    """Unbiased estimate of the probability that >=1 of k samples drawn (without
    replacement) from n trials with c successes passes. (Chen et al., 2021.)"""
    if n <= 0:
        return 0.0
    k = min(k, n)
    if c <= 0:
        return 0.0
    if n - c < k:
        return 1.0
    prod = 1.0
    for i in range(n - c + 1, n + 1):
        prod *= 1.0 - k / i
    return 1.0 - prod


def wilson_ci(c: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion c/n. n==0 -> (0,1)."""
    if n <= 0:
        return (0.0, 1.0)
    p = c / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, center - half), min(1.0, center + half))


# --------------------------------------------------------------------------- #
# store
# --------------------------------------------------------------------------- #
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def append_trial(store: Path | str, record: dict) -> dict:
    """Append one trial record as a JSON line (atomic append). Stamps a UTC
    timestamp + schema if absent and returns the stored record."""
    store = Path(store)
    store.parent.mkdir(parents=True, exist_ok=True)
    rec = dict(record)
    rec.setdefault("schema", TRIAL_SCHEMA)
    rec.setdefault("ts", _dt.datetime.now(_dt.timezone.utc).isoformat())
    line = json.dumps(rec, sort_keys=True) + "\n"
    with open(store, "a", encoding="utf-8") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())
    return rec


def load_trials(store: Path | str) -> list[dict]:
    store = Path(store)
    if not store.is_file():
        return []
    out = []
    for line in store.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


# --------------------------------------------------------------------------- #
# aggregation
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class CaseModelAgg:
    case_id: str
    model: str
    n_total: int
    n_valid: int          # PASS + FAIL (ERROR excluded)
    successes: int
    n_error: int
    pass1: float
    ci: tuple
    pass_at_k: dict       # {k: value} over valid trials


@dataclasses.dataclass
class ModelAgg:
    model: str
    cases_attempted: int
    cases_solved_any: int        # cases with >=1 PASS
    macro_pass1: float           # mean over cases of case pass1
    micro_pass1: float           # pooled successes / pooled valid trials
    n_valid: int
    n_error: int


def _is_pass(t: dict) -> bool:
    return t.get("verdict") == "PASS" or (t.get("verdict") is None and t.get("accepted") is True)


def _is_error(t: dict) -> bool:
    return t.get("verdict") == "ERROR"


def aggregate(trials: list[dict], ks: tuple = (1, 5, 10)) -> dict:
    by_cm: dict[tuple, list] = {}
    for t in trials:
        by_cm.setdefault((t.get("case_id"), t.get("model")), []).append(t)

    case_model = []
    for (case_id, model), ts in sorted(by_cm.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        n_total = len(ts)
        n_error = sum(1 for t in ts if _is_error(t))
        valid = [t for t in ts if not _is_error(t)]
        n_valid = len(valid)
        successes = sum(1 for t in valid if _is_pass(t))
        pass1 = (successes / n_valid) if n_valid else 0.0
        patk = {k: pass_at_k(n_valid, successes, k) for k in ks if k <= n_valid} if n_valid else {}
        case_model.append(CaseModelAgg(
            case_id=case_id, model=model, n_total=n_total, n_valid=n_valid,
            successes=successes, n_error=n_error, pass1=pass1,
            ci=wilson_ci(successes, n_valid), pass_at_k=patk))

    by_model: dict[str, list] = {}
    for cm in case_model:
        by_model.setdefault(cm.model, []).append(cm)
    model_aggs = []
    for model, cms in sorted(by_model.items(), key=lambda kv: str(kv[0])):
        attempted = len(cms)
        solved_any = sum(1 for cm in cms if cm.successes > 0)
        macro = sum(cm.pass1 for cm in cms) / attempted if attempted else 0.0
        pooled_valid = sum(cm.n_valid for cm in cms)
        pooled_succ = sum(cm.successes for cm in cms)
        micro = (pooled_succ / pooled_valid) if pooled_valid else 0.0
        model_aggs.append(ModelAgg(
            model=model, cases_attempted=attempted, cases_solved_any=solved_any,
            macro_pass1=macro, micro_pass1=micro, n_valid=pooled_valid,
            n_error=sum(cm.n_error for cm in cms)))

    return {"by_case_model": case_model, "by_model": model_aggs, "ks": list(ks)}


__all__ = ["pass_at_k", "wilson_ci", "sha256", "append_trial", "load_trials",
           "aggregate", "CaseModelAgg", "ModelAgg", "TRIAL_SCHEMA"]
