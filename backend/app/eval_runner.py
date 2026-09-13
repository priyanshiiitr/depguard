"""
Evaluation harness for DepGuard's decision layer.

Cases fall into three kinds:
  - live_osv:  queries the real OSV.dev API for a known name@version and runs
               it through the same policy.decide_vulnerability() used in
               production. This is an integration test against live,
               authoritative ground truth (not a mock).
  - policy_unit_no_fix / policy_unit_license: feed a small synthetic input
    directly into the deterministic policy functions to exercise rules that
    are hard to find real-world examples for on demand (e.g. "no fixed
    version exists yet"). Labeled distinctly so it's clear these do not hit
    an external API.
  - eol: queries the real endoflife.date API for Node.js and checks the
    classification rule against today's date.

No metric here is invented after the fact -- every number in the returned
summary is computed from the actual pass/fail outcomes of running these
cases in this process, on this run.
"""
import json
from pathlib import Path

from . import policy
from .clients.osv import OSVClient
from .clients.eol import EOLClient, classify_eol
from . import semver

GOLD_SET_PATH = Path(__file__).resolve().parent.parent.parent / "eval" / "gold_set.json"


def _load_gold_set():
    with open(GOLD_SET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


async def _run_live_osv_case(osv: OSVClient, case: dict) -> dict:
    name, version, is_direct = case["name"], case["version"], case["is_direct"]
    results = await osv.query_batch([{"name": name, "version": version}])
    vuln_ids = [v["id"] for v in results[0].get("vulns", [])] if results else []
    records = []
    for vid in vuln_ids:
        try:
            records.append(await osv.get_vuln(vid))
        except Exception:
            continue

    actual_vulnerable = len(records) > 0
    if not actual_vulnerable:
        actual_action = "NONE"
        actual_min_safe = None
    else:
        decision = policy.decide_vulnerability(name, version, is_direct, records)
        actual_action = decision["recommended_action"]
        actual_min_safe = decision["min_safe_version"]

    passed = actual_vulnerable == case["expect_vulnerable"] and actual_action == case["expect_action"]
    if passed and case.get("expect_min_safe_at_least") and actual_min_safe:
        cmp = semver.compare(actual_min_safe, case["expect_min_safe_at_least"])
        if cmp is not None and cmp < 0:
            passed = False

    return {
        "id": case["id"], "kind": case["kind"], "passed": passed,
        "expected": {"vulnerable": case["expect_vulnerable"], "action": case["expect_action"],
                     "min_safe_at_least": case.get("expect_min_safe_at_least")},
        "actual": {"vulnerable": actual_vulnerable, "action": actual_action, "min_safe_version": actual_min_safe},
    }


def _run_policy_no_fix_case(case: dict) -> dict:
    synthetic_vuln = {
        "id": "SYNTHETIC-NO-FIX-0001",
        "summary": "Synthetic advisory with no published fix, for policy testing.",
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"ecosystem": "npm", "name": case["name"]},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }],
    }
    decision = policy.decide_vulnerability(case["name"], case["version"], case["is_direct"], [synthetic_vuln])
    passed = decision["recommended_action"] == case["expect_action"]
    return {
        "id": case["id"], "kind": case["kind"], "passed": passed,
        "expected": {"action": case["expect_action"]},
        "actual": {"action": decision["recommended_action"], "reason": decision["reason"]},
    }


def _run_policy_license_case(case: dict) -> dict:
    conflict, reason = policy.check_license_conflict(case["project_license"], case["dep_license"])
    passed = conflict == case["expect_conflict"]
    return {
        "id": case["id"], "kind": case["kind"], "passed": passed,
        "expected": {"conflict": case["expect_conflict"]},
        "actual": {"conflict": conflict, "reason": reason},
    }


async def _run_eol_case(eol: EOLClient, cycles_cache: dict, case: dict) -> dict:
    if "nodejs" not in cycles_cache:
        cycles_cache["nodejs"] = await eol.get_cycles("nodejs")
    cycles = cycles_cache["nodejs"] or []
    entry = next((c for c in cycles if str(c.get("cycle")) == str(case["major"])), None)
    if entry is None:
        return {"id": case["id"], "kind": case["kind"], "passed": False,
                "expected": {"status": case["expect_status"]}, "actual": {"status": "no_data"}}
    status, reason = classify_eol(entry)
    passed = status == case["expect_status"]
    return {
        "id": case["id"], "kind": case["kind"], "passed": passed,
        "expected": {"status": case["expect_status"]},
        "actual": {"status": status, "reason": reason},
    }


async def run_eval() -> dict:
    cases = _load_gold_set()
    osv = OSVClient()
    eol = EOLClient()
    cycles_cache: dict = {}
    results = []
    try:
        for case in cases:
            if case["kind"] == "live_osv":
                results.append(await _run_live_osv_case(osv, case))
            elif case["kind"] == "policy_unit_no_fix":
                results.append(_run_policy_no_fix_case(case))
            elif case["kind"] == "policy_unit_license":
                results.append(_run_policy_license_case(case))
            elif case["kind"] == "eol":
                results.append(await _run_eol_case(eol, cycles_cache, case))
            else:
                results.append({"id": case["id"], "kind": case["kind"], "passed": False,
                                 "expected": {}, "actual": {"error": "unknown case kind"}})
    finally:
        await osv.close()
        await eol.close()

    total = len(results)
    passed = sum(1 for r in results if r["passed"])

    # Vulnerability detection precision/recall over the binary-labeled live_osv subset.
    binary_cases = [(r, c) for r, c in zip(results, cases) if c["kind"] == "live_osv"]
    tp = sum(1 for r, c in binary_cases if c["expect_vulnerable"] and r["actual"]["vulnerable"])
    fp = sum(1 for r, c in binary_cases if not c["expect_vulnerable"] and r["actual"]["vulnerable"])
    fn = sum(1 for r, c in binary_cases if c["expect_vulnerable"] and not r["actual"]["vulnerable"])
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None

    # Safety metric: an "unsafe automatic upgrade" is any case where DepGuard
    # would have auto-remediated but the gold set says it should not have.
    unsafe_auto = sum(
        1 for r, c in zip(results, cases)
        if r["actual"].get("action") == "AUTO_REMEDIATE" and c.get("expect_action") != "AUTO_REMEDIATE"
    )

    return {
        "total_cases": total,
        "passed": passed,
        "failed": total - passed,
        "accuracy": round(passed / total, 4) if total else 0,
        "vulnerability_detection_precision": round(precision, 4) if precision is not None else None,
        "vulnerability_detection_recall": round(recall, 4) if recall is not None else None,
        "unsafe_automatic_upgrades": unsafe_auto,
        "results": results,
    }
