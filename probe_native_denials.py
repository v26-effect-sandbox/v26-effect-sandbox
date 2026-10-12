#!/usr/bin/env python3
"""Provider-native bypass probe with ordinary B GitHub Actions contents:write token.

First proves token CAN write unprotected v26-requests; then attempts to write
v26-protected-effects. Native provider denial and unchanged ref are mandatory.
The test must run only after B administrator authorizes exact sandbox paths.
"""
import json
import os
from pathlib import Path
from common.github_api import GitHubApi
from common.pilot_core import json_file, sha256


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    run_id = os.environ["GITHUB_RUN_ID"]
    expected = os.environ["PARTY_B_TARGET_REPO"]
    if repo != expected:
        raise AssertionError("probe_must_run_in_B_sandbox_repo_only")
    gh = GitHubApi(os.environ["GITHUB_TOKEN"])
    source_branch = "v26-requests"
    protected = "v26-protected-effects"
    stamp = f"v26-native-denial-{run_id}"
    control_path = f"proposals/{stamp}.json"
    denied_path = f"effects/{stamp}.json"
    content = json_file({"schema": "v26.native-permission-control.v1", "run": run_id,
                         "synthetic_only": True})
    records = []

    def log(name, res):
        records.append({"name": name, "http": res.status,
                        "github_request_id": res.request_id, "response_sha256": res.response_sha256})

    report = {"schema": "v26.b.provider.native-denial.v1", "run_id": run_id,
              "repo": repo, "controls": records, "status": "NOT_COMPLETE"}
    out = Path("evidence")
    out.mkdir(exist_ok=True)
    try:
        pre, _, _ = gh.get_content(repo, control_path, source_branch)
        log("control_pre_absent", pre)
        if pre.status != 404:
            raise AssertionError("unprotected_nonce_already_exists")
        writable = gh.put_content(repo, control_path, source_branch, content,
                                   "V26 harmless write-token capability calibration")
        log("unprotected_branch_write_accepted", writable)
        if writable.status != 201:
            raise AssertionError("token_is_not_actually_contents_write: invalid_bypass_test")
        before_ref = gh.call("GET", f"/repos/{repo}/git/ref/heads/{protected}")
        log("protected_ref_before", before_ref)
        if before_ref.status != 200:
            raise AssertionError("protected_branch_does_not_exist")
        initial_sha = before_ref.data["object"]["sha"]
        attempted = gh.put_content(repo, denied_path, protected, content,
                                   "V26 expected native rejection of unauthorized B writer")
        log("provider_native_protected_write_attempt", attempted)
        after_ref = gh.call("GET", f"/repos/{repo}/git/ref/heads/{protected}")
        log("protected_ref_after", after_ref)
        after, _, _ = gh.get_content(repo, denied_path, protected)
        log("protected_effect_after", after)
        provider_reason = attempted.data.get("message", "") if isinstance(attempted.data, dict) else ""
        report.update({"protected_ref_before": initial_sha,
                       "protected_ref_after": after_ref.data.get("object", {}).get("sha") if after_ref.data else None,
                       "denial_http": attempted.status,
                       "provider_denial_reason": str(provider_reason)[:250],
                       "effect_still_absent_http": after.status,
                       "result": "NATIVE_DENIAL_PASS" if attempted.status in (403, 422) and bool(provider_reason)
                         and after_ref.status == 200 and after_ref.data["object"]["sha"] == initial_sha
                         and after.status == 404 else "NATIVE_DENIAL_FAILED"})
        if report["result"] != "NATIVE_DENIAL_PASS":
            raise AssertionError("B_WRITER_BYPASSED_PROTECTED_TARGET_OR_RESULT_UNVERIFIED")
        report["status"] = "PASS"
    except Exception as exc:
        report["status"] = "FAIL"
        report["error"] = str(exc)[:350]
        raise
    finally:
        (out / f"native_denial_{run_id}.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print("V26_NATIVE_DENIAL=" + json.dumps({"status": report["status"],
              "result": report.get("result"), "http": report.get("denial_http")}, sort_keys=True))


if __name__ == "__main__":
    main()
