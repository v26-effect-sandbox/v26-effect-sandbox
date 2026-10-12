#!/usr/bin/env python3
"""V26 evidence audit from public Party A and public Party B sandboxes.

This is a reproducible file-content audit, NOT proof of institution-level
independence, admin bypass closure, or atomic cross-repository revocation.
Requires an out-of-band verified pinned Ed25519 public key fingerprint.
"""
import argparse
import json
import os
from pathlib import Path
from common.github_api import GitHubApi
from common.pilot_core import public_from_b64, public_raw, sha256, grant_decision, effect_valid, json_file


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--nonce", required=True)
    ap.add_argument("--expected-effect", choices=("present", "absent"), required=True)
    arg = ap.parse_args()
    cfg = json.loads(Path(arg.config).read_text())
    A = cfg["party_a_ledger_repo"]
    B = cfg["party_b_target_repo"]
    trust = cfg["party_a_trust_anchor_public_key_b64"]
    fp = cfg["party_a_out_of_band_fingerprint_sha256"]
    pk = public_from_b64(trust)
    if sha256(public_raw(pk)) != fp:
        raise ValueError("public_key_does_not_match_out_of_band_verified_fingerprint")
    if A.split("/")[0] == B.split("/")[0]:
        raise ValueError("same_github_org_cannot_satisfy_two_party_pilot")
    gh = GitHubApi(os.getenv("GITHUB_TOKEN", "")) if os.getenv("GITHUB_TOKEN") else None
    if gh is None:
        # In a public-only pilot, a read-only GitHub token is recommended to
        # avoid unauthenticated GitHub API rate limiting.
        raise ValueError("provide_a_read_only_GITHUB_TOKEN; NEVER use a private signing token")
    branch = "v26-protected-effects"
    ledger, raw, _ = gh.get_content(A, f"ledger/{arg.nonce}.json", "authority-ledger")
    if ledger.status != 200:
        raise ValueError("Party_A_live_signed_ledger_unavailable")
    note = json.loads(raw)
    target, effectraw, blobsha = gh.get_content(B, f"effects/{arg.nonce}.json", branch)
    exists = target.status == 200
    if exists != (arg.expected_effect == "present"):
        raise AssertionError("real_provider_effect_presence_unexpected")
    report = {"issuer_repo": A, "target_repo": B, "nonce": arg.nonce,
              "out_of_band_public_fingerprint_sha256": fp,
              "source_note_sha256": sha256(raw), "effect_status_http": target.status,
              "effect_git_blob_sha": blobsha, "verified_effect_exists": exists,
              "strong_claims": {"independent_admin_ownership": "REQUIRES_HUMAN_ATTESTATION",
                                "provider_admin_bypass_absence": "REQUIRES_NATIVE_RULESET_SNAPSHOT",
                                "cross_repositories_atomic_revocation": "NOT_PROVEN"}}
    if exists:
        item = json.loads(effectraw)
        if not effect_valid(item, arg.nonce, B, branch) or json_file(item) != effectraw:
            raise AssertionError("remote_provider_effect_wrong_format_or_out_of_scope")
        allowed, reason = grant_decision(note, pk, issuer=A, nonce=arg.nonce,
            target_repo=B, target_branch=branch, target_path=f"effects/{arg.nonce}.json",
            payload_sha256=sha256(effectraw))
        report["latest_source_grant_valid"] = allowed
        report["latest_source_reason"] = reason
        # An effect may have been authorized BEFORE later source revocation;
        # current state alone is not a historical time-of-commit proof.
    else:
        from common.pilot_core import verify_signature
        if not verify_signature(pk, note):
            raise AssertionError("absent_effect_source_note_signature_invalid")
        report["latest_source_decision"] = note["body"]["decision"]
    ref = gh.call("GET", f"/repos/{B}/branches/{branch}")
    if ref.status != 200:
        raise ValueError("cannot_read_target_protection_metadata")
    report["branch_reported_protected"] = bool(ref.data.get("protected"))
    if not report["branch_reported_protected"]:
        raise AssertionError("target_branch_not_provider_protected")
    rules = gh.call("GET", f"/repos/{B}/rulesets?includes_parents=true")
    report["rulesets_http"] = rules.status
    report["rulesets_count"] = len(rules.data) if isinstance(rules.data, list) else None
    if rules.status != 200 or not isinstance(rules.data, list) or not rules.data:
        raise AssertionError("no_provider_native_rulesets_observed")
    Path("evidence").mkdir(exist_ok=True)
    Path(f"evidence/READBACK_{arg.nonce}.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": "PUBLIC_SOURCE_AND_PROVIDER_READBACK_VERIFIED",
        "nonce": arg.nonce, "effect_exists": exists,
        "independent_legal_owner_proven": False,
        "unconditional_revocation_safety_proven": False}, sort_keys=True))


if __name__ == "__main__":
    main()
