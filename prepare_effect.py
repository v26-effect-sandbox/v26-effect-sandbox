#!/usr/bin/env python3
"""Party B: create deterministic synthetic proposal; never write protected branch."""
import argparse
import json
from pathlib import Path
from common.pilot_core import effect_document, json_file, sha256


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--nonce", required=True)
    p.add_argument("--target-repo", required=True, help="B_ORG/v26-effect-sandbox")
    p.add_argument("--description", default="V26 synthetic audit event")
    args = p.parse_args()
    record = effect_document(args.nonce, args.target_repo, "v26-protected-effects",
                             args.description)
    path = Path("proposals") / f"{args.nonce}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError("Nonce collision: pick a new nonce rather than replacing proposal")
    raw = json_file(record)
    path.write_bytes(raw)
    print(json.dumps({"status": "PROPOSAL_PREPARED_NOT_PUBLISHED",
                      "proposal_path": str(path), "payload_sha256": sha256(raw),
                      "nonce": args.nonce}, sort_keys=True))
    print("COMMIT ONLY to v26-requests. Do not push to v26-protected-effects.")


if __name__ == "__main__":
    main()
