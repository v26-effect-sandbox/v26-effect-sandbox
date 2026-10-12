"""V26 pilot primitives. NO network and NO implicit trust in another party's files.

Canonical encoding is UTF-8 JSON, sorted keys, compact separators, allow_nan=False,
plus a single terminal newline for file encoding. Signatures cover the JSON object
WITHOUT that file delimiter; all statements must carry a version and strict keys.
"""
from __future__ import annotations
import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

NONCE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,63}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
LEDGER_SCHEMA = "v26.source.ledger.v1"
EFFECT_SCHEMA = "v26.synthetic-effect.v1"
AUDIENCE = "v26-party-a-controlled-writer"


class PolicyError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def json_file(value: object) -> bytes:
    return canonical(value) + b"\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:
        raise PolicyError("malformed_base64") from exc


def checked_nonce(nonce: str) -> str:
    if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
        raise PolicyError("nonce_must_be_8_to_64_lowercase_alnum_or_hyphen")
    return nonce


def checked_repo(repo: str) -> str:
    if not isinstance(repo, str) or not REPO_RE.fullmatch(repo):
        raise PolicyError("invalid_owner_repo")
    return repo


def public_raw(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_from_b64(raw_b64: str) -> Ed25519PublicKey:
    raw = unb64(raw_b64)
    if len(raw) != 32:
        raise PolicyError("ed25519_public_key_must_be_32_bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def private_from_pem_b64(pem_b64: str) -> Ed25519PrivateKey:
    raw = unb64(pem_b64)
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise PolicyError("private_key_must_be_ed25519")
    return key


def make_signature(private: Ed25519PrivateKey, body: dict) -> dict:
    return {"body": body, "signature_b64": b64(private.sign(canonical(body)))}


def verify_signature(public: Ed25519PublicKey, note: object) -> bool:
    if not isinstance(note, dict) or set(note) != {"body", "signature_b64"}:
        return False
    if not isinstance(note.get("body"), dict) or not isinstance(note.get("signature_b64"), str):
        return False
    try:
        public.verify(unb64(note["signature_b64"]), canonical(note["body"]))
        return True
    except (InvalidSignature, PolicyError, ValueError, TypeError):
        return False


def effect_document(nonce: str, target_repo: str, target_branch: str,
                    description: str) -> dict:
    checked_nonce(nonce)
    checked_repo(target_repo)
    if target_branch != "v26-protected-effects":
        raise PolicyError("invalid_protected_branch")
    if not isinstance(description, str) or not (1 <= len(description) <= 160):
        raise PolicyError("description_must_be_1_to_160_chars")
    return {
        "schema": EFFECT_SCHEMA,
        "nonce": nonce,
        "target_repo": target_repo,
        "target_branch": target_branch,
        "target_path": f"effects/{nonce}.json",
        "kind": "SYNTHETIC_RESEARCH_AUDIT_ONLY",
        "description": description,
        "no_production_or_physical_effect": True,
    }


def effect_valid(effect: dict, nonce: str, repo: str, branch: str) -> bool:
    try:
        return (isinstance(effect, dict)
                and set(effect) == {"schema", "nonce", "target_repo", "target_branch",
                                    "target_path", "kind", "description",
                                    "no_production_or_physical_effect"}
                and effect == effect_document(nonce, repo, branch, effect["description"]))
    except (PolicyError, KeyError, ValueError, TypeError):
        return False


def new_ledger_body(*, issuer: str, nonce: str, target_repo: str,
                    payload_sha256: str, now: int, expires_at: int) -> dict:
    checked_repo(issuer)
    checked_repo(target_repo)
    checked_nonce(nonce)
    if not HASH_RE.fullmatch(payload_sha256):
        raise PolicyError("payload_must_have_64_char_sha256")
    if expires_at <= now or expires_at > now + 3600:
        raise PolicyError("max_grant_ttl_is_3600_seconds")
    return {
        "schema": LEDGER_SCHEMA,
        "issuer": issuer,
        "nonce": nonce,
        "revision": 1,
        "decision": "active",
        "audience": AUDIENCE,
        "target_repo": target_repo,
        "target_branch": "v26-protected-effects",
        "target_path": f"effects/{nonce}.json",
        "payload_sha256": payload_sha256,
        "issued_at_unix": now,
        "expires_at_unix": expires_at,
        "updated_at_unix": now,
        "previous_note_sha256": None,
    }


def revoke_ledger_body(previous_note: dict, *, now: int) -> dict:
    body = previous_note["body"]
    if body["schema"] != LEDGER_SCHEMA or body["decision"] != "active":
        raise PolicyError("only_active_notes_can_be_revoked")
    x = dict(body)
    x["revision"] += 1
    x["decision"] = "revoked"
    x["updated_at_unix"] = max(now, body["updated_at_unix"])
    x["previous_note_sha256"] = sha256(json_file(previous_note))
    return x


def grant_decision(note: object, public: Ed25519PublicKey,
                   *, issuer: str, nonce: str, target_repo: str,
                   target_branch: str, target_path: str, payload_sha256: str,
                   now: int | None = None) -> tuple[bool, str]:
    now = int(time.time()) if now is None else now
    if not verify_signature(public, note):
        return False, "invalid_or_missing_issuer_signature"
    b = note["body"]
    required = {"schema", "issuer", "nonce", "revision", "decision", "audience",
                "target_repo", "target_branch", "target_path", "payload_sha256",
                "issued_at_unix", "expires_at_unix", "updated_at_unix",
                "previous_note_sha256"}
    if set(b) != required:
        return False, "unrecognized_issuer_note_structure"
    if (b["schema"] != LEDGER_SCHEMA or b["issuer"] != issuer
            or b["audience"] != AUDIENCE):
        return False, "issuer_or_audience_untrusted"
    if (b["nonce"] != nonce or b["target_repo"] != target_repo
            or b["target_branch"] != target_branch or b["target_path"] != target_path
            or b["payload_sha256"] != payload_sha256):
        return False, "task_scope_or_digest_mismatch"
    if not isinstance(b["revision"], int) or b["revision"] < 1:
        return False, "invalid_source_revision"
    if b["decision"] != "active":
        return False, "revoked_source_authorization"
    if not all(isinstance(b[v], int) for v in
               ("issued_at_unix", "expires_at_unix", "updated_at_unix")):
        return False, "malformed_source_time"
    if b["updated_at_unix"] > now + 60 or b["issued_at_unix"] > now + 60:
        return False, "source_timestamp_in_future"
    if now >= b["expires_at_unix"] or b["expires_at_unix"] - b["issued_at_unix"] > 3600:
        return False, "source_grant_expired_or_excessive_ttl"
    if now - b["updated_at_unix"] > 3600:
        return False, "source_state_too_old"
    return True, "signed_current_source_authorizes_exact_effect"
