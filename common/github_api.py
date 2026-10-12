"""Minimal GitHub REST wrapper. Does not log bearer tokens or response payloads."""
from __future__ import annotations
import base64
import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Any


@dataclass
class ApiResponse:
    status: int
    data: Any
    request_id: str | None
    response_sha256: str


class GitHubApi:
    def __init__(self, token: str):
        if not token or len(token) < 12:
            raise ValueError("A valid token must be provided to runtime only")
        self.token = token

    def call(self, method: str, path: str, payload: dict | None = None) -> ApiResponse:
        from .pilot_core import canonical, sha256
        assert path.startswith("/"), path
        data = None if payload is None else canonical(payload)
        req = urllib.request.Request(
            "https://api.github.com" + path,
            method=method,
            data=data,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "V26-independent-two-party-research-pilot/1.0",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                status, raw, headers = resp.status, resp.read(1000000), resp.headers
        except urllib.error.HTTPError as e:
            status, raw, headers = e.code, e.read(100000), e.headers
        try:
            obj = json.loads(raw)
        except Exception:
            obj = None
        return ApiResponse(status, obj, headers.get("x-github-request-id"), sha256(raw))

    def get_content(self, repo: str, filename: str, ref: str):
        from urllib.parse import quote
        resp = self.call("GET", "/repos/" + repo + "/contents/" +
                         quote(filename, safe="/") + "?ref=" + quote(ref, safe=""))
        if resp.status != 200:
            return resp, None, None
        obj = resp.data
        if not isinstance(obj, dict) or obj.get("encoding") != "base64":
            raise ValueError("GitHub Contents returned unexpected encoding")
        return resp, base64.b64decode(obj["content"]), obj["sha"]

    def put_content(self, repo: str, filename: str, branch: str, content: bytes,
                    message: str, previous_sha: str | None = None):
        payload = {"branch": branch, "message": message,
                   "content": base64.b64encode(content).decode()}
        if previous_sha:
            payload["sha"] = previous_sha
        return self.call("PUT", f"/repos/{repo}/contents/{filename}", payload)
