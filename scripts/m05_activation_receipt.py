#!/usr/bin/env python3
"""M05 paired live/restore/review evidence를 서명된 production receipt로 봉인한다."""

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PLAYWRIGHT_IMAGE_RE = re.compile(
    r"mcr\.microsoft\.com/playwright(?::[A-Za-z0-9][A-Za-z0-9._-]*)?@sha256:[0-9a-f]{64}\Z"
)
_REVIEW_PR_RE = re.compile(r"https://github\.com/digitie/pinvi/pull/[1-9][0-9]*\Z")
_M05_ACTIVATION_PR_URL = "https://github.com/digitie/pinvi/pull/466"
_M05_RESTORE_DATABASE_RE = re.compile(r"pinvi_m05_restore_[a-z0-9_]+\Z")
_HOST_TOOL_DIRECTORIES = (Path("/usr/bin"), Path("/bin"))
_RESTORE_TOOL_DIRECTORIES = (Path("/usr/local/bin"), Path("/usr/bin"), Path("/bin"))
_POSTGRES_TOOL_DIRECTORY_RE = re.compile(r"/usr/lib/postgresql/[0-9]+/bin\Z")
_RESTORE_TOOL_NAMES = ("bash", "git", "pg_dump", "pg_restore", "psql")
_RESTORE_IDENTITY_ENDPOINT_FIELDS = (
    "database",
    "database_oid",
    "system_identifier",
    "hostaddr",
    "port",
    "sslmode",
)
_PAIR_PROVENANCE = Path(__file__).resolve().parents[1] / (
    "contracts/kor-travel-map-m05-pair-provenance-v1.json"
)
_TRUST_ANCHOR = Path(__file__).resolve().parents[1] / (
    "contracts/pinvi-m05-activation-receipt-trust-v1.json"
)
_REVIEWER_ROSTER = Path(__file__).resolve().parents[1] / (
    "contracts/pinvi-m05-reviewer-roster-v1.json"
)
_EVIDENCE_FILES = (
    "attestation.json",
    "reviews.json",
    "ui-run.json",
    "live-ui.json",
    "restore.json",
    "map-pair.json",
    "pinvi-images.json",
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _canonical_github_opener() -> urllib.request.OpenerDirector:
    # GitHub PR provenance must not be supplied by ambient HTTP(S) proxy variables.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )


class ReceiptError(ValueError):
    """M05 evidence가 canonical receipt 계약을 위반했다."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError("duplicate JSON key")
        result[key] = value
    return result


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_base64url(value: object, *, expected_length: int) -> bytes | None:
    if not isinstance(value, str) or not value or "=" in value:
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        return None
    if len(decoded) != expected_length or _base64url(decoded) != value:
        return None
    return decoded


def _open_secure_directory(path: Path, *, require_root_owned: bool) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReceiptError("evidence directory must be a regular directory") from exc
    directory_stat = os.fstat(fd)
    if not stat.S_ISDIR(directory_stat.st_mode):
        os.close(fd)
        raise ReceiptError("evidence directory must be a regular directory")
    if stat.S_IMODE(directory_stat.st_mode) != 0o700:
        os.close(fd)
        raise ReceiptError("evidence directory mode is not 0700")
    if require_root_owned and directory_stat.st_uid != 0:
        os.close(fd)
        raise ReceiptError("evidence directory is not root-owned")
    return fd


def _read_secure_bytes(
    path: Path,
    *,
    require_root_owned: bool,
    directory_fd: int | None = None,
    label: str,
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        if directory_fd is None:
            fd = os.open(path, flags)
        else:
            fd = os.open(path.name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise ReceiptError(f"{label} is not a readable regular file: {path.name}") from exc
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ReceiptError(f"{label} is not a regular file: {path.name}")
        if stat.S_IMODE(file_stat.st_mode) != 0o600:
            raise ReceiptError(f"{label} mode is not 0600: {path.name}")
        if require_root_owned and file_stat.st_uid != 0:
            raise ReceiptError(f"{label} is not root-owned: {path.name}")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            return stream.read()
    finally:
        if fd != -1:
            os.close(fd)


def _read_json(
    path: Path,
    *,
    require_root_owned: bool,
    directory_fd: int | None = None,
) -> tuple[object, str]:
    raw = _read_secure_bytes(
        path,
        require_root_owned=require_root_owned,
        directory_fd=directory_fd,
        label="evidence file",
    )
    try:
        return (
            json.loads(raw, object_pairs_hook=_reject_duplicate_keys),
            hashlib.sha256(raw).hexdigest(),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as exc:
        raise ReceiptError(f"evidence JSON is invalid: {path.name}") from exc


def _write_new_json(path: Path, value: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ReceiptError("output parent must be a regular directory")
    parent_stat = path.parent.stat()
    if stat.S_IMODE(parent_stat.st_mode) & 0o022:
        raise ReceiptError("output parent must not be group/world writable")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ReceiptError(f"output already exists: {path}") from exc
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(
                json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            )
    finally:
        if fd != -1:
            os.close(fd)


def _object(value: object, *, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReceiptError(f"{name} must be an object")
    return cast(dict[str, object], value)


def _string(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        raise ReceiptError(f"{name} must be a non-empty token-free string")
    return value


def _sha256(value: object, *, name: str) -> str:
    value = _string(value, name=name)
    if _SHA256_RE.fullmatch(value) is None:
        raise ReceiptError(f"{name} must be lowercase SHA-256")
    return value


def _digest(value: object, *, name: str) -> str:
    value = _string(value, name=name)
    if _DIGEST_RE.fullmatch(value) is None:
        raise ReceiptError(f"{name} must be an immutable image digest")
    return value


def _commit(value: object, *, name: str) -> str:
    value = _string(value, name=name)
    if _COMMIT_RE.fullmatch(value) is None:
        raise ReceiptError(f"{name} must be a full lowercase commit")
    return value


def _uuid(value: object, *, name: str) -> str:
    value = _string(value, name=name)
    try:
        if str(UUID(value)) != value:
            raise ValueError
    except ValueError as exc:
        raise ReceiptError(f"{name} must be a canonical UUID") from exc
    return value


def _review_nonce(value: object, *, name: str) -> str:
    value = _string(value, name=name)
    if _decode_base64url(value, expected_length=32) is None:
        raise ReceiptError(f"{name} must be canonical 256-bit base64url")
    return value


def _ledger_record_hash(record: dict[str, object]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
    return hashlib.sha256(_canonical_json(unsigned)).hexdigest()


def _trust_anchor() -> str:
    try:
        raw = json.loads(_TRUST_ANCHOR.read_bytes(), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as exc:
        raise ReceiptError("M05 activation trust anchor is invalid") from exc
    payload = _object(raw, name="M05 activation trust anchor")
    if (
        set(payload) != {"public_key_sha256", "reviewer_roster_sha256", "version"}
        or type(payload["version"]) is not int
        or payload["version"] != 1
    ):
        raise ReceiptError("M05 activation trust anchor schema is invalid")
    return _sha256(payload["public_key_sha256"], name="M05 activation public key fingerprint")


def _reviewer_public_keys(path: Path | None = None) -> dict[str, bytes]:
    roster_path = path or _REVIEWER_ROSTER
    try:
        raw_bytes = roster_path.read_bytes()
        raw = json.loads(raw_bytes, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as exc:
        raise ReceiptError("M05 reviewer roster is invalid") from exc
    payload = _object(raw, name="M05 reviewer roster")
    if set(payload) != {"agent_ids", "public_keys", "version"} or payload["version"] != 2:
        raise ReceiptError("M05 reviewer roster schema is invalid")
    agents = payload["agent_ids"]
    if not isinstance(agents, list) or len(agents) != 2:
        raise ReceiptError("M05 reviewer roster must contain exactly two agents")
    agent_ids = {_uuid(agent, name="M05 reviewer roster agent") for agent in agents}
    if len(agent_ids) != 2:
        raise ReceiptError("M05 reviewer roster agents must be distinct")
    public_keys = _object(payload["public_keys"], name="M05 reviewer roster public keys")
    if set(public_keys) != agent_ids:
        raise ReceiptError("M05 reviewer roster public key inventory is invalid")
    result: dict[str, bytes] = {}
    for agent_id in agent_ids:
        public_key = _decode_base64url(public_keys[agent_id], expected_length=32)
        if public_key is None:
            raise ReceiptError("M05 reviewer roster public key is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(public_key)
        except (ValueError, TypeError) as exc:
            raise ReceiptError("M05 reviewer roster public key is invalid") from exc
        result[agent_id] = public_key
    if path is None:
        try:
            trust = json.loads(
                _TRUST_ANCHOR.read_bytes(), object_pairs_hook=_reject_duplicate_keys
            )
            trust_object = _object(trust, name="M05 activation trust anchor")
            expected_roster_sha256 = _sha256(
                trust_object["reviewer_roster_sha256"], name="M05 reviewer roster fingerprint"
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ReceiptError, KeyError) as exc:
            raise ReceiptError("M05 reviewer roster trust binding is invalid") from exc
        if hashlib.sha256(raw_bytes).hexdigest() != expected_roster_sha256:
            raise ReceiptError("M05 reviewer roster does not match the vendored trust anchor")
    return result


def _reviewer_roster(path: Path | None = None) -> set[str]:
    return set(_reviewer_public_keys(path))


def _reviewer_signature_payload(
    *,
    agent_id: str,
    challenge_id: str,
    pinvi_source_revision: str,
    review_id: str,
    review_response_nonce: str,
    summary: str,
) -> dict[str, object]:
    return {
        "agent_id": agent_id,
        "challenge_id": challenge_id,
        "commit": pinvi_source_revision,
        "p0_p1": 0,
        "pr_url": _M05_ACTIVATION_PR_URL,
        "review_id": review_id,
        "review_nonce": review_response_nonce,
        "summary": summary,
        "verdict": "GO",
    }


def _review_challenge(
    path: Path,
    *,
    require_root_owned: bool,
    pinvi_source_revision: str,
    review_response_nonce: str,
    reviewer_roster_path: Path | None,
) -> tuple[str, dict[str, str], dict[str, dict[str, object]]]:
    raw = _read_secure_bytes(
        path,
        require_root_owned=require_root_owned,
        label="review challenge",
    )
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as exc:
        raise ReceiptError("review challenge is invalid JSON") from exc
    challenge = _object(value, name="review challenge")
    if set(challenge) != {
        "agent_ids",
        "commit",
        "challenge_id",
        "pr_url",
        "response_paths",
        "response_nonce_sha256",
        "version",
    }:
        raise ReceiptError("review challenge schema is invalid")
    if challenge["version"] != 2:
        raise ReceiptError("review challenge version is invalid")
    if (
        _sha256(challenge["response_nonce_sha256"], name="review challenge nonce hash")
        != hashlib.sha256(review_response_nonce.encode("ascii")).hexdigest()
    ):
        raise ReceiptError("review challenge nonce does not match the receipt input")
    challenge_id = _uuid(challenge["challenge_id"], name="review challenge ID")
    if _commit(challenge["commit"], name="review challenge commit") != pinvi_source_revision:
        raise ReceiptError("review challenge commit does not match the signed source revision")
    if challenge["pr_url"] != _M05_ACTIVATION_PR_URL:
        raise ReceiptError("review challenge is not pinned to M05")
    agent_ids = challenge["agent_ids"]
    if (
        not isinstance(agent_ids, list)
        or {_uuid(item, name="review challenge agent") for item in agent_ids}
        != _reviewer_roster(reviewer_roster_path)
    ):
        raise ReceiptError("review challenge must cover the pinned reviewers")
    response_paths = _object(challenge["response_paths"], name="review challenge response paths")
    if set(response_paths) != _reviewer_roster(reviewer_roster_path):
        raise ReceiptError("review challenge response path inventory is invalid")
    response_hashes: dict[str, str] = {}
    response_records: dict[str, dict[str, object]] = {}
    reviewer_public_keys = _reviewer_public_keys(reviewer_roster_path)
    for agent_id in reviewer_public_keys:
        response_path = Path(_string(response_paths[agent_id], name="review response path"))
        response_bytes = _read_secure_bytes(
            response_path,
            require_root_owned=require_root_owned,
            label="review response",
        )
        response_hashes[agent_id] = hashlib.sha256(response_bytes).hexdigest()
        response_records[agent_id] = _parse_review_response(
            response_bytes,
            agent_id=agent_id,
            challenge_id=challenge_id,
            pinvi_source_revision=pinvi_source_revision,
            review_response_nonce=review_response_nonce,
            reviewer_public_key=reviewer_public_keys[agent_id],
        )
    return challenge_id, response_hashes, response_records


def _parse_review_response(
    raw: bytes,
    *,
    agent_id: str,
    challenge_id: str,
    pinvi_source_revision: str,
    review_response_nonce: str,
    reviewer_public_key: bytes,
) -> dict[str, object]:
    """리뷰 도구의 machine-readable header를 검증해 임의 텍스트를 거부한다."""

    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ReceiptError("review response is not valid UTF-8") from exc
    fields: dict[str, str] = {}
    required = {
        "agent_id",
        "challenge_id",
        "commit",
        "p0_p1",
        "pr_url",
        "review_id",
        "reviewer_agent_id",
        "review_nonce",
        "review_signature",
        "reviewed_commit",
        "summary",
        "verdict",
    }
    for line in lines:
        if ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key in required:
            if key in fields:
                raise ReceiptError("review response repeats a required field")
            fields[key] = value
    if set(fields) != required:
        raise ReceiptError("review response machine-readable header is incomplete")
    if (
        _uuid(fields["agent_id"], name="review response agent_id") != agent_id
        or _uuid(fields["reviewer_agent_id"], name="review response reviewer_agent_id") != agent_id
        or _uuid(fields["challenge_id"], name="review response challenge_id") != challenge_id
        or _commit(fields["commit"], name="review response commit") != pinvi_source_revision
        or _commit(fields["reviewed_commit"], name="review response reviewed_commit")
        != pinvi_source_revision
        or _review_nonce(fields["review_nonce"], name="review response review_nonce")
        != review_response_nonce
        or fields["pr_url"] != _M05_ACTIVATION_PR_URL
        or fields["verdict"] != "GO"
        or fields["p0_p1"] != "0"
        or not fields["summary"]
        or any(character in "\r\n" for character in fields["summary"])
    ):
        raise ReceiptError("review response does not prove a zero-finding GO for the challenge")
    review_id = _uuid(fields["review_id"], name="review response review_id")
    signature = _decode_base64url(fields["review_signature"], expected_length=64)
    if signature is None:
        raise ReceiptError("review response signature encoding is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(reviewer_public_key).verify(
            signature,
            _canonical_json(
                _reviewer_signature_payload(
                    agent_id=agent_id,
                    challenge_id=challenge_id,
                    pinvi_source_revision=pinvi_source_revision,
                    review_id=review_id,
                    review_response_nonce=review_response_nonce,
                    summary=fields["summary"],
                )
            ),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ReceiptError("review response signature is invalid") from exc
    return {
        "agent_id": agent_id,
        "challenge_id": challenge_id,
        "commit": pinvi_source_revision,
        "p0_p1": 0,
        "pr_url": _M05_ACTIVATION_PR_URL,
        "review_id": review_id,
        "summary": fields["summary"],
        "verdict": "GO",
    }


def _review_allowlist(
    path: Path | None,
    *,
    challenge_path: Path,
    pinvi_source_revision: str,
    require_root_owned: bool,
    review_response_nonce: str,
    reviewer_roster_path: Path | None,
) -> set[tuple[str, str, str, str, str, str]]:
    if path is None:
        raise ReceiptError("production receipt requires an external review allowlist")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ReceiptError("review allowlist parent must be a regular directory")
    parent_stat = parent.stat()
    if stat.S_IMODE(parent_stat.st_mode) & 0o022:
        raise ReceiptError("review allowlist parent must not be group/world writable")
    if require_root_owned and parent_stat.st_uid != 0:
        raise ReceiptError("review allowlist parent is not root-owned")
    challenge_id, response_hashes, response_records = _review_challenge(
        challenge_path,
        require_root_owned=require_root_owned,
        pinvi_source_revision=pinvi_source_revision,
        review_response_nonce=review_response_nonce,
        reviewer_roster_path=reviewer_roster_path,
    )
    raw = _read_secure_bytes(
        path,
        require_root_owned=require_root_owned,
        label="review allowlist",
    )
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as exc:
        raise ReceiptError("review allowlist is invalid JSON") from exc
    if not isinstance(value, list) or len(value) != 2:
        raise ReceiptError("review allowlist must contain exactly two reviews")
    result: set[tuple[str, str, str, str, str, str]] = set()
    allowed_agents = _reviewer_roster(reviewer_roster_path)
    for item in value:
        review = _object(item, name="review allowlist entry")
        if set(review) != {
            "agent_id",
            "challenge_id",
            "commit",
            "pr_url",
            "response_sha256",
            "review_id",
        }:
            raise ReceiptError("review allowlist entry schema is invalid")
        agent_id = _uuid(review["agent_id"], name="review allowlist agent_id")
        commit = _commit(review["commit"], name="review allowlist commit")
        pr_url = _string(review["pr_url"], name="review allowlist pr_url")
        review_id = _uuid(review["review_id"], name="review allowlist review_id")
        if _uuid(review["challenge_id"], name="review allowlist challenge_id") != challenge_id:
            raise ReceiptError("review allowlist challenge does not match the challenge file")
        response_sha256 = _sha256(review["response_sha256"], name="review allowlist response hash")
        if response_hashes.get(agent_id) != response_sha256:
            raise ReceiptError("review allowlist response is not bound to the challenge file")
        if agent_id not in allowed_agents or pr_url != _M05_ACTIVATION_PR_URL:
            raise ReceiptError("review allowlist entry is not pinned to M05")
        response_record = response_records[agent_id]
        if (
            response_record["review_id"] != review_id
            or response_record["commit"] != commit
            or response_record["challenge_id"] != challenge_id
            or response_record["pr_url"] != pr_url
        ):
            raise ReceiptError("review allowlist metadata is not bound to the parsed response")
        key = (agent_id, review_id, commit, pr_url, challenge_id, response_sha256)
        if key in result:
            raise ReceiptError("review allowlist entries must be distinct")
        result.add(key)
    if {entry[0] for entry in result} != allowed_agents:
        raise ReceiptError("review allowlist must cover both pinned reviewers")
    return result


def _host_tool(name: str) -> str:
    directories = list(_HOST_TOOL_DIRECTORIES)
    if name in {"pg_dump", "pg_restore", "psql"}:
        directories.extend(sorted(Path("/usr/lib/postgresql").glob("*/bin")))
    for directory in directories:
        candidate = directory / name
        if (
            not candidate.is_file()
            or candidate.is_symlink()
            or not os.access(candidate, os.X_OK)
        ):
            continue
        resolved = candidate.resolve()
        if resolved.parent in _HOST_TOOL_DIRECTORIES or (
            name in {"pg_dump", "pg_restore", "psql"}
            and _POSTGRES_TOOL_DIRECTORY_RE.fullmatch(str(resolved.parent))
        ):
            return str(resolved)
    raise ReceiptError(f"pinned host tool is missing: {name}")


def _trusted_restore_tool_path(path: Path, name: str) -> bool:
    if path.name != name or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        return False
    parent = str(path.resolve().parent)
    return path.resolve().parent in _RESTORE_TOOL_DIRECTORIES or bool(
        _POSTGRES_TOOL_DIRECTORY_RE.fullmatch(parent)
    )


def _assert_source_checkout(
    source_revision: str,
    *,
    scope: str,
    test_mode: bool,
) -> None:
    """서명 대상 checkout과 PR 상태·merge provenance를 확인한다."""

    root = Path(__file__).resolve().parents[1]
    git_env = os.environ.copy()
    for name in tuple(git_env):
        if name.startswith("GIT_"):
            git_env.pop(name, None)
    git_env.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
    )
    try:
        top_level = subprocess.run(
            [_host_tool("git"), "-C", str(root), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
            env=git_env,
        ).stdout.strip()
        if Path(top_level).resolve() != root.resolve():
            raise ReceiptError("receipt producer checkout root is not canonical")
        revision = subprocess.run(
            [_host_tool("git"), "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            env=git_env,
        ).stdout.strip()
        status = subprocess.run(
            [
                _host_tool("git"),
                "-C",
                str(root),
                "status",
                "--porcelain",
                "--untracked-files=all",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=git_env,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReceiptError("receipt producer source revision could not be verified") from exc
    if revision != source_revision or (status and not test_mode):
        raise ReceiptError("receipt producer checkout must be clean at the signed revision")
    if test_mode:
        return
    pr_match = re.fullmatch(
        r"https://github\.com/digitie/pinvi/pull/([1-9][0-9]*)", _M05_ACTIVATION_PR_URL
    )
    if pr_match is None:
        raise ReceiptError("M05 activation PR URL is invalid")
    try:
        request = urllib.request.Request(
            f"https://api.github.com/repos/digitie/pinvi/pulls/{pr_match.group(1)}",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "pinvi-m05-activation-receipt",
            },
        )
        token = os.environ.get("PINVI_GITHUB_TOKEN", "")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        with _canonical_github_opener().open(
            request, timeout=20
        ) as response:
            if response.geturl() != request.full_url or response.getcode() != 200:
                raise ReceiptError("M05 activation PR response origin is not canonical")
            remote_payload = json.loads(response.read(), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ReceiptError) as exc:
        raise ReceiptError("M05 activation PR head could not be verified by GitHub") from exc
    remote_object = _object(remote_payload, name="GitHub pull request")
    head_object = _object(remote_object.get("head"), name="GitHub pull request head")
    base_object = _object(remote_object.get("base"), name="GitHub pull request base")
    head_repo = _object(head_object.get("repo"), name="GitHub pull request head repo")
    base_repo = _object(base_object.get("repo"), name="GitHub pull request base repo")
    remote_revision = _commit(head_object.get("sha"), name="GitHub pull request head SHA")
    if (
        remote_object.get("html_url") != _M05_ACTIVATION_PR_URL
        or base_object.get("ref") != "main"
        or base_repo.get("full_name") != "digitie/pinvi"
        or head_repo.get("full_name") != "digitie/pinvi"
        or head_object.get("ref") != "codex/m05-activation"
    ):
        raise ReceiptError("GitHub pull request provenance is not the canonical Pinvi PR")
    if scope == "production":
        if (
            remote_object.get("state") != "closed"
            or remote_object.get("draft") is not False
            or not isinstance(remote_object.get("merged_at"), str)
            or not remote_object.get("merged_at")
        ):
            raise ReceiptError("production receipt requires a closed, merged, non-draft M05 PR")
        merge_revision = _commit(
            remote_object.get("merge_commit_sha"),
            name="GitHub pull request merge commit SHA",
        )
        if merge_revision != source_revision:
            raise ReceiptError("production receipt source revision is not the merged M05 PR commit")
    elif remote_revision != source_revision:
        raise ReceiptError("receipt source revision is not the current M05 PR head")


def _ledger_records(path: Path, *, require_root_owned: bool) -> list[dict[str, object]]:
    if not path.is_file() or path.is_symlink():
        return []
    raw = _read_secure_bytes(
        path,
        require_root_owned=require_root_owned,
        label="activation ledger",
    )
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ReceiptError("activation ledger is not valid UTF-8") from exc
    records: list[dict[str, object]] = []
    previous_generation: int | None = None
    activation_nonces: set[str] = set()
    for line in lines:
        try:
            record = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, ReceiptError) as exc:
            raise ReceiptError("activation ledger contains invalid JSON") from exc
        record_object = _object(record, name="activation ledger record")
        if set(record_object) != {
            "activation_expires_at",
            "activation_generation",
            "activation_issued_at",
            "activation_nonce",
            "previous_record_sha256",
            "record_sha256",
            "receipt_sha256",
            "scope",
            "source_revision",
        }:
            raise ReceiptError("activation ledger record schema is invalid")
        generation = record_object["activation_generation"]
        issued_at = record_object["activation_issued_at"]
        expires_at = record_object["activation_expires_at"]
        scope = record_object["scope"]
        if (
            type(generation) is not int
            or generation < 1
            or (previous_generation is not None and generation <= previous_generation)
            or type(issued_at) is not int
            or type(expires_at) is not int
            or expires_at <= issued_at
            or expires_at - issued_at > 7 * 24 * 60 * 60
            or not isinstance(scope, str)
            or scope not in {"staging", "production"}
        ):
            raise ReceiptError("activation ledger record fields are invalid")
        activation_nonce = _uuid(record_object["activation_nonce"], name="ledger activation nonce")
        if activation_nonce in activation_nonces:
            raise ReceiptError("activation ledger contains a replayed nonce")
        activation_nonces.add(activation_nonce)
        previous_record_sha = _sha256(
            record_object["previous_record_sha256"],
            name="ledger previous record hash",
        )
        if previous_record_sha != (records[-1]["record_sha256"] if records else "0" * 64):
            raise ReceiptError("activation ledger hash chain is broken")
        _sha256(record_object["receipt_sha256"], name="ledger receipt hash")
        _commit(record_object["source_revision"], name="ledger source revision")
        if record_object["record_sha256"] != _ledger_record_hash(record_object):
            raise ReceiptError("activation ledger record hash is invalid")
        previous_generation = generation
        records.append(record_object)
    return records


def _read_high_watermark(path: Path, *, require_root_owned: bool) -> tuple[int, str] | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ReceiptError("activation high-watermark is not a regular file")
    raw = _read_secure_bytes(
        path,
        require_root_owned=require_root_owned,
        label="activation high-watermark",
    )
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as exc:
        raise ReceiptError("activation high-watermark is invalid JSON") from exc
    payload = _object(value, name="activation high-watermark")
    if set(payload) != {"generation", "receipt_sha256"}:
        raise ReceiptError("activation high-watermark schema is invalid")
    generation = payload["generation"]
    receipt_sha256 = _sha256(
        payload["receipt_sha256"], name="activation high-watermark receipt hash"
    )
    if type(generation) is not int or generation < 1:
        raise ReceiptError("activation high-watermark generation is invalid")
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ReceiptError("activation high-watermark mode is not 0600")
    if require_root_owned and metadata.st_uid != 0:
        raise ReceiptError("activation high-watermark is not root-owned")
    return generation, receipt_sha256


def _write_high_watermark(
    path: Path,
    *,
    generation: int,
    receipt_sha256: str,
    require_root_owned: bool,
) -> None:
    if type(generation) is not int or generation < 1:
        raise ReceiptError("activation high-watermark generation is invalid")
    receipt_sha256 = _sha256(receipt_sha256, name="activation high-watermark receipt hash")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ReceiptError("activation high-watermark parent must be a regular directory")
    parent_stat = path.parent.stat()
    if stat.S_IMODE(parent_stat.st_mode) & 0o022:
        raise ReceiptError("activation high-watermark parent must not be group/world writable")
    if require_root_owned and parent_stat.st_uid != 0:
        raise ReceiptError("activation high-watermark parent is not root-owned")
    existing = _read_high_watermark(path, require_root_owned=require_root_owned)
    if existing is not None:
        existing_generation, existing_receipt_sha256 = existing
        if existing_generation > generation:
            raise ReceiptError("activation high-watermark generation cannot move backwards")
        if existing_generation == generation and existing_receipt_sha256 != receipt_sha256:
            raise ReceiptError("activation high-watermark conflicts at the same generation")
        if existing_generation == generation:
            return

    temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    value = {"generation": generation, "receipt_sha256": receipt_sha256}
    fd = -1
    try:
        fd = os.open(temporary, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(_canonical_json(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise ReceiptError("activation high-watermark could not be updated") from exc
    finally:
        if fd != -1:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    written = _read_high_watermark(path, require_root_owned=require_root_owned)
    if written != (generation, receipt_sha256):
        raise ReceiptError("activation high-watermark update could not be verified")


def _read_durable_floor(path: Path, *, require_root_owned: bool) -> int | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ReceiptError("activation durable floor is not a regular file")
    raw = _read_secure_bytes(
        path,
        require_root_owned=require_root_owned,
        label="activation durable floor",
    )
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as exc:
        raise ReceiptError("activation durable floor is invalid JSON") from exc
    payload = _object(value, name="activation durable floor")
    generation = payload.get("generation")
    if set(payload) != {"generation"} or type(generation) is not int or generation < 1:
        raise ReceiptError("activation durable floor schema is invalid")
    return generation


def _durable_history_records(path: Path, *, require_root_owned: bool) -> list[dict[str, object]]:
    if not path.exists():
        return []
    raw = _read_secure_bytes(
        path,
        require_root_owned=require_root_owned,
        label="activation durable history",
    )
    records: list[dict[str, object]] = []
    previous_generation: int | None = None
    previous_record_sha256 = "0" * 64
    for line in raw.decode("utf-8").splitlines():
        try:
            value = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as exc:
            raise ReceiptError("activation durable history contains invalid JSON") from exc
        record = _object(value, name="activation durable history record")
        if set(record) != {
            "generation",
            "previous_record_sha256",
            "receipt_sha256",
            "record_sha256",
        }:
            raise ReceiptError("activation durable history record schema is invalid")
        generation = record["generation"]
        if (
            type(generation) is not int
            or generation < 1
            or (previous_generation is not None and generation <= previous_generation)
            or _sha256(record["previous_record_sha256"], name="durable history previous hash")
            != previous_record_sha256
        ):
            raise ReceiptError("activation durable history generation chain is invalid")
        _sha256(record["receipt_sha256"], name="durable history receipt hash")
        record_sha256 = _sha256(record["record_sha256"], name="durable history record hash")
        if record_sha256 != _ledger_record_hash(record):
            raise ReceiptError("activation durable history record hash is invalid")
        previous_generation = generation
        previous_record_sha256 = record_sha256
        records.append(record)
    return records


def _append_durable_history(
    path: Path,
    *,
    generation: int,
    receipt_sha256: str,
    require_root_owned: bool,
) -> None:
    receipt_sha256 = _sha256(receipt_sha256, name="activation durable history receipt hash")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ReceiptError("activation durable history parent must be a regular directory")
    parent_stat = path.parent.stat()
    if stat.S_IMODE(parent_stat.st_mode) & 0o022:
        raise ReceiptError("activation durable history parent must not be group/world writable")
    if require_root_owned and parent_stat.st_uid != 0:
        raise ReceiptError("activation durable history parent is not root-owned")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ReceiptError("activation durable history cannot be opened") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (require_root_owned and metadata.st_uid != 0)
        ):
            raise ReceiptError("activation durable history file permissions are invalid")
        records = _durable_history_records(path, require_root_owned=require_root_owned)
        if records:
            previous = records[-1]
            previous_generation = previous["generation"]
            if generation < previous_generation:
                raise ReceiptError("activation durable history generation cannot move backwards")
            if generation == previous_generation:
                if previous["receipt_sha256"] != receipt_sha256:
                    raise ReceiptError(
                        "activation durable history conflicts at the same generation"
                    )
                return
            previous_record_sha256 = cast(str, previous["record_sha256"])
        else:
            previous_record_sha256 = "0" * 64
        record: dict[str, object] = {
            "generation": generation,
            "previous_record_sha256": previous_record_sha256,
            "receipt_sha256": receipt_sha256,
        }
        record["record_sha256"] = _ledger_record_hash(record)
        with os.fdopen(fd, "ab") as stream:
            fd = -1
            stream.write(_canonical_json(record) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd != -1:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    records = _durable_history_records(path, require_root_owned=require_root_owned)
    if not records or records[-1]["generation"] != generation:
        raise ReceiptError("activation durable history update could not be verified")


@contextmanager
def _activation_write_lock(path: Path, *, require_root_owned: bool) -> Iterator[None]:
    """ledger와 네 개의 monotonic sidecar 갱신을 하나의 writer critical section으로 묶는다."""

    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise ReceiptError("activation ledger lock parent must be a regular directory")
    parent_stat = parent.stat()
    if stat.S_IMODE(parent_stat.st_mode) & 0o022:
        raise ReceiptError("activation ledger lock parent must not be group/world writable")
    if require_root_owned and parent_stat.st_uid != 0:
        raise ReceiptError("activation ledger lock parent is not root-owned")
    lock_path = parent / ".activation-ledger.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise ReceiptError("activation ledger lock cannot be opened") from exc
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (require_root_owned and metadata.st_uid != 0)
        ):
            raise ReceiptError("activation ledger lock permissions are invalid")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _write_durable_floor(path: Path, *, generation: int, require_root_owned: bool) -> None:
    if type(generation) is not int or generation < 1:
        raise ReceiptError("activation durable floor generation is invalid")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ReceiptError("activation durable floor parent must be a regular directory")
    parent_stat = path.parent.stat()
    if stat.S_IMODE(parent_stat.st_mode) & 0o022:
        raise ReceiptError("activation durable floor parent must not be group/world writable")
    if require_root_owned and parent_stat.st_uid != 0:
        raise ReceiptError("activation durable floor parent is not root-owned")
    existing = _read_durable_floor(path, require_root_owned=require_root_owned)
    if existing is not None:
        if existing > generation:
            raise ReceiptError("activation durable floor generation cannot move backwards")
        if existing == generation:
            return
    temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(temporary, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(_canonical_json({"generation": generation}))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise ReceiptError("activation durable floor could not be updated") from exc
    finally:
        if fd != -1:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    if _read_durable_floor(path, require_root_owned=require_root_owned) != generation:
        raise ReceiptError("activation durable floor update could not be verified")


def _database_anchor_url(database_url: str, *, require_root_owned: bool) -> str | None:
    if not database_url:
        if require_root_owned:
            raise ReceiptError("root-owned activation ledger requires a database anchor URL")
        return None
    if database_url.startswith("postgresql+asyncpg://"):
        database_url = "postgresql://" + database_url.removeprefix("postgresql+asyncpg://")
    return database_url


def _database_anchor_command_env() -> dict[str, str]:
    command_env = os.environ.copy()
    for name in (
        "BASH_ENV",
        "CDPATH",
        "ENV",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "PGAPPNAME",
        "PGDATABASE",
        "PGHOST",
        "PGPASSWORD",
        "PGPORT",
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGSSLMODE",
        "PSQLRC",
    ):
        command_env.pop(name, None)
    return command_env


def _read_database_anchor_generation(
    database_url: str,
    *,
    require_root_owned: bool,
) -> int | None:
    database_url = _database_anchor_url(database_url, require_root_owned=require_root_owned)
    if database_url is None:
        return None
    psql = _host_tool("psql")
    try:
        current = subprocess.run(
            [
                psql,
                "--no-psqlrc",
                "--set=ON_ERROR_STOP=1",
                "--tuples-only",
                "--no-align",
                "--dbname",
                database_url,
                "--command",
                "SELECT COALESCE(MAX(generation), 0)::text FROM ops.m05_activation_database_anchor",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=_database_anchor_command_env(),
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReceiptError("M05 activation database anchor could not be read") from exc
    try:
        return int(current)
    except ValueError as exc:
        raise ReceiptError("M05 activation database anchor returned an invalid generation") from exc


def _append_database_anchor(
    database_url: str,
    *,
    generation: int,
    receipt_sha256: str,
    record_sha256: str,
    require_root_owned: bool,
) -> None:
    database_url = _database_anchor_url(database_url, require_root_owned=require_root_owned)
    if database_url is None:
        return
    psql = _host_tool("psql")
    command_env = _database_anchor_command_env()
    current_generation = _read_database_anchor_generation(
        database_url,
        require_root_owned=require_root_owned,
    )
    if current_generation is None:
        raise ReceiptError("M05 activation database anchor URL is invalid")
    if current_generation > generation:
        raise ReceiptError("activation ledger generation is below the database anchor")
    if current_generation < generation:
        sql = (
            "INSERT INTO ops.m05_activation_database_anchor "
            "(generation, receipt_sha256, record_sha256) VALUES "
            f"({generation}, '{receipt_sha256}', '{record_sha256}') "
            "ON CONFLICT (generation) DO NOTHING"
        )
        try:
            subprocess.run(
                [
                    psql,
                    "--no-psqlrc",
                    "--set=ON_ERROR_STOP=1",
                    "--dbname",
                    database_url,
                    "--command",
                    sql,
                ],
                check=True,
                capture_output=True,
                text=True,
                env=command_env,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ReceiptError("M05 activation database anchor could not be appended") from exc
    try:
        stored = subprocess.run(
            [
                psql,
                "--no-psqlrc",
                "--set=ON_ERROR_STOP=1",
                "--tuples-only",
                "--no-align",
                "--dbname",
                database_url,
                "--command",
                (
                    "SELECT generation::text || '|' || receipt_sha256 || '|' || record_sha256 "
                    f"FROM ops.m05_activation_database_anchor WHERE generation = {generation}"
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=command_env,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReceiptError("M05 activation database anchor could not be verified") from exc
    if stored != f"{generation}|{receipt_sha256}|{record_sha256}":
        raise ReceiptError("M05 activation database anchor does not match the ledger record")


def _validate_ledger_receipt_signature(
    envelope_object: dict[str, object], *, public_key_value: str
) -> bytes:
    public_key_bytes = _decode_base64url(public_key_value, expected_length=32)
    signature_bytes = _decode_base64url(envelope_object.get("signature"), expected_length=64)
    if public_key_bytes is None or signature_bytes is None:
        raise ReceiptError("ledger requires a canonical signed receipt and public key")
    if (
        hashlib.sha256(public_key_bytes).hexdigest() != _trust_anchor()
        and os.environ.get("PINVI_M05_RECEIPT_TEST_MODE") != "1"
    ):
        raise ReceiptError("ledger public key does not match the vendored trust anchor")
    payload = _object(envelope_object["payload"], name="receipt payload")
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes, _canonical_json(payload)
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ReceiptError("ledger receipt signature is invalid") from exc
    return public_key_bytes


def _validate_ledger_evidence(args: argparse.Namespace, payload: dict[str, object]) -> None:
    evidence_directory_fd = _open_secure_directory(
        args.evidence_dir, require_root_owned=args.require_root_owned
    )
    try:
        evidence: dict[str, object] = {}
        evidence_hashes: dict[str, str] = {}
        paths = {name.removesuffix(".json").replace("-", "_"): Path(name) for name in _EVIDENCE_FILES}
        for key, path in paths.items():
            value, digest = _read_json(
                path,
                require_root_owned=args.require_root_owned,
                directory_fd=evidence_directory_fd,
            )
            evidence[key] = value
            evidence_hashes[key] = digest
    finally:
        os.close(evidence_directory_fd)

    expected_hashes = {
        "activation_attestation_sha256": evidence_hashes["attestation"],
        "ui_run_evidence_sha256": evidence_hashes["ui_run"],
        "live_ui_evidence_sha256": evidence_hashes["live_ui"],
        "map_pair_evidence_sha256": evidence_hashes["map_pair"],
        "pinvi_image_evidence_sha256": evidence_hashes["pinvi_images"],
        "restore_evidence_sha256": evidence_hashes["restore"],
        "review_evidence_sha256": evidence_hashes["reviews"],
    }
    for field, expected in expected_hashes.items():
        if payload.get(field) != expected:
            raise ReceiptError(f"receipt does not bind {field} to the supplied evidence")

    source_revision = _commit(payload["pinvi_source_revision"], name="receipt source revision")
    scope = _string(payload["scope"], name="receipt scope")
    reviewer_roster_path = args.reviewer_roster or _REVIEWER_ROSTER
    allowed_review_keys = _review_allowlist(
        args.review_allowlist,
        challenge_path=args.review_challenge,
        pinvi_source_revision=source_revision,
        require_root_owned=args.require_root_owned,
        review_response_nonce=_review_nonce(
            args.review_response_nonce,
            name="review response nonce",
        ),
        reviewer_roster_path=reviewer_roster_path,
    )
    reviews = _reviews(
        evidence["reviews"],
        pinvi_source_revision=source_revision,
        expected_pr_url=args.pr_url,
        allowed_review_keys=allowed_review_keys,
        reviewer_roster_path=reviewer_roster_path,
    )
    if payload.get("adversarial_reviews") != reviews:
        raise ReceiptError("receipt adversarial reviews do not match the supplied review evidence")
    live_ui = _live_ui(evidence["live_ui"], pinvi_source_revision=source_revision)
    _ui_run(
        evidence["ui_run"],
        live_ui=live_ui,
        pinvi_source_revision=source_revision,
        ui_run_sha256=evidence_hashes["ui_run"],
    )
    _restore(
        evidence["restore"],
        pinvi_source_revision=source_revision,
        environment=scope,
        require_root_owned=args.require_root_owned,
    )
    pair_expected = _pair_provenance()
    map_pair = _map_pair(evidence["map_pair"], pair_expected, environment=scope)
    pinvi_images = _pinvi_images(
        evidence["pinvi_images"],
        pinvi_source_revision=source_revision,
        environment=scope,
    )
    _attestation(
        evidence["attestation"],
        evidence_hashes={
            "live-ui": evidence_hashes["live_ui"],
            "ui-run": evidence_hashes["ui_run"],
            "map-pair": evidence_hashes["map_pair"],
            "pinvi-images": evidence_hashes["pinvi_images"],
            "restore": evidence_hashes["restore"],
            "reviews": evidence_hashes["reviews"],
        },
        live_ui=live_ui,
        pinvi_source_revision=source_revision,
        scope=scope,
        public_key_bytes=_decode_base64url(args.public_key, expected_length=32) or b"",
        issued_at=cast(int, payload["activation_issued_at"]),
        expires_at=cast(int, payload["activation_expires_at"]),
        activation_nonce=_uuid(payload["activation_nonce"], name="receipt activation nonce"),
    )
    if (
        payload.get("live_ui_event_id") != live_ui["event_id"]
        or payload.get("live_ui_verification_id") != live_ui["verification_id"]
        or payload.get("m04_attestation_sha256") != live_ui["m04_attestation_sha256"]
        or payload.get("m04_created_at") != live_ui["m04_created_at"]
        or payload.get("m04_feature_request_id") != live_ui["m04_feature_request_id"]
        or payload.get("m04_map_feature_uuid") != live_ui["m04_map_feature_uuid"]
        or payload.get("m04_map_pending_receipt_sha256")
        != live_ui["m04_map_pending_receipt_sha256"]
        or payload.get("m04_map_provenance_sha256")
        != live_ui["m04_map_provenance_sha256"]
        or payload.get("m04_map_request_sha256") != live_ui["m04_map_request_sha256"]
        or payload.get("m04_pinvi_approval_sha256")
        != live_ui["m04_pinvi_approval_sha256"]
        or payload.get("m04_verification_id") != live_ui["m04_verification_id"]
        or payload.get("activation_nonce") != live_ui["m04_verification_id"]
        or payload.get("m05_old_feature_id") != live_ui["old_feature_id"]
        or payload.get("m05_replacement_feature_id") != live_ui["replacement_feature_id"]
        or payload.get("m05_impact_count") != live_ui["impact_count"]
        or payload.get("m05_pinvi_detail_sha256") != live_ui["pinvi_detail_sha256"]
        or payload.get("live_ui_map_admin_endpoint") != live_ui["map_admin_endpoint"]
        or payload.get("live_ui_pinvi_api_endpoint") != live_ui["pinvi_api_endpoint"]
        or payload.get("live_ui_pinvi_web_endpoint") != live_ui["pinvi_web_endpoint"]
        or payload.get("map_admin_container_id") != map_pair["map_admin_container_id"]
        or payload.get("map_api_container_id") != map_pair["map_api_container_id"]
        or payload.get("map_frontend_container_id") != map_pair["map_frontend_container_id"]
        or payload.get("pinvi_api_container_id") != pinvi_images["api_container_id"]
        or payload.get("pinvi_web_container_id") != pinvi_images["web_container_id"]
        or payload.get("pinvi_dagster_container_id") != pinvi_images["dagster_container_id"]
    ):
        raise ReceiptError("receipt runtime identity does not match the supplied evidence")


def _ledger_unlocked(args: argparse.Namespace) -> int:
    receipt_bytes = _read_secure_bytes(
        args.receipt,
        require_root_owned=args.require_root_owned,
        label="receipt",
    )
    try:
        envelope = json.loads(receipt_bytes, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as exc:
        raise ReceiptError("receipt is not valid JSON") from exc
    envelope_object = _object(envelope, name="receipt")
    if set(envelope_object) != {"payload", "signature"}:
        raise ReceiptError("receipt envelope schema is invalid")
    _validate_ledger_receipt_signature(
        envelope_object,
        public_key_value=args.public_key,
    )
    payload = _object(envelope_object["payload"], name="receipt payload")
    required = {
        "activation_expires_at",
        "activation_generation",
        "activation_issued_at",
        "activation_nonce",
        "pinvi_source_revision",
        "scope",
    }
    if not required.issubset(payload):
        raise ReceiptError("receipt does not contain ledger fields")
    generation = payload["activation_generation"]
    issued_at = payload["activation_issued_at"]
    expires_at = payload["activation_expires_at"]
    if (
        type(generation) is not int
        or generation < 1
        or type(issued_at) is not int
        or type(expires_at) is not int
        or expires_at <= issued_at
        or not isinstance(payload["scope"], str)
        or payload["scope"] not in {"staging", "production"}
    ):
        raise ReceiptError("receipt ledger fields are invalid")
    _validate_ledger_evidence(args, payload)
    database_generation = _read_database_anchor_generation(
        args.durable_anchor_database_url,
        require_root_owned=args.require_root_owned,
    )
    if database_generation is not None and database_generation > generation:
        raise ReceiptError("activation ledger generation is below the database anchor")
    nonce = _uuid(payload["activation_nonce"], name="receipt activation nonce")
    source_revision = _commit(payload["pinvi_source_revision"], name="receipt source revision")
    record = {
        "activation_expires_at": expires_at,
        "activation_generation": generation,
        "activation_issued_at": issued_at,
        "activation_nonce": nonce,
        "previous_record_sha256": "0" * 64,
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "scope": payload["scope"],
        "source_revision": source_revision,
    }
    args.ledger.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.ledger.parent.is_symlink() or not args.ledger.parent.is_dir():
        raise ReceiptError("activation ledger parent must be a regular directory")
    if args.ledger.parent.stat().st_mode & 0o022:
        raise ReceiptError("activation ledger parent must not be group/world writable")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(args.ledger, flags, 0o600)
    except OSError as exc:
        raise ReceiptError("activation ledger cannot be opened") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        ledger_stat = os.fstat(fd)
        if not stat.S_ISREG(ledger_stat.st_mode) or stat.S_IMODE(ledger_stat.st_mode) != 0o600:
            raise ReceiptError("activation ledger mode is not 0600")
        if args.require_root_owned and ledger_stat.st_uid != 0:
            raise ReceiptError("activation ledger is not root-owned")
        records = _ledger_records(args.ledger, require_root_owned=args.require_root_owned)
        existing = next(
            (item for item in records if item["activation_nonce"] == nonce),
            None,
        )
        if existing is not None:
            if any(
                existing[field] != record[field]
                for field in (
                    "activation_expires_at",
                    "activation_generation",
                    "activation_issued_at",
                    "activation_nonce",
                    "receipt_sha256",
                    "scope",
                    "source_revision",
                )
            ):
                raise ReceiptError("activation nonce conflicts with the existing ledger record")
            record = existing
        else:
            if records:
                record["previous_record_sha256"] = records[-1]["record_sha256"]
                previous_generation = records[-1]["activation_generation"]
                if type(previous_generation) is not int or generation <= previous_generation:
                    raise ReceiptError("activation ledger generation must increase monotonically")
            record["record_sha256"] = _ledger_record_hash(record)
            with os.fdopen(fd, "ab") as stream:
                fd = -1
                stream.write(_canonical_json(record) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
    finally:
        if fd != -1:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    _write_high_watermark(
        args.high_watermark,
        generation=generation,
        receipt_sha256=cast(str, record["receipt_sha256"]),
        require_root_owned=args.require_root_owned,
    )
    _write_durable_floor(
        args.durable_floor,
        generation=generation,
        require_root_owned=args.require_root_owned,
    )
    _append_durable_history(
        args.durable_history,
        generation=generation,
        receipt_sha256=cast(str, record["receipt_sha256"]),
        require_root_owned=args.require_root_owned,
    )
    _append_durable_history(
        args.durable_anchor,
        generation=generation,
        receipt_sha256=cast(str, record["receipt_sha256"]),
        require_root_owned=args.require_root_owned,
    )
    _append_database_anchor(
        args.durable_anchor_database_url,
        generation=generation,
        receipt_sha256=cast(str, record["receipt_sha256"]),
        record_sha256=cast(str, record["record_sha256"]),
        require_root_owned=args.require_root_owned,
    )
    print(f"ledger_generation={generation}")
    print(f"ledger_receipt_sha256={record['receipt_sha256']}")
    return 0


def _ledger(args: argparse.Namespace) -> int:
    with _activation_write_lock(args.ledger, require_root_owned=args.require_root_owned):
        return _ledger_unlocked(args)


def _pair_provenance() -> dict[str, dict[str, str]]:
    try:
        raw = json.loads(_PAIR_PROVENANCE.read_bytes(), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as exc:
        raise ReceiptError("pair provenance file is invalid") from exc
    payload = _object(raw, name="pair provenance")
    # v1은 surface마다 `source_revision`을, 최상위에 `runtime_image_digests`를 갖는다.
    # 둘 다 pin registry/Manager receipt가 정본인 값의 두 번째 선언이라 v2가 걷어낸다
    # (`T-VN-PAIR-V2`). 이 스크립트는 그 두 값을 쓰지 않으므로 봉투 판정만 넓힌다.
    version = payload.get("version")
    if version == 1:
        expected_envelope = {"map", "runtime_image_digests", "version"}
    elif version == 2:
        expected_envelope = {"map", "version"}
    else:
        raise ReceiptError("pair provenance envelope is invalid")
    if set(payload) != expected_envelope or type(payload["version"]) is not int:
        raise ReceiptError("pair provenance envelope is invalid")
    map_value = _object(payload["map"], name="pair provenance map")
    if set(map_value) != {"admin", "full", "service", "user"}:
        raise ReceiptError("pair provenance map inventory is invalid")
    if version == 1:
        runtime_images = _object(
            payload["runtime_image_digests"], name="pair provenance runtime image digests"
        )
        if set(runtime_images) != {"admin", "api", "frontend"}:
            raise ReceiptError("pair provenance runtime image digest inventory is invalid")
    result: dict[str, dict[str, str]] = {}
    for name in ("admin", "full", "service", "user"):
        entry = _object(map_value.get(name), name=f"pair provenance {name}")
        expected_entry = {
            "openapi_sha256",
            "runtime_operation_contract_sha256",
            "source_canonical_sha256",
            "source_operation_contract_sha256",
        }
        if version == 1:
            expected_entry = expected_entry | {"source_revision"}
        if set(entry) != expected_entry:
            raise ReceiptError(f"pair provenance {name} schema is invalid")
        result[name] = {
            "openapi_sha256": _sha256(entry["openapi_sha256"], name=f"{name}.openapi_sha256"),
            "runtime_operation_contract_sha256": _sha256(
                entry["runtime_operation_contract_sha256"],
                name=f"{name}.runtime_operation_contract_sha256",
            ),
            "source_canonical_sha256": _sha256(
                entry["source_canonical_sha256"],
                name=f"{name}.source_canonical_sha256",
            ),
            "source_operation_contract_sha256": _sha256(
                entry["source_operation_contract_sha256"],
                name=f"{name}.source_operation_contract_sha256",
            ),
            **(
                {
                    "source_revision": _commit(
                        entry["source_revision"], name=f"{name}.source_revision"
                    )
                }
                if version == 1
                else {}
            ),
        }
    result["runtime_image_digests"] = {
        name: _digest(runtime_images[name], name=f"runtime_image_digests.{name}")
        for name in ("admin", "api", "frontend")
    }
    return result


def _reviews(
    value: object,
    *,
    pinvi_source_revision: str,
    expected_pr_url: str,
    allowed_review_keys: set[tuple[str, str, str, str, str, str]],
    reviewer_roster_path: Path | None,
) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != 2:
        raise ReceiptError("reviews.json must contain exactly two reviews")
    result: list[dict[str, object]] = []
    review_keys: set[tuple[str, str, str]] = set()
    allowlist_keys: set[tuple[str, str, str, str, str, str]] = set()
    reviewer_ids: set[str] = set()
    review_ids: set[str] = set()
    agent_ids: set[str] = set()
    allowed_agent_ids = _reviewer_roster(reviewer_roster_path)
    for item in value:
        review = _object(item, name="review")
        if set(review) != {
            "agent_id",
            "challenge_id",
            "commit",
            "p0_p1",
            "pr_url",
            "review_id",
            "reviewer_id",
            "response_sha256",
            "summary",
            "summary_sha256",
            "verdict",
        }:
            raise ReceiptError("review schema is invalid")
        if type(review["p0_p1"]) is not int or review["p0_p1"] != 0:
            raise ReceiptError("review P0/P1 count must be zero")
        commit = _commit(review["commit"], name="review.commit")
        if commit != pinvi_source_revision:
            raise ReceiptError("review commit does not match the signed Pinvi source revision")
        review_id = _uuid(review["review_id"], name="review.review_id")
        challenge_id = _uuid(review["challenge_id"], name="review.challenge_id")
        response_sha256 = _sha256(review["response_sha256"], name="review.response_sha256")
        reviewer_id = _uuid(review["reviewer_id"], name="review.reviewer_id")
        agent_id = _uuid(review["agent_id"], name="review.agent_id")
        if reviewer_id != agent_id:
            raise ReceiptError("review.reviewer_id must bind to review.agent_id")
        pr_url = _string(review["pr_url"], name="review.pr_url")
        if pr_url != expected_pr_url or _REVIEW_PR_RE.fullmatch(pr_url) is None:
            raise ReceiptError("review.pr_url must identify the exact Pinvi pull request")
        if agent_id not in allowed_agent_ids:
            raise ReceiptError("review.agent_id is not in the pinned reviewer roster")
        if review["verdict"] != "GO":
            raise ReceiptError("review verdict must be GO")
        summary = review["summary"]
        if (
            not isinstance(summary, str)
            or not summary
            or any(character in "\r\n" for character in summary)
        ):
            raise ReceiptError("review.summary must be a non-empty one-line string")
        summary_sha256 = _sha256(review["summary_sha256"], name="review.summary_sha256")
        if hashlib.sha256(summary.encode("utf-8")).hexdigest() != summary_sha256:
            raise ReceiptError("review summary hash is invalid")
        if reviewer_id in reviewer_ids or review_id in review_ids or agent_id in agent_ids:
            raise ReceiptError("reviews.json must contain distinct reviewers and review IDs")
        reviewer_ids.add(reviewer_id)
        review_ids.add(review_id)
        agent_ids.add(agent_id)
        normalized = {
            "commit": commit,
            "challenge_id": challenge_id,
            "p0_p1": 0,
            "agent_id": agent_id,
            "pr_url": pr_url,
            "review_id": review_id,
            "reviewer_id": reviewer_id,
            "response_sha256": response_sha256,
            "summary": summary,
            "summary_sha256": summary_sha256,
            "verdict": "GO",
        }
        key = (reviewer_id, review_id, commit)
        if key in review_keys:
            raise ReceiptError("reviews.json must contain two distinct reviews")
        review_keys.add(key)
        allowlist_key = (
            agent_id,
            review_id,
            commit,
            pr_url,
            challenge_id,
            response_sha256,
        )
        if allowlist_key not in allowed_review_keys:
            raise ReceiptError("review is not bound to the external review allowlist")
        allowlist_keys.add(allowlist_key)
        result.append(normalized)
    if allowlist_keys != allowed_review_keys:
        raise ReceiptError("external review allowlist does not match reviews.json")
    return result


def _live_ui(value: object, *, pinvi_source_revision: str) -> dict[str, object]:
    live = _object(value, name="live-ui evidence")
    expected = {
        "event_id",
        "event_sha256",
        "m04_attestation_sha256",
        "m04_created_at",
        "m04_feature_request_id",
        "m04_map_feature_uuid",
        "m04_map_pending_receipt_sha256",
        "m04_map_provenance_sha256",
        "m04_map_request_sha256",
        "m04_pinvi_approval_sha256",
        "m04_server_side_chain_verified",
        "m04_verification_id",
        "map_admin_endpoint",
        "map_ack_sha256",
        "map_local_receipt_sha256",
        "map_snapshot_after_sha256",
        "map_snapshot_before_sha256",
        "pinvi_api_endpoint",
        "pinvi_web_endpoint",
        "pinvi_receipt_sha256",
        "pinvi_source_revision",
        "pinvi_snapshot_after_sha256",
        "pinvi_snapshot_before_sha256",
        "old_feature_id",
        "replacement_feature_id",
        "impact_count",
        "pinvi_detail_sha256",
        "runner_exit_code",
        "server_side_ack_verified",
        "status",
        "ui_evidence_sha256",
        "verification_id",
        "playwright_runner_image_id",
        "playwright_runner_image_ref",
    }
    isolated_fields = {
        "isolated_execution_identity_sha256",
        "isolated_manager_source_revision",
        "isolated_pinset_sha256",
        "isolated_runtime_provenance_sha256",
    }
    supplied_isolated_fields = set(live) & isolated_fields
    if supplied_isolated_fields and supplied_isolated_fields != isolated_fields:
        raise ReceiptError("live-ui isolated execution binding is incomplete")
    expected |= supplied_isolated_fields
    if set(live) != expected or live["status"] != "passed":
        raise ReceiptError("live-ui evidence schema/status is invalid")
    if type(live["runner_exit_code"]) is not int or live["runner_exit_code"] != 0:
        raise ReceiptError("live-ui runner did not exit successfully")
    if live["server_side_ack_verified"] is not True:
        raise ReceiptError("live-ui server-side Map ACK was not verified")
    if live["m04_server_side_chain_verified"] is not True:
        raise ReceiptError("live-ui server-side M04→M05 chain was not verified")
    verification_id = _uuid(live["verification_id"], name="live-ui.verification_id")
    m04_verification_id = _uuid(
        live["m04_verification_id"], name="live-ui.m04_verification_id"
    )
    if m04_verification_id != verification_id:
        raise ReceiptError("live-ui M04 challenge is not bound to the M05 verification ID")
    m04_created_at = live["m04_created_at"]
    if type(m04_created_at) is not int or m04_created_at <= 0:
        raise ReceiptError("live-ui M04 creation time is invalid")
    _digest(
        live["playwright_runner_image_id"],
        name="live-ui.playwright_runner_image_id",
    )
    if (
        not isinstance(live["playwright_runner_image_ref"], str)
        or _PLAYWRIGHT_IMAGE_RE.fullmatch(live["playwright_runner_image_ref"]) is None
    ):
        raise ReceiptError("live-ui Playwright runner image reference is invalid")
    for field in ("map_admin_endpoint", "pinvi_api_endpoint", "pinvi_web_endpoint"):
        endpoint = live[field]
        if (
            not isinstance(endpoint, str)
            or not endpoint.startswith("http://127.0.0.1:")
            or any(character.isspace() for character in endpoint)
        ):
            raise ReceiptError(f"live-ui endpoint is not a canonical loopback URL: {field}")
    local_receipt_sha = _sha256(
        live["map_local_receipt_sha256"], name="live-ui.map_local_receipt_sha256"
    )
    pinvi_receipt_sha = _sha256(live["pinvi_receipt_sha256"], name="live-ui.pinvi_receipt_sha256")
    if local_receipt_sha != pinvi_receipt_sha:
        raise ReceiptError("live-ui Map ACK and Pinvi receipt hashes differ")
    if (
        live["map_snapshot_before_sha256"] != live["map_snapshot_after_sha256"]
        or live["pinvi_snapshot_before_sha256"] != live["pinvi_snapshot_after_sha256"]
    ):
        raise ReceiptError("live-ui remote snapshot drifted during the UI flow")
    if (
        _commit(live["pinvi_source_revision"], name="live-ui.pinvi_source_revision")
        != pinvi_source_revision
    ):
        raise ReceiptError("live-ui source revision does not match the signed Pinvi pair")
    old_feature_id = _string(live["old_feature_id"], name="live-ui.old_feature_id")
    replacement_feature_id = _string(
        live["replacement_feature_id"], name="live-ui.replacement_feature_id"
    )
    impact_count = live["impact_count"]
    if type(impact_count) is not int or impact_count < 0:
        raise ReceiptError("live-ui.impact_count is invalid")
    pinvi_detail_sha256 = _sha256(
        live["pinvi_detail_sha256"], name="live-ui.pinvi_detail_sha256"
    )
    result = {
        "event_id": _uuid(live["event_id"], name="live-ui.event_id"),
        "event_sha256": _sha256(live["event_sha256"], name="live-ui.event_sha256"),
        "m04_attestation_sha256": _sha256(
            live["m04_attestation_sha256"], name="live-ui.m04_attestation_sha256"
        ),
        "m04_created_at": m04_created_at,
        "m04_feature_request_id": _uuid(
            live["m04_feature_request_id"], name="live-ui.m04_feature_request_id"
        ),
        "m04_map_feature_uuid": _uuid(
            live["m04_map_feature_uuid"], name="live-ui.m04_map_feature_uuid"
        ),
        "m04_map_pending_receipt_sha256": _sha256(
            live["m04_map_pending_receipt_sha256"],
            name="live-ui.m04_map_pending_receipt_sha256",
        ),
        "m04_map_provenance_sha256": _sha256(
            live["m04_map_provenance_sha256"],
            name="live-ui.m04_map_provenance_sha256",
        ),
        "m04_map_request_sha256": _sha256(
            live["m04_map_request_sha256"], name="live-ui.m04_map_request_sha256"
        ),
        "m04_pinvi_approval_sha256": _sha256(
            live["m04_pinvi_approval_sha256"],
            name="live-ui.m04_pinvi_approval_sha256",
        ),
        "m04_verification_id": m04_verification_id,
        "map_ack_sha256": _sha256(live["map_ack_sha256"], name="live-ui.map_ack_sha256"),
        "map_admin_endpoint": _string(
            live["map_admin_endpoint"], name="live-ui.map_admin_endpoint"
        ),
        "map_local_receipt_sha256": local_receipt_sha,
        "map_snapshot_after_sha256": _sha256(
            live["map_snapshot_after_sha256"], name="live-ui.map_snapshot_after_sha256"
        ),
        "map_snapshot_before_sha256": _sha256(
            live["map_snapshot_before_sha256"],
            name="live-ui.map_snapshot_before_sha256",
        ),
        "pinvi_source_revision": pinvi_source_revision,
        "pinvi_api_endpoint": _string(
            live["pinvi_api_endpoint"], name="live-ui.pinvi_api_endpoint"
        ),
        "pinvi_web_endpoint": _string(
            live["pinvi_web_endpoint"], name="live-ui.pinvi_web_endpoint"
        ),
        "pinvi_receipt_sha256": pinvi_receipt_sha,
        "old_feature_id": old_feature_id,
        "replacement_feature_id": replacement_feature_id,
        "impact_count": impact_count,
        "pinvi_detail_sha256": pinvi_detail_sha256,
        "playwright_runner_image_id": _digest(
            live["playwright_runner_image_id"],
            name="live-ui.playwright_runner_image_id",
        ),
        "playwright_runner_image_ref": _string(
            live["playwright_runner_image_ref"],
            name="live-ui.playwright_runner_image_ref",
        ),
        "pinvi_snapshot_after_sha256": _sha256(
            live["pinvi_snapshot_after_sha256"],
            name="live-ui.pinvi_snapshot_after_sha256",
        ),
        "pinvi_snapshot_before_sha256": _sha256(
            live["pinvi_snapshot_before_sha256"],
            name="live-ui.pinvi_snapshot_before_sha256",
        ),
        "verification_id": verification_id,
        "ui_evidence_sha256": _sha256(
            live["ui_evidence_sha256"], name="live-ui.ui_evidence_sha256"
        ),
    }
    if supplied_isolated_fields:
        result.update(
            {
                "isolated_execution_identity_sha256": _sha256(
                    live["isolated_execution_identity_sha256"],
                    name="live-ui.isolated_execution_identity_sha256",
                ),
                "isolated_manager_source_revision": _commit(
                    live["isolated_manager_source_revision"],
                    name="live-ui.isolated_manager_source_revision",
                ),
                "isolated_pinset_sha256": _sha256(
                    live["isolated_pinset_sha256"], name="live-ui.isolated_pinset_sha256"
                ),
                "isolated_runtime_provenance_sha256": _sha256(
                    live["isolated_runtime_provenance_sha256"],
                    name="live-ui.isolated_runtime_provenance_sha256",
                ),
            }
        )
    return result


def _ui_run(
    value: object,
    *,
    live_ui: dict[str, object],
    pinvi_source_revision: str,
    ui_run_sha256: str,
) -> dict[str, object]:
    marker = _object(value, name="UI evidence marker")
    expected = {
        "assertions",
        "event_id",
        "impact_count",
        "old_feature_id",
        "pinvi_api_endpoint",
        "pinvi_detail_sha256",
        "replacement_feature_id",
        "source_revision",
        "status",
        "verification_id",
        "playwright_runner_image_id",
        "playwright_runner_image_ref",
    }
    if set(marker) != expected or marker["status"] != "passed":
        raise ReceiptError("UI evidence marker schema/status is invalid")
    event_id = _uuid(marker["event_id"], name="UI marker event ID")
    verification_id = _uuid(marker["verification_id"], name="UI marker verification ID")
    if event_id != live_ui["event_id"] or verification_id != live_ui["verification_id"]:
        raise ReceiptError("UI marker is not bound to the live UI event and verification ID")
    if _commit(marker["source_revision"], name="UI marker source revision") != pinvi_source_revision:
        raise ReceiptError("UI marker source revision does not match the receipt")
    if marker["pinvi_api_endpoint"] != live_ui["pinvi_api_endpoint"]:
        raise ReceiptError("UI marker does not bind the live Pinvi API endpoint")
    if marker["playwright_runner_image_id"] != live_ui["playwright_runner_image_id"] \
        or marker["playwright_runner_image_ref"] != live_ui["playwright_runner_image_ref"]:
        raise ReceiptError("UI marker Playwright runner does not match live UI evidence")
    impact_count = marker["impact_count"]
    if type(impact_count) is not int or impact_count < 0:
        raise ReceiptError("UI marker impact count is invalid")
    marker_values = {
        "old_feature_id": _string(marker["old_feature_id"], name="UI marker old_feature_id"),
        "replacement_feature_id": _string(
            marker["replacement_feature_id"], name="UI marker replacement_feature_id"
        ),
        "impact_count": impact_count,
        "pinvi_detail_sha256": _sha256(
            marker["pinvi_detail_sha256"], name="UI marker pinvi_detail_sha256"
        ),
    }
    for field, expected_value in marker_values.items():
        if live_ui[field] != expected_value:
            raise ReceiptError(f"UI marker does not bind live-ui.{field}")
    if _sha256(live_ui["ui_evidence_sha256"], name="live-ui.ui_evidence_sha256") != ui_run_sha256:
        raise ReceiptError("live-ui evidence hash does not match ui-run.json")
    return {
        "event_id": event_id,
        "impact_count": impact_count,
        "old_feature_id": marker_values["old_feature_id"],
        "pinvi_api_endpoint": _string(marker["pinvi_api_endpoint"], name="UI marker Pinvi API endpoint"),
        "pinvi_detail_sha256": marker_values["pinvi_detail_sha256"],
        "replacement_feature_id": marker_values["replacement_feature_id"],
        "source_revision": pinvi_source_revision,
        "verification_id": verification_id,
    }


def _restore(
    value: object,
    *,
    pinvi_source_revision: str,
    environment: str,
    require_root_owned: bool,
) -> None:
    restore = _object(value, name="restore evidence")
    expected = {
        "backup_runner_sha256",
        "backup_tool_path",
        "backup_tool_sha256",
        "bash_tool_path",
        "bash_tool_sha256",
        "psql_tool_path",
        "psql_tool_sha256",
        "dump_sha256",
        "execution_id",
        "no_owner_restore",
        "restore_command",
        "restore_output_sha256",
        "restore_db_runner_sha256",
        "hotswap_runner_sha256",
        "restore_runner_sha256",
        "m05_restore_drill_sha256",
        "restore_tool_path",
        "restore_tool_sha256",
        "tool_trust_manifest_path",
        "tool_trust_manifest_sha256",
        "git_tool_path",
        "git_tool_sha256",
        "environment",
        "fresh_target_verified",
        "fence_db_identity",
        "fence_db_identity_before_restore",
        "fence_db_identity_before_restore_sha256",
        "fence_db_identity_sha256",
        "fence_role",
        "fence_role_verified",
        "provisioner_login_disabled",
        "provisioner_role",
        "runtime_db_identity",
        "runtime_role",
        "runtime_role_verified",
        "source_db_identity",
        "source_db_identity_after_backup",
        "source_db_identity_after_backup_sha256",
        "source_db_identity_sha256",
        "source_revision",
        "staging_role",
        "staging_role_verified",
        "status",
        "target_db_identity",
        "target_db_identity_before_restore",
        "target_db_identity_before_restore_sha256",
        "target_db_identity_sha256",
        "target_recreated",
        "trigger_guard_verified",
        "runtime_db_identity_sha256",
        "hotswap_success",
        "hotswap_success_marker",
        "hotswap_success_output_sha256",
        "hotswap_schema_oid_before",
        "hotswap_schema_oid_after",
        "hotswap_previous_schema_oid",
        "hotswap_previous_schema_present",
        "hotswap_restore_schema_absent",
        "hotswap_advisory_lock_released",
        "hotswap_fence_restored",
        "hotswap_executor_reconnect_fenced",
    }
    if set(restore) != expected or restore["status"] != "passed":
        raise ReceiptError("restore evidence schema/status is invalid")
    if restore["environment"] != environment or environment == "test":
        raise ReceiptError("restore evidence is not from the signed non-test environment")
    if restore["fresh_target_verified"] is not True:
        raise ReceiptError("restore evidence does not prove a disposable fresh target")
    if restore["target_recreated"] is not True:
        raise ReceiptError("restore evidence does not prove target database recreation")
    if restore["restore_command"] != (
        "pg_restore --clean --if-exists --exit-on-error --no-owner --no-privileges"
    ):
        raise ReceiptError("restore evidence is not a no-owner restore")
    for field in (
        "no_owner_restore",
        "provisioner_login_disabled",
        "runtime_role_verified",
        "staging_role_verified",
        "fence_role_verified",
        "trigger_guard_verified",
        "hotswap_success",
        "hotswap_previous_schema_present",
        "hotswap_restore_schema_absent",
        "hotswap_advisory_lock_released",
        "hotswap_fence_restored",
        "hotswap_executor_reconnect_fenced",
    ):
        if restore[field] is not True:
            raise ReceiptError(f"restore evidence flag is not true: {field}")
    for field in (
        "backup_runner_sha256",
        "backup_tool_sha256",
        "psql_tool_sha256",
        "dump_sha256",
        "restore_output_sha256",
        "restore_db_runner_sha256",
        "hotswap_runner_sha256",
        "restore_runner_sha256",
        "m05_restore_drill_sha256",
        "restore_tool_sha256",
        "bash_tool_sha256",
        "git_tool_sha256",
        "tool_trust_manifest_sha256",
        "runtime_db_identity_sha256",
        "source_db_identity_after_backup_sha256",
        "source_db_identity_sha256",
        "target_db_identity_before_restore_sha256",
        "target_db_identity_sha256",
        "fence_db_identity_before_restore_sha256",
        "fence_db_identity_sha256",
        "hotswap_success_output_sha256",
    ):
        _sha256(restore[field], name=f"restore.{field}")
    if restore["hotswap_success_marker"] != (
        "RESTORE_PHASE=switching:success:schema-swap completed"
    ):
        raise ReceiptError("restore evidence does not prove a successful schema swap")
    for field in (
        "hotswap_schema_oid_before",
        "hotswap_schema_oid_after",
        "hotswap_previous_schema_oid",
    ):
        if (
            not isinstance(restore[field], str)
            or re.fullmatch(r"[0-9]+", restore[field]) is None
        ):
            raise ReceiptError(f"restore hotswap schema OID is invalid: {field}")
    if (
        restore["hotswap_schema_oid_before"] == restore["hotswap_schema_oid_after"]
        or restore["hotswap_previous_schema_oid"] != restore["hotswap_schema_oid_before"]
    ):
        raise ReceiptError("restore hotswap schema OID matrix is invalid")
    repository_root = Path(__file__).resolve().parents[1]
    tool_path_fields = {
        "bash": "bash_tool_path",
        "git": "git_tool_path",
        "pg_dump": "backup_tool_path",
        "pg_restore": "restore_tool_path",
        "psql": "psql_tool_path",
    }
    tool_digest_fields = {
        "bash": "bash_tool_sha256",
        "git": "git_tool_sha256",
        "pg_dump": "backup_tool_sha256",
        "pg_restore": "restore_tool_sha256",
        "psql": "psql_tool_sha256",
    }
    for field, expected_name in (
        ("backup_tool_path", "pg_dump"),
        ("bash_tool_path", "bash"),
        ("git_tool_path", "git"),
        ("psql_tool_path", "psql"),
        ("restore_tool_path", "pg_restore"),
    ):
        tool_path = _string(restore[field], name=f"restore.{field}")
        path_object = Path(tool_path)
        if (
            not tool_path.startswith("/")
            or any(character.isspace() for character in tool_path)
            or not _trusted_restore_tool_path(path_object, expected_name)
        ):
            raise ReceiptError(f"restore tool path is not a trusted system path: {field}")
        digest_field = field.removesuffix("_path") + "_sha256"
        if hashlib.sha256(path_object.read_bytes()).hexdigest() != restore[digest_field]:
            raise ReceiptError(f"restore tool digest is not bound to the path: {field}")
    manifest_path = Path(os.environ.get("PINVI_M05_RESTORE_TOOL_TRUST_MANIFEST", ""))
    if (
        not str(manifest_path)
        or manifest_path.is_symlink()
        or not manifest_path.is_file()
        or stat.S_IMODE(manifest_path.stat().st_mode) != 0o600
        or (require_root_owned and manifest_path.stat().st_uid != 0)
    ):
        raise ReceiptError("restore evidence requires the external tool trust manifest")
    manifest_bytes = manifest_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != restore["tool_trust_manifest_sha256"]:
        raise ReceiptError("restore tool trust manifest hash is not bound")
    try:
        manifest = json.loads(manifest_bytes, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ReceiptError) as exc:
        raise ReceiptError("restore tool trust manifest is invalid") from exc
    manifest_object = _object(manifest, name="restore tool trust manifest")
    if set(manifest_object) != {"tools", "version"} or manifest_object["version"] != 1:
        raise ReceiptError("restore tool trust manifest schema is invalid")
    tools = _object(manifest_object["tools"], name="restore tool trust manifest tools")
    if set(tools) != set(_RESTORE_TOOL_NAMES):
        raise ReceiptError("restore tool trust manifest inventory is invalid")
    for name in _RESTORE_TOOL_NAMES:
        entry = _object(tools[name], name=f"restore tool trust manifest {name}")
        if set(entry) != {"path", "sha256"}:
            raise ReceiptError("restore tool trust manifest entry schema is invalid")
        path = _string(entry["path"], name=f"restore tool trust manifest {name}.path")
        digest = _sha256(entry["sha256"], name=f"restore tool trust manifest {name}.sha256")
        if path != restore[tool_path_fields[name]]:
            raise ReceiptError(f"restore tool trust manifest path is not bound: {name}")
        if digest != restore[tool_digest_fields[name]]:
            raise ReceiptError(f"restore tool trust manifest digest is not bound: {name}")
    if restore["tool_trust_manifest_path"] != str(manifest_path):
        raise ReceiptError("restore tool trust manifest path is not bound")
    for evidence_field, script_path in (
        ("backup_runner_sha256", repository_root / "scripts/backup-db.sh"),
        ("restore_db_runner_sha256", repository_root / "scripts/restore-db.sh"),
        ("hotswap_runner_sha256", repository_root / "scripts/restore-hotswap.sh"),
        ("restore_runner_sha256", repository_root / "scripts/restore-staging-drill.sh"),
        ("m05_restore_drill_sha256", repository_root / "scripts/m05_restore_drill.py"),
    ):
        try:
            expected_script_sha256 = hashlib.sha256(script_path.read_bytes()).hexdigest()
        except OSError as exc:
            raise ReceiptError("restore runner source is missing") from exc
        if restore[evidence_field] != expected_script_sha256:
            raise ReceiptError(f"restore runner hash is not bound to {script_path.name}")
    for field in (
        "source_db_identity",
        "source_db_identity_after_backup",
        "target_db_identity_before_restore",
        "target_db_identity",
        "runtime_db_identity",
        "fence_db_identity_before_restore",
        "fence_db_identity",
    ):
        identity = _object(restore[field], name=f"restore.{field}")
        if set(identity) != {
            "database",
            "host",
            "hostaddr",
            "database_oid",
            "port",
            "schema_exists",
            "server_version_num",
            "sslmode",
            "system_identifier",
            "user",
        }:
            raise ReceiptError(f"restore.{field} identity schema is invalid")
    for identity_field, digest_field in (
        ("source_db_identity", "source_db_identity_sha256"),
        ("source_db_identity_after_backup", "source_db_identity_after_backup_sha256"),
        (
            "target_db_identity_before_restore",
            "target_db_identity_before_restore_sha256",
        ),
        ("target_db_identity", "target_db_identity_sha256"),
        ("runtime_db_identity", "runtime_db_identity_sha256"),
        (
            "fence_db_identity_before_restore",
            "fence_db_identity_before_restore_sha256",
        ),
        ("fence_db_identity", "fence_db_identity_sha256"),
    ):
        expected_identity_sha256 = hashlib.sha256(
            _canonical_json(restore[identity_field])
        ).hexdigest()
        if restore[digest_field] != expected_identity_sha256:
            raise ReceiptError(f"restore identity hash is not bound: {identity_field}")
    source_identity = _object(restore["source_db_identity"], name="restore.source_db_identity")
    source_after_backup_identity = _object(
        restore["source_db_identity_after_backup"],
        name="restore.source_db_identity_after_backup",
    )
    target_before_restore_identity = _object(
        restore["target_db_identity_before_restore"],
        name="restore.target_db_identity_before_restore",
    )
    target_identity = _object(restore["target_db_identity"], name="restore.target_db_identity")
    runtime_identity = _object(restore["runtime_db_identity"], name="restore.runtime_db_identity")
    fence_before_restore_identity = _object(
        restore["fence_db_identity_before_restore"],
        name="restore.fence_db_identity_before_restore",
    )
    fence_identity = _object(restore["fence_db_identity"], name="restore.fence_db_identity")
    for label, left, right in (
        ("source backup", source_identity, source_after_backup_identity),
        ("target restore", target_before_restore_identity, target_identity),
        ("target runtime", target_identity, runtime_identity),
        ("target fence before restore", target_before_restore_identity, fence_before_restore_identity),
        ("target fence", target_identity, fence_identity),
    ):
        if any(left[field] != right[field] for field in _RESTORE_IDENTITY_ENDPOINT_FIELDS):
            raise ReceiptError(f"restore {label} endpoint identity is not bound")
    if (
        runtime_identity["user"] != restore["runtime_role"]
        or target_before_restore_identity["user"] != restore["staging_role"]
        or fence_before_restore_identity["user"] != restore["fence_role"]
        or fence_identity["user"] != restore["fence_role"]
        or source_identity["schema_exists"] is not True
        or source_after_backup_identity["schema_exists"] is not True
        or target_before_restore_identity["schema_exists"] is not False
        or target_identity["schema_exists"] is not True
        or runtime_identity["schema_exists"] is not True
        or fence_before_restore_identity["schema_exists"] is not False
        or fence_identity["schema_exists"] is not True
        or _M05_RESTORE_DATABASE_RE.fullmatch(
            target_before_restore_identity["database"]
        )
        is None
        or _M05_RESTORE_DATABASE_RE.fullmatch(target_identity["database"]) is None
        or source_identity["database"] == target_before_restore_identity["database"]
        or source_identity["database_oid"] == target_before_restore_identity["database_oid"]
    ):
        raise ReceiptError("restore database identities or roles are not bound")
    _string(restore["runtime_role"], name="restore.runtime_role")
    _string(restore["staging_role"], name="restore.staging_role")
    fence_role = _string(restore["fence_role"], name="restore.fence_role")
    provisioner_role = _string(restore["provisioner_role"], name="restore.provisioner_role")
    if provisioner_role in {restore["runtime_role"], restore["staging_role"], fence_role}:
        raise ReceiptError("restore provisioner role is not dedicated")
    _uuid(restore["execution_id"], name="restore.execution_id")
    if _commit(restore["source_revision"], name="restore.source_revision") != pinvi_source_revision:
        raise ReceiptError("restore producer source revision does not match Pinvi")


def _map_pair(
    value: object,
    expected: dict[str, dict[str, str]],
    *,
    environment: str,
) -> dict[str, str]:
    pair = _object(value, name="Map pair evidence")
    if set(pair) != {
        "admin",
        "admin_image_digest",
        "api_image_digest",
        "frontend_image_digest",
        "full",
        "runtime",
        "service",
        "user",
    }:
        raise ReceiptError("Map pair evidence schema is invalid")
    for name in ("admin", "full", "service", "user"):
        entry = _object(pair[name], name=f"Map pair {name}")
        if set(entry) != {
            "openapi_sha256",
            "runtime_operation_contract_sha256",
            "source_canonical_sha256",
            "source_operation_contract_sha256",
            "source_revision",
        }:
            raise ReceiptError(f"Map pair {name} evidence schema is invalid")
        for field in ("openapi_sha256", "source_revision"):
            if entry[field] != expected[name][field]:
                raise ReceiptError(f"Map pair {name} does not match the vendored provenance")
        if (
            entry["runtime_operation_contract_sha256"]
            != expected[name]["runtime_operation_contract_sha256"]
            or entry["source_canonical_sha256"] != expected[name]["source_canonical_sha256"]
            or entry["source_operation_contract_sha256"]
            != expected[name]["source_operation_contract_sha256"]
        ):
            raise ReceiptError(f"Map pair {name} hashes are not pinned to provenance")
    runtime = _object(pair["runtime"], name="Map pair runtime evidence")
    if set(runtime) != {
        "admin_openapi",
        "admin",
        "api",
        "frontend",
        "full_openapi",
        "full_openapi_sha256",
        "service_openapi",
        "user_openapi",
    }:
        raise ReceiptError("Map pair runtime evidence schema is invalid")
    if runtime["full_openapi_sha256"] != expected["full"]["openapi_sha256"]:
        raise ReceiptError("Map runtime OpenAPI does not match the vendored provenance")
    runtime_openapi: dict[str, dict[str, object]] = {}
    for surface, provenance_name in (
        ("admin_openapi", "admin"),
        ("full_openapi", "full"),
        ("service_openapi", "service"),
        ("user_openapi", "user"),
    ):
        artifact = _object(runtime[surface], name=f"Map runtime {provenance_name} OpenAPI evidence")
        if set(artifact) != {
            "canonical_sha256",
            "source_canonical_sha256",
            "source_revision",
            "source_sha256",
            "surface_coverage_sha256",
            "transport",
            "transport_sha256",
        }:
            raise ReceiptError(f"Map runtime {provenance_name} OpenAPI evidence schema is invalid")
        expected_transport = "http" if provenance_name in {"admin", "full"} else "source-artifact"
        if artifact["transport"] != expected_transport:
            raise ReceiptError(f"Map runtime {provenance_name} OpenAPI transport is invalid")
        for field in (
            "canonical_sha256",
            "source_canonical_sha256",
            "surface_coverage_sha256",
            "transport_sha256",
        ):
            _sha256(
                artifact[field],
                name=f"Map runtime {provenance_name} OpenAPI.{field}",
            )
        if (
            (
                provenance_name != "full"
                and artifact["canonical_sha256"] != artifact["source_canonical_sha256"]
            )
            or artifact["source_sha256"] != expected[provenance_name]["openapi_sha256"]
            or artifact["source_canonical_sha256"]
            != expected[provenance_name]["source_canonical_sha256"]
            or artifact["surface_coverage_sha256"]
            != expected[provenance_name]["runtime_operation_contract_sha256"]
            # v1 계약은 Map revision을 스스로 선언해서 여기서 대조할 상대가 있었다.
            # v2는 그 선언을 걷어냈고 정본은 evidence artifact 하나다 — 대조 상대가
            # 사라지는 것이 v2의 목적이다. 형식 검증은 아래 `_commit`이 계속 한다.
            or (
                "source_revision" in expected[provenance_name]
                and artifact["source_revision"]
                != expected[provenance_name]["source_revision"]
            )
        ):
            raise ReceiptError(f"Map runtime {provenance_name} OpenAPI is not bound to the pair")
        _commit(
            artifact["source_revision"],
            name=f"Map runtime {provenance_name} OpenAPI.source_revision",
        )
        runtime_openapi[surface] = artifact
    if (
        runtime_openapi["full_openapi"]["canonical_sha256"]
        != runtime_openapi["admin_openapi"]["canonical_sha256"]
        or runtime_openapi["full_openapi"]["transport_sha256"]
        != runtime_openapi["admin_openapi"]["transport_sha256"]
    ):
        raise ReceiptError("Map full/admin runtime OpenAPI HTTP proofs do not match")
    for name in ("admin", "api", "frontend"):
        runtime_image = _object(runtime[name], name=f"Map runtime {name}")
        if set(runtime_image) != {
            "container_id",
            "digest",
            "environment",
            "image_id",
            "compose_project",
            "compose_service",
            "revision_label",
            "source_revision",
            "started_at",
        }:
            raise ReceiptError(f"Map runtime {name} evidence schema is invalid")
        if runtime_image["digest"] != runtime_image["image_id"]:
            raise ReceiptError(f"Map runtime {name} image ID is not bound to its digest")
        if runtime_image["revision_label"] != runtime_image["source_revision"]:
            raise ReceiptError(f"Map runtime {name} source label is not self-consistent")
        if runtime_image["environment"] != environment:
            raise ReceiptError(f"Map runtime {name} environment does not match receipt scope")
        if runtime_image["source_revision"] != expected["admin"]["source_revision"]:
            raise ReceiptError(f"Map runtime {name} source revision does not match the pair")
        _digest(runtime_image["digest"], name=f"Map runtime {name}.digest")
        _commit(runtime_image["source_revision"], name=f"Map runtime {name}.source_revision")
        _string(runtime_image["environment"], name=f"Map runtime {name}.environment")
        for field in ("compose_project", "compose_service"):
            value = runtime_image[field]
            if (
                not isinstance(value, str)
                or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value) is None
            ):
                raise ReceiptError(f"Map runtime {name} {field} is invalid")
        if (
            not isinstance(runtime_image["container_id"], str)
            or re.fullmatch(r"[0-9a-f]{64}\Z", runtime_image["container_id"]) is None
            or not isinstance(runtime_image["started_at"], str)
            or not runtime_image["started_at"]
        ):
            raise ReceiptError(f"Map runtime {name} container identity is invalid")
    map_projects = {runtime[name]["compose_project"] for name in ("admin", "api", "frontend")}
    map_services = {runtime[name]["compose_service"] for name in ("admin", "api", "frontend")}
    if len(map_projects) != 1 or len(map_services) != 3:
        raise ReceiptError("Map runtime Compose project/service binding is inconsistent")
    image_digests = {
        "admin": _digest(pair["admin_image_digest"], name="Map admin image digest"),
        "api": _digest(pair["api_image_digest"], name="Map API image digest"),
        "frontend": _digest(pair["frontend_image_digest"], name="Map frontend image digest"),
    }
    expected_image_digests = _object(
        expected["runtime_image_digests"], name="Map expected runtime image digests"
    )
    for name, digest in image_digests.items():
        if digest != _digest(
            expected_image_digests[name], name=f"Map expected {name} image digest"
        ):
            raise ReceiptError(f"Map {name} image digest does not match the pinned runtime")
        runtime_image = _object(runtime[name], name=f"Map runtime {name}")
        if digest != _digest(runtime_image["digest"], name=f"Map runtime {name} digest"):
            raise ReceiptError(f"Map {name} image digest is not bound to its runtime")
    return {
        "admin_image_digest": image_digests["admin"],
        # v2 계약은 Map revision을 선언하지 않는다. 그 값은 Manager가 만든 evidence
        # artifact에 있고, 여기서 그대로 실어 준다 — receipt payload가 그것을 담고
        # Ed25519 서명이 보호한다(`T-VN-PAIR-V2`).
        "source_revisions": {
            surface: runtime_openapi[f"{surface}_openapi"]["source_revision"]
            for surface in ("admin", "full", "service", "user")
        },
        "map_admin_container_id": runtime["admin"]["container_id"],
        "admin_runtime_openapi_sha256": _sha256(
            runtime_openapi["admin_openapi"]["transport_sha256"],
            name="Map runtime admin OpenAPI.transport_sha256",
        ),
        "admin_runtime_operation_contract_sha256": expected["admin"][
            "runtime_operation_contract_sha256"
        ],
        "full_runtime_openapi_sha256": _sha256(
            runtime_openapi["full_openapi"]["transport_sha256"],
            name="Map runtime full OpenAPI.transport_sha256",
        ),
        "full_runtime_operation_contract_sha256": expected["full"][
            "runtime_operation_contract_sha256"
        ],
        "api_image_digest": image_digests["api"],
        "map_api_container_id": runtime["api"]["container_id"],
        "frontend_image_digest": image_digests["frontend"],
        "map_frontend_container_id": runtime["frontend"]["container_id"],
        "service_runtime_openapi_sha256": _sha256(
            runtime_openapi["service_openapi"]["transport_sha256"],
            name="Map runtime service OpenAPI.transport_sha256",
        ),
        "service_runtime_operation_contract_sha256": expected["service"][
            "runtime_operation_contract_sha256"
        ],
        "user_runtime_openapi_sha256": _sha256(
            runtime_openapi["user_openapi"]["transport_sha256"],
            name="Map runtime user OpenAPI.transport_sha256",
        ),
        "user_runtime_operation_contract_sha256": expected["user"][
            "runtime_operation_contract_sha256"
        ],
    }


def _pinvi_images(value: object, *, pinvi_source_revision: str, environment: str) -> dict[str, str]:
    images = _object(value, name="Pinvi image evidence")
    if set(images) != {"api", "dagster", "web"}:
        raise ReceiptError("Pinvi image evidence schema is invalid")
    result: dict[str, str] = {}
    for name in ("api", "web", "dagster"):
        image = _object(images[name], name=f"Pinvi {name} image evidence")
        if set(image) != {
            "container_id",
            "digest",
            "environment",
            "image_id",
            "compose_project",
            "compose_service",
            "revision_label",
            "source_revision",
            "started_at",
        }:
            raise ReceiptError(f"Pinvi {name} image evidence schema is invalid")
        if image["environment"] != environment:
            raise ReceiptError(f"Pinvi {name} image environment does not match receipt scope")
        if image["digest"] != image["image_id"]:
            raise ReceiptError(f"Pinvi {name} image ID is not bound to its digest")
        if image["revision_label"] != image["source_revision"]:
            raise ReceiptError(f"Pinvi {name} image source label is not self-consistent")
        for field in ("compose_project", "compose_service"):
            value = image[field]
            if (
                not isinstance(value, str)
                or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value) is None
            ):
                raise ReceiptError(f"Pinvi {name} image {field} is invalid")
        if (
            _commit(image["source_revision"], name=f"Pinvi {name}.source_revision")
            != pinvi_source_revision
        ):
            raise ReceiptError("Pinvi runtime images do not share one source revision")
        if (
            not isinstance(image["container_id"], str)
            or re.fullmatch(r"[0-9a-f]{64}\Z", image["container_id"]) is None
            or not isinstance(image["started_at"], str)
            or not image["started_at"]
        ):
            raise ReceiptError(f"Pinvi {name} container identity is invalid")
        result[name] = _digest(image["digest"], name=f"Pinvi {name}.digest")
        result[f"{name}_container_id"] = image["container_id"]
    pinvi_projects = {images[name]["compose_project"] for name in ("api", "web", "dagster")}
    expected_services = {
        "api": "app-api",
        "web": "app-web",
        "dagster": "app-dagster",
    }
    if len(pinvi_projects) != 1 or any(
        images[name]["compose_service"] != service
        for name, service in expected_services.items()
    ):
        raise ReceiptError("Pinvi runtime Compose project/service binding is inconsistent")
    return result


def _attestation(
    value: object,
    *,
    evidence_hashes: dict[str, str],
    live_ui: dict[str, object],
    pinvi_source_revision: str,
    scope: str,
    public_key_bytes: bytes,
    issued_at: int,
    expires_at: int,
    activation_nonce: str,
) -> str:
    envelope = _object(value, name="M05 live attestation")
    if set(envelope) != {"payload", "signature"} or not isinstance(envelope["signature"], str):
        raise ReceiptError("M05 live attestation envelope is invalid")
    payload = _object(envelope["payload"], name="M05 live attestation payload")
    expected = {
        "created_at",
        "event_id",
        "evidence_sha256",
        "local_receipt_sha256",
        "map_admin_endpoint",
        "map_ack_sha256",
        "map_snapshot_sha256",
        "m04_attestation_sha256",
        "m04_created_at",
        "m04_feature_request_id",
        "m04_map_feature_uuid",
        "m04_map_pending_receipt_sha256",
        "m04_map_provenance_sha256",
        "m04_map_request_sha256",
        "m04_pinvi_approval_sha256",
        "m04_server_side_chain_verified",
        "m04_verification_id",
        "old_feature_id",
        "replacement_feature_id",
        "impact_count",
        "pinvi_detail_sha256",
        "pinvi_snapshot_sha256",
        "pinvi_api_endpoint",
        "pinvi_web_endpoint",
        "pinvi_source_revision",
        "playwright_runner_image_id",
        "playwright_runner_image_ref",
        "scope",
        "status",
        "verification_id",
        "version",
    }
    isolated_fields = {
        "isolated_execution_identity_sha256",
        "isolated_manager_source_revision",
        "isolated_pinset_sha256",
        "isolated_runtime_provenance_sha256",
    }
    if scope == "isolated":
        expected |= isolated_fields
    if set(payload) != expected:
        raise ReceiptError("M05 live attestation payload schema is invalid")
    if (
        type(payload["version"]) is not int
        or payload["version"] != (4 if scope == "isolated" else 3)
        or payload["status"] != "passed"
        or payload["scope"] != scope
        or _commit(payload["pinvi_source_revision"], name="attestation source revision")
        != pinvi_source_revision
        or _uuid(payload["event_id"], name="attestation event ID") != live_ui["event_id"]
        or type(payload["created_at"]) is not int
        or type(payload["m04_created_at"]) is not int
        or payload["created_at"] < issued_at - 60
        or payload["created_at"] > issued_at + 15 * 60
        or payload["created_at"] > int(time.time()) + 60
    ):
        raise ReceiptError("M05 live attestation identity/status is invalid")
    verification_id = _uuid(payload["verification_id"], name="attestation verification ID")
    m04_verification_id = _uuid(
        payload["m04_verification_id"], name="attestation M04 verification ID"
    )
    if (
        verification_id != activation_nonce
        or verification_id != live_ui["verification_id"]
        or m04_verification_id != verification_id
        or m04_verification_id != live_ui["m04_verification_id"]
    ):
        raise ReceiptError("M05 live attestation verification ID is not bound to the receipt nonce")
    m04_created_at = live_ui["m04_created_at"]
    if (
        type(m04_created_at) is not int
        or payload["m04_created_at"] != m04_created_at
        or m04_created_at > payload["created_at"]
        or payload["created_at"] - m04_created_at > 15 * 60
    ):
        raise ReceiptError("M05 live attestation M04 evidence is outside the activation window")
    if (
        payload["m04_server_side_chain_verified"] is not True
        or _sha256(
            payload["m04_attestation_sha256"], name="attestation.m04_attestation_sha256"
        )
        != live_ui["m04_attestation_sha256"]
        or _uuid(
            payload["m04_feature_request_id"], name="attestation.m04_feature_request_id"
        )
        != live_ui["m04_feature_request_id"]
        or _uuid(
            payload["m04_map_feature_uuid"], name="attestation.m04_map_feature_uuid"
        )
        != live_ui["m04_map_feature_uuid"]
        or _sha256(
            payload["m04_map_pending_receipt_sha256"],
            name="attestation.m04_map_pending_receipt_sha256",
        )
        != live_ui["m04_map_pending_receipt_sha256"]
        or _sha256(
            payload["m04_map_provenance_sha256"],
            name="attestation.m04_map_provenance_sha256",
        )
        != live_ui["m04_map_provenance_sha256"]
        or _sha256(
            payload["m04_map_request_sha256"], name="attestation.m04_map_request_sha256"
        )
        != live_ui["m04_map_request_sha256"]
        or _sha256(
            payload["m04_pinvi_approval_sha256"],
            name="attestation.m04_pinvi_approval_sha256",
        )
        != live_ui["m04_pinvi_approval_sha256"]
    ):
        raise ReceiptError("M05 live attestation does not bind the M04→M05 chain")
    if (
        payload["playwright_runner_image_id"] != live_ui["playwright_runner_image_id"]
        or payload["playwright_runner_image_ref"] != live_ui["playwright_runner_image_ref"]
    ):
        raise ReceiptError("M05 live attestation does not bind the Playwright runner")
    if (
        _string(payload["old_feature_id"], name="attestation.old_feature_id")
        != live_ui["old_feature_id"]
        or _string(payload["replacement_feature_id"], name="attestation.replacement_feature_id")
        != live_ui["replacement_feature_id"]
        or payload["impact_count"] != live_ui["impact_count"]
        or _sha256(payload["pinvi_detail_sha256"], name="attestation.pinvi_detail_sha256")
        != live_ui["pinvi_detail_sha256"]
    ):
        raise ReceiptError("M05 live attestation does not bind the UI target and impact scope")
    if scope == "isolated" and any(
        payload[field] != live_ui[field] for field in isolated_fields
    ):
        raise ReceiptError("M05 live attestation does not bind the isolated execution")
    _digest(
        payload["playwright_runner_image_id"],
        name="attestation.playwright_runner_image_id",
    )
    if _PLAYWRIGHT_IMAGE_RE.fullmatch(payload["playwright_runner_image_ref"]) is None:
        raise ReceiptError("M05 live attestation Playwright image reference is invalid")
    if payload["created_at"] > expires_at:
        raise ReceiptError("M05 live attestation is newer than the receipt expiry")
    for field, expected_endpoint in (
        ("map_admin_endpoint", live_ui["map_admin_endpoint"]),
        ("pinvi_api_endpoint", live_ui["pinvi_api_endpoint"]),
        ("pinvi_web_endpoint", live_ui["pinvi_web_endpoint"]),
    ):
        if payload[field] != expected_endpoint:
            raise ReceiptError(f"M05 live attestation does not bind {field}")
    if (
        _sha256(payload["local_receipt_sha256"], name="attestation.local_receipt_sha256")
        != live_ui["map_local_receipt_sha256"]
        or live_ui["map_local_receipt_sha256"] != live_ui["pinvi_receipt_sha256"]
    ):
        raise ReceiptError("M05 live attestation does not bind the terminal receipt hash")
    for field, expected_value in (
        ("map_ack_sha256", live_ui["map_ack_sha256"]),
        ("map_snapshot_sha256", live_ui["map_snapshot_after_sha256"]),
        ("pinvi_snapshot_sha256", live_ui["pinvi_snapshot_after_sha256"]),
    ):
        if _sha256(payload[field], name=f"attestation.{field}") != expected_value:
            raise ReceiptError(f"M05 live attestation does not bind {field}")
    attested_hashes = _object(payload["evidence_sha256"], name="attestation evidence hashes")
    # reviews/restore는 사람 리뷰·복구 드릴의 **외부** 증거로 staging/production
    # 활성화 경로에만 존재한다. 격리 harness는 기계 체인만 증명하므로 그 둘을
    # 생산하지 않으며, 생산자(attestation)와 검증자(여기)가 서로 다른 목록을
    # 선언하면 같은 이중 선언 결함이 방향만 바뀌어 남는다(적대 리뷰).
    expected_evidence = ("ui-run", "live-ui", "map-pair", "pinvi-images")
    if scope != "isolated":
        expected_evidence += ("restore", "reviews")
    if set(attested_hashes) != set(expected_evidence):
        raise ReceiptError("M05 live attestation evidence inventory is invalid")
    for name in expected_evidence:
        if _sha256(attested_hashes[name], name=f"attestation.{name}") != evidence_hashes[name]:
            raise ReceiptError(f"M05 live attestation does not bind {name} evidence")
    signature_bytes = _decode_base64url(envelope["signature"], expected_length=64)
    if signature_bytes is None:
        raise ReceiptError("M05 live attestation signature encoding is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes, _canonical_json(payload)
        )
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise ReceiptError("M05 live attestation signature is invalid") from exc
    return verification_id


def _runtime_dependency(value: object, *, name: str) -> dict[str, object]:
    dependency = _object(value, name=f"{name} runtime dependency")
    expected = {
        "container_id",
        "digest",
        "environment",
        "image_id",
        "compose_project",
        "compose_service",
        "revision_label",
        "source_revision",
        "started_at",
    }
    if set(dependency) != expected:
        raise ReceiptError(f"{name} runtime dependency schema is invalid")
    if dependency["digest"] != dependency["image_id"]:
        raise ReceiptError(f"{name} runtime dependency image is not digest-bound")
    if dependency["revision_label"] != dependency["source_revision"]:
        raise ReceiptError(f"{name} runtime dependency source label is not bound")
    if (
        not isinstance(dependency["container_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}\Z", dependency["container_id"]) is None
        or not isinstance(dependency["started_at"], str)
        or not dependency["started_at"]
    ):
        raise ReceiptError(f"{name} runtime dependency identity is invalid")
    _digest(dependency["digest"], name=f"{name}.digest")
    _string(dependency["environment"], name=f"{name}.environment")
    for field in ("compose_project", "compose_service"):
        value = dependency[field]
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value) is None
        ):
            raise ReceiptError(f"{name} runtime dependency {field} is invalid")
    _commit(dependency["source_revision"], name=f"{name}.source_revision")
    return dependency


def _create(args: argparse.Namespace) -> int:
    evidence_dir = args.evidence_dir
    evidence_directory_fd = _open_secure_directory(
        evidence_dir, require_root_owned=args.require_root_owned
    )

    source_revision = _commit(args.pinvi_source_revision, name="Pinvi source revision")
    scope = _string(args.scope, name="receipt scope")
    if scope not in {"staging", "production"}:
        raise ReceiptError("receipt scope must be staging or production")
    _assert_source_checkout(
        source_revision,
        scope=scope,
        test_mode=(
            os.environ.get("PINVI_M05_RECEIPT_TEST_MODE") == "1"
            and not args.require_root_owned
        ),
    )
    if args.pr_url != _M05_ACTIVATION_PR_URL:
        raise ReceiptError("M05 activation receipt is pinned to PR #466")
    reviewer_roster_path = args.reviewer_roster or _REVIEWER_ROSTER
    if args.require_root_owned and reviewer_roster_path != _REVIEWER_ROSTER:
        raise ReceiptError("root-owned M05 receipt must use the vendored reviewer roster")
    if scope == "production" and (
        not args.require_root_owned
        or os.environ.get("PINVI_M05_RECEIPT_TEST_MODE") == "1"
    ):
        raise ReceiptError("production receipt requires root-owned evidence and cannot use test mode")
    allowed_review_keys = _review_allowlist(
        args.review_allowlist,
        challenge_path=args.review_challenge,
        pinvi_source_revision=source_revision,
        require_root_owned=args.require_root_owned,
        review_response_nonce=_review_nonce(
            args.review_response_nonce,
            name="review response nonce",
        ),
        reviewer_roster_path=reviewer_roster_path,
    )
    now = int(time.time())
    issued_at = args.activation_issued_at if args.activation_issued_at is not None else now
    expires_at = (
        args.activation_expires_at if args.activation_expires_at is not None else now + 24 * 60 * 60
    )
    if type(issued_at) is not int or type(expires_at) is not int:
        raise ReceiptError("activation timestamps must be integers")
    if issued_at > now + 60 or expires_at <= now or expires_at <= issued_at:
        raise ReceiptError("activation receipt freshness window is invalid")
    if expires_at - issued_at > 7 * 24 * 60 * 60:
        raise ReceiptError("activation receipt lifetime exceeds seven days")
    paths = {name.removesuffix(".json").replace("-", "_"): Path(name) for name in _EVIDENCE_FILES}
    try:
        evidence: dict[str, object] = {}
        evidence_hashes: dict[str, str] = {}
        for key, path in paths.items():
            value, digest = _read_json(
                path,
                require_root_owned=args.require_root_owned,
                directory_fd=evidence_directory_fd,
            )
            evidence[key] = value
            evidence_hashes[key] = digest

        attestation_envelope = _object(evidence["attestation"], name="M05 live attestation")
        attestation_payload = _object(
            attestation_envelope.get("payload"), name="M05 live attestation payload"
        )
        attestation_nonce = _uuid(
            attestation_payload.get("verification_id"),
            name="M05 attestation verification ID",
        )
        activation_nonce = _uuid(
            args.activation_nonce or attestation_nonce, name="activation nonce"
        )
        if activation_nonce != attestation_nonce:
            raise ReceiptError("activation nonce must match the live attestation verification ID")
        reviews = _reviews(
            evidence["reviews"],
            pinvi_source_revision=source_revision,
            expected_pr_url=args.pr_url,
            allowed_review_keys=allowed_review_keys,
            reviewer_roster_path=reviewer_roster_path,
        )
        live_ui = _live_ui(evidence["live_ui"], pinvi_source_revision=source_revision)
        _ui_run(
            evidence["ui_run"],
            live_ui=live_ui,
            pinvi_source_revision=source_revision,
            ui_run_sha256=evidence_hashes["ui_run"],
        )
        _restore(
            evidence["restore"],
            pinvi_source_revision=source_revision,
            environment=scope,
            require_root_owned=args.require_root_owned,
        )
        pair_expected = _pair_provenance()
        map_pair = _map_pair(evidence["map_pair"], pair_expected, environment=scope)
        pinvi_images = _pinvi_images(
            evidence["pinvi_images"],
            pinvi_source_revision=source_revision,
            environment=scope,
        )
    finally:
        os.close(evidence_directory_fd)

    private_key_bytes = _read_secure_bytes(
        args.private_key,
        require_root_owned=args.require_root_owned,
        label="private key",
    )
    try:
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    except (ValueError, TypeError) as exc:
        raise ReceiptError("private key is not valid PEM") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ReceiptError("private key is not Ed25519")
    public_key_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if args.require_root_owned and hashlib.sha256(public_key_raw).hexdigest() != _trust_anchor():
        raise ReceiptError("private key does not match the vendored M05 trust anchor")
    _attestation(
        evidence["attestation"],
        evidence_hashes={
            "live-ui": evidence_hashes["live_ui"],
            "ui-run": evidence_hashes["ui_run"],
            "map-pair": evidence_hashes["map_pair"],
            "pinvi-images": evidence_hashes["pinvi_images"],
            "restore": evidence_hashes["restore"],
            "reviews": evidence_hashes["reviews"],
        },
        live_ui=live_ui,
        pinvi_source_revision=source_revision,
        scope=scope,
        public_key_bytes=public_key_raw,
        issued_at=issued_at,
        expires_at=expires_at,
        activation_nonce=activation_nonce,
    )

    payload: dict[str, object] = {
        "activation_expires_at": expires_at,
        "activation_generation": args.activation_generation,
        "activation_issued_at": issued_at,
        "activation_nonce": activation_nonce,
        "activation_attestation_sha256": evidence_hashes["attestation"],
        "adversarial_reviews": reviews,
        "live_ui_e2e": "passed",
        "live_ui_event_id": live_ui["event_id"],
        "m05_old_feature_id": live_ui["old_feature_id"],
        "m05_replacement_feature_id": live_ui["replacement_feature_id"],
        "m05_impact_count": live_ui["impact_count"],
        "m05_pinvi_detail_sha256": live_ui["pinvi_detail_sha256"],
        "ui_run_evidence_sha256": evidence_hashes["ui_run"],
        "live_ui_evidence_sha256": evidence_hashes["live_ui"],
        "live_ui_map_ack_sha256": live_ui["map_ack_sha256"],
        "live_ui_local_receipt_sha256": live_ui["map_local_receipt_sha256"],
        "live_ui_map_admin_endpoint": live_ui["map_admin_endpoint"],
        "live_ui_map_snapshot_sha256": live_ui["map_snapshot_after_sha256"],
        "live_ui_pinvi_api_endpoint": live_ui["pinvi_api_endpoint"],
        "live_ui_pinvi_snapshot_sha256": live_ui["pinvi_snapshot_after_sha256"],
        "live_ui_pinvi_web_endpoint": live_ui["pinvi_web_endpoint"],
        "live_ui_playwright_runner_image_id": live_ui["playwright_runner_image_id"],
        "live_ui_playwright_runner_image_ref": live_ui["playwright_runner_image_ref"],
        "live_ui_verification_id": live_ui["verification_id"],
        "m04_attestation_sha256": live_ui["m04_attestation_sha256"],
        "m04_created_at": live_ui["m04_created_at"],
        "m04_feature_request_id": live_ui["m04_feature_request_id"],
        "m04_map_feature_uuid": live_ui["m04_map_feature_uuid"],
        "m04_map_pending_receipt_sha256": live_ui[
            "m04_map_pending_receipt_sha256"
        ],
        "m04_map_provenance_sha256": live_ui["m04_map_provenance_sha256"],
        "m04_map_request_sha256": live_ui["m04_map_request_sha256"],
        "m04_pinvi_approval_sha256": live_ui["m04_pinvi_approval_sha256"],
        "m04_verification_id": live_ui["m04_verification_id"],
        "map_admin_openapi_sha256": pair_expected["admin"]["openapi_sha256"],
        "map_admin_runtime_openapi_sha256": map_pair["admin_runtime_openapi_sha256"],
        "map_admin_runtime_operation_contract_sha256": map_pair[
            "admin_runtime_operation_contract_sha256"
        ],
        "map_admin_source_operation_contract_sha256": pair_expected["admin"][
            "source_operation_contract_sha256"
        ],
        "map_admin_source_revision": map_pair["source_revisions"]["admin"],
        "map_admin_image_digest": map_pair["admin_image_digest"],
        "map_admin_container_id": map_pair["map_admin_container_id"],
        "map_api_image_digest": map_pair["api_image_digest"],
        "map_api_container_id": map_pair["map_api_container_id"],
        "map_frontend_image_digest": map_pair["frontend_image_digest"],
        "map_frontend_container_id": map_pair["map_frontend_container_id"],
        "map_full_openapi_sha256": pair_expected["full"]["openapi_sha256"],
        "map_full_runtime_openapi_sha256": map_pair["full_runtime_openapi_sha256"],
        "map_full_runtime_operation_contract_sha256": map_pair[
            "full_runtime_operation_contract_sha256"
        ],
        "map_full_source_operation_contract_sha256": pair_expected["full"][
            "source_operation_contract_sha256"
        ],
        "map_full_source_revision": map_pair["source_revisions"]["full"],
        "map_pair_evidence_sha256": evidence_hashes["map_pair"],
        "map_service_openapi_sha256": pair_expected["service"]["openapi_sha256"],
        "map_service_runtime_openapi_sha256": map_pair["service_runtime_openapi_sha256"],
        "map_service_runtime_operation_contract_sha256": map_pair[
            "service_runtime_operation_contract_sha256"
        ],
        "map_service_source_operation_contract_sha256": pair_expected["service"][
            "source_operation_contract_sha256"
        ],
        "map_service_source_revision": map_pair["source_revisions"]["service"],
        "map_user_openapi_sha256": pair_expected["user"]["openapi_sha256"],
        "map_user_runtime_openapi_sha256": map_pair["user_runtime_openapi_sha256"],
        "map_user_runtime_operation_contract_sha256": map_pair[
            "user_runtime_operation_contract_sha256"
        ],
        "map_user_source_operation_contract_sha256": pair_expected["user"][
            "source_operation_contract_sha256"
        ],
        "map_user_source_revision": map_pair["source_revisions"]["user"],
        "pinvi_api_image_digest": pinvi_images["api"],
        "pinvi_api_container_id": pinvi_images["api_container_id"],
        "pinvi_dagster_image_digest": pinvi_images["dagster"],
        "pinvi_dagster_container_id": pinvi_images["dagster_container_id"],
        "pinvi_image_evidence_sha256": evidence_hashes["pinvi_images"],
        "pinvi_source_revision": source_revision,
        "pinvi_web_container_id": pinvi_images["web_container_id"],
        "pinvi_web_image_digest": pinvi_images["web"],
        "restore_drill": "passed",
        "restore_evidence_sha256": evidence_hashes["restore"],
        "review_evidence_sha256": evidence_hashes["reviews"],
        "scope": scope,
        "version": 2,
    }
    signed = {
        "payload": payload,
        "signature": _base64url(private_key.sign(_canonical_json(payload))),
    }
    _write_new_json(args.output, signed)
    map_pair_evidence = _object(evidence["map_pair"], name="Map pair evidence")
    map_runtime = _object(map_pair_evidence["runtime"], name="Map pair runtime evidence")
    pinvi_image_evidence = _object(evidence["pinvi_images"], name="Pinvi image evidence")
    runtime_payload = {
        "activation_generation": args.activation_generation,
        "activation_nonce": activation_nonce,
        "created_at": int(time.time()),
        "dependencies": {
            "map_admin": _runtime_dependency(map_runtime["admin"], name="Map admin"),
            "map_api": _runtime_dependency(map_runtime["api"], name="Map API"),
            "map_frontend": _runtime_dependency(map_runtime["frontend"], name="Map frontend"),
            "pinvi_api": _runtime_dependency(pinvi_image_evidence["api"], name="Pinvi API"),
            "pinvi_web": _runtime_dependency(pinvi_image_evidence["web"], name="Pinvi Web"),
            "pinvi_dagster": _runtime_dependency(
                pinvi_image_evidence["dagster"], name="Pinvi Dagster"
            ),
        },
        "endpoints": {
            "map_admin": live_ui["map_admin_endpoint"],
            "pinvi_api": live_ui["pinvi_api_endpoint"],
            "pinvi_web": live_ui["pinvi_web_endpoint"],
        },
        "pinvi_source_revision": source_revision,
        "receipt_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "scope": scope,
        "version": 2,
    }
    runtime_attestation = {
        "payload": runtime_payload,
        "signature": _base64url(private_key.sign(_canonical_json(runtime_payload))),
    }
    runtime_attestation_path = evidence_dir / "runtime-attestation.json"
    _write_new_json(runtime_attestation_path, runtime_attestation)
    print(f"receipt_sha256={hashlib.sha256(args.output.read_bytes()).hexdigest()}")
    print(
        f"runtime_attestation_sha256={hashlib.sha256(runtime_attestation_path.read_bytes()).hexdigest()}"
    )
    print(
        f"public_key={_base64url(private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))}"
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--evidence-dir", type=Path, required=True)
    create.add_argument("--private-key", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument(
        "--pinvi-source-revision", default=os.environ.get("PINVI_SOURCE_REVISION", "")
    )
    create.add_argument("--scope", choices=("staging", "production"), default="production")
    create.add_argument("--pr-url", default=_M05_ACTIVATION_PR_URL)
    create.add_argument("--activation-generation", type=int, required=True)
    create.add_argument("--activation-nonce")
    create.add_argument("--activation-issued-at", type=int)
    create.add_argument("--activation-expires-at", type=int)
    create.add_argument("--review-allowlist", type=Path, required=True)
    create.add_argument("--review-challenge", type=Path, required=True)
    create.add_argument("--reviewer-roster", type=Path)
    create.add_argument(
        "--review-response-nonce",
        default=os.environ.get("PINVI_M05_REVIEW_RESPONSE_NONCE", ""),
    )
    create.add_argument("--require-root-owned", action="store_true")
    create.set_defaults(handler=_create)
    ledger = subparsers.add_parser("ledger")
    ledger.add_argument("--receipt", type=Path, required=True)
    ledger.add_argument("--ledger", type=Path, required=True)
    ledger.add_argument("--high-watermark", type=Path, required=True)
    ledger.add_argument("--durable-floor", type=Path, required=True)
    ledger.add_argument("--durable-history", type=Path, required=True)
    ledger.add_argument("--durable-anchor", type=Path, required=True)
    ledger.add_argument("--public-key", default=os.environ.get("PINVI_M05_ACTIVATION_RECEIPT_PUBLIC_KEY", ""))
    ledger.add_argument("--evidence-dir", type=Path, required=True)
    ledger.add_argument("--pr-url", default=_M05_ACTIVATION_PR_URL)
    ledger.add_argument("--review-allowlist", type=Path, required=True)
    ledger.add_argument("--review-challenge", type=Path, required=True)
    ledger.add_argument("--reviewer-roster", type=Path)
    ledger.add_argument(
        "--review-response-nonce",
        default=os.environ.get("PINVI_M05_REVIEW_RESPONSE_NONCE", ""),
    )
    ledger.add_argument(
        "--durable-anchor-database-url",
        default=os.environ.get("PINVI_M05_ACTIVATION_ANCHOR_DATABASE_URL", ""),
    )
    ledger.add_argument("--require-root-owned", action="store_true")
    ledger.set_defaults(handler=_ledger)
    return parser


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Accept a URL-safe public key even when its first byte renders as ``-``."""

    values = list(sys.argv[1:] if argv is None else argv)
    normalized: list[str] = []
    index = 0
    while index < len(values):
        value = values[index]
        if (
            value == "--public-key"
            and index + 1 < len(values)
            and values[index + 1].startswith("-")
        ):
            normalized.append(f"--public-key={values[index + 1]}")
            index += 2
            continue
        normalized.append(value)
        index += 1
    return _parser().parse_args(normalized)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        return cast(int, args.handler(args))
    except (OSError, ReceiptError, binascii.Error) as exc:
        raise SystemExit(f"M05 activation receipt failed: {exc}") from None


if __name__ == "__main__":
    raise SystemExit(main())
