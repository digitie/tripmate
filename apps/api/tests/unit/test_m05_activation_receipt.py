"""M05 evidence signer와 production Settings 서명 검증의 왕복 계약."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core import config as config_module
from app.core.config import (
    KOR_TRAVEL_MAP_M05_ADMIN_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_M05_ADMIN_RUNTIME_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_M05_ADMIN_SOURCE_CANONICAL_SHA256,
    KOR_TRAVEL_MAP_M05_FULL_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_M05_FULL_RUNTIME_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_M05_FULL_SOURCE_CANONICAL_SHA256,
    KOR_TRAVEL_MAP_M05_SERVICE_RUNTIME_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_M05_SERVICE_SOURCE_CANONICAL_SHA256,
    KOR_TRAVEL_MAP_M05_USER_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_M05_USER_RUNTIME_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_M05_USER_SOURCE_CANONICAL_SHA256,
    KOR_TRAVEL_MAP_SERVICE_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_SERVICE_RELEASE_REVISION,
    Settings,
)

READ = "r" * 32
ACK = "a" * 32
REPO_ROOT = Path(__file__).resolve().parents[4]
PINVI_REVISION = subprocess.run(  # noqa: S603
    ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],  # noqa: S607
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
PINVI_DIGESTS = {
    "api": "sha256:" + "1" * 64,
    "web": "sha256:" + "2" * 64,
    "dagster": "sha256:" + "3" * 64,
}

#: v2 pair 계약은 Map revision과 runtime image digest를 선언하지 않는다
#: (`T-VN-PAIR-V2`). evidence는 Manager가 만드는 문서이므로, 이 테스트도 계약이
#: 아니라 **Manager가 줄 법한 값**으로 픽스처를 만든다.
#: vendored pair 계약. 픽스처의 표면 블록이 여기서 나온다.
_PAIR_CONTRACT = json.loads(
    (REPO_ROOT / "contracts/kor-travel-map-m05-pair-provenance-v1.json").read_text(encoding="utf-8")
)
_MAP_REVISION = "1" * 40
_MAP_IMAGE_DIGESTS = {
    "admin": "sha256:" + "1" * 64,
    "api": "sha256:" + "2" * 64,
    "frontend": "sha256:" + "3" * 64,
}


def _map_pair_evidence() -> dict[str, object]:
    """attestation이 만드는 map-pair evidence 한 벌.

    네 표면 블록은 **vendored 계약에서 그대로** 가져온다 — 실제 생산자가 그렇게
    한다(`m05_activation_attestation.py`). 그래서 계약이 v1이든 v2든 이 픽스처는
    자동으로 그 모양을 따르고, 손으로 적은 모양이 결함을 가리는 일이 없다.
    """
    return {
        "admin_image_digest": _MAP_IMAGE_DIGESTS["admin"],
        "api_image_digest": _MAP_IMAGE_DIGESTS["api"],
        "frontend_image_digest": _MAP_IMAGE_DIGESTS["frontend"],
        # 네 표면 블록은 attestation이 **계약을 그대로 복사한 것**이다. 손으로
        # 다시 적으면 실제 생산자가 낼 수 없는 문서를 만들게 되고, 실제로 그렇게
        # 만든 픽스처가 v2 스키마 결함을 통째로 가리고 있었다(적대 리뷰).
        **{
            name: dict(_PAIR_CONTRACT["map"][name]) for name in ("admin", "full", "service", "user")
        },
        "runtime": {
            "admin_openapi": {
                "canonical_sha256": KOR_TRAVEL_MAP_M05_ADMIN_SOURCE_CANONICAL_SHA256,
                "source_canonical_sha256": KOR_TRAVEL_MAP_M05_ADMIN_SOURCE_CANONICAL_SHA256,
                "source_revision": _MAP_REVISION,
                "source_sha256": KOR_TRAVEL_MAP_M05_ADMIN_OPENAPI_SHA256,
                "surface_coverage_sha256": KOR_TRAVEL_MAP_M05_ADMIN_RUNTIME_OPERATION_CONTRACT_SHA256,
                "transport": "http",
                "transport_sha256": "a" * 64,
            },
            "api": {
                "container_id": "b" * 64,
                "digest": _MAP_IMAGE_DIGESTS["api"],
                "environment": "staging",
                "image_id": _MAP_IMAGE_DIGESTS["api"],
                "compose_project": "map-m05",
                "compose_service": "api",
                "revision_label": _MAP_REVISION,
                "source_revision": _MAP_REVISION,
                "started_at": "2026-08-23T00:00:00.000000000Z",
            },
            "admin": {
                "container_id": "a" * 64,
                "digest": _MAP_IMAGE_DIGESTS["admin"],
                "environment": "staging",
                "image_id": _MAP_IMAGE_DIGESTS["admin"],
                "compose_project": "map-m05",
                "compose_service": "admin",
                "revision_label": _MAP_REVISION,
                "source_revision": _MAP_REVISION,
                "started_at": "2026-08-23T00:00:00.000000000Z",
            },
            "frontend": {
                "container_id": "c" * 64,
                "digest": _MAP_IMAGE_DIGESTS["frontend"],
                "environment": "staging",
                "image_id": _MAP_IMAGE_DIGESTS["frontend"],
                "compose_project": "map-m05",
                "compose_service": "frontend",
                "revision_label": _MAP_REVISION,
                "source_revision": _MAP_REVISION,
                "started_at": "2026-08-23T00:00:00.000000000Z",
            },
            "full_openapi_sha256": KOR_TRAVEL_MAP_M05_FULL_OPENAPI_SHA256,
            "full_openapi": {
                "canonical_sha256": KOR_TRAVEL_MAP_M05_ADMIN_SOURCE_CANONICAL_SHA256,
                "source_canonical_sha256": KOR_TRAVEL_MAP_M05_FULL_SOURCE_CANONICAL_SHA256,
                "source_revision": _MAP_REVISION,
                "source_sha256": KOR_TRAVEL_MAP_M05_FULL_OPENAPI_SHA256,
                "surface_coverage_sha256": KOR_TRAVEL_MAP_M05_FULL_RUNTIME_OPERATION_CONTRACT_SHA256,
                "transport": "http",
                "transport_sha256": "a" * 64,
            },
            "service_openapi": {
                "canonical_sha256": KOR_TRAVEL_MAP_M05_SERVICE_SOURCE_CANONICAL_SHA256,
                "source_canonical_sha256": KOR_TRAVEL_MAP_M05_SERVICE_SOURCE_CANONICAL_SHA256,
                "source_revision": KOR_TRAVEL_MAP_SERVICE_RELEASE_REVISION,
                "source_sha256": KOR_TRAVEL_MAP_SERVICE_OPENAPI_SHA256,
                "surface_coverage_sha256": KOR_TRAVEL_MAP_M05_SERVICE_RUNTIME_OPERATION_CONTRACT_SHA256,
                "transport": "source-artifact",
                "transport_sha256": "b" * 64,
            },
            "user_openapi": {
                "canonical_sha256": KOR_TRAVEL_MAP_M05_USER_SOURCE_CANONICAL_SHA256,
                "source_canonical_sha256": KOR_TRAVEL_MAP_M05_USER_SOURCE_CANONICAL_SHA256,
                "source_revision": _MAP_REVISION,
                "source_sha256": KOR_TRAVEL_MAP_M05_USER_OPENAPI_SHA256,
                "surface_coverage_sha256": KOR_TRAVEL_MAP_M05_USER_RUNTIME_OPERATION_CONTRACT_SHA256,
                "transport": "source-artifact",
                "transport_sha256": "d" * 64,
            },
        },
    }


def _test_trust_anchor_sha256(private_key: Ed25519PrivateKey) -> str:
    return hashlib.sha256(private_key.public_key().public_bytes_raw()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    path.chmod(0o600)


def _receipt_module() -> ModuleType:
    path = REPO_ROOT / "scripts" / "m05_activation_receipt.py"
    spec = importlib.util.spec_from_file_location("m05_activation_receipt", path)
    if spec is None or spec.loader is None:
        raise AssertionError("activation receipt module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _isolated_live_ui() -> dict[str, object]:
    return {
        "event_id": "11111111-1111-4111-8111-111111111111",
        "event_sha256": "a" * 64,
        "impact_count": 1,
        "isolated_execution_identity_sha256": "b" * 64,
        "isolated_manager_source_revision": "c" * 40,
        "isolated_pinset_sha256": "d" * 64,
        "isolated_runtime_provenance_sha256": "e" * 64,
        "m04_attestation_sha256": "f" * 64,
        "m04_created_at": 1,
        "m04_feature_request_id": "22222222-2222-4222-8222-222222222222",
        "m04_map_feature_uuid": "33333333-3333-4333-8333-333333333333",
        "m04_map_pending_receipt_sha256": "0" * 64,
        "m04_map_provenance_sha256": "1" * 64,
        "m04_map_request_sha256": "2" * 64,
        "m04_pinvi_approval_sha256": "3" * 64,
        "m04_server_side_chain_verified": True,
        "m04_verification_id": "44444444-4444-4444-8444-444444444444",
        "map_ack_sha256": "4" * 64,
        "map_admin_endpoint": "http://127.0.0.1:12701",
        "map_local_receipt_sha256": "5" * 64,
        "map_snapshot_after_sha256": "6" * 64,
        "map_snapshot_before_sha256": "6" * 64,
        "old_feature_id": "feature-old",
        "pinvi_api_endpoint": "http://127.0.0.1:12801",
        "pinvi_detail_sha256": "7" * 64,
        "pinvi_receipt_sha256": "5" * 64,
        "pinvi_snapshot_after_sha256": "8" * 64,
        "pinvi_snapshot_before_sha256": "8" * 64,
        "pinvi_source_revision": PINVI_REVISION,
        "pinvi_web_endpoint": "http://127.0.0.1:12805",
        "playwright_runner_image_id": "sha256:" + "9" * 64,
        "playwright_runner_image_ref": "mcr.microsoft.com/playwright:v1.60.0-noble@sha256:"
        + "a" * 64,
        "replacement_feature_id": "feature-new",
        "runner_exit_code": 0,
        "server_side_ack_verified": True,
        "status": "passed",
        "ui_evidence_sha256": "b" * 64,
        "verification_id": "44444444-4444-4444-8444-444444444444",
    }


def test_isolated_live_ui_requires_the_complete_execution_binding() -> None:
    module = _receipt_module()
    live_ui = _isolated_live_ui()

    parsed = module._live_ui(live_ui, pinvi_source_revision=PINVI_REVISION)
    assert parsed["isolated_execution_identity_sha256"] == "b" * 64
    incomplete = dict(live_ui)
    incomplete.pop("isolated_pinset_sha256")
    with pytest.raises(module.ReceiptError, match="isolated execution binding is incomplete"):
        module._live_ui(incomplete, pinvi_source_revision=PINVI_REVISION)


def _identity_sha256(identity: dict[str, object]) -> str:
    material = json.dumps(identity, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _script_sha256(name: str) -> str:
    return hashlib.sha256((REPO_ROOT / "scripts" / name).read_bytes()).hexdigest()


def _receipt_script_module() -> object:
    script = REPO_ROOT / "scripts" / "m05_activation_receipt.py"
    spec = importlib.util.spec_from_file_location("m05_activation_receipt", script)
    if spec is None or spec.loader is None:
        raise AssertionError("activation receipt script could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_receipt_accepts_digest_only_or_tagged_playwright_image_reference() -> None:
    module = _receipt_script_module()
    for image_ref in (
        "mcr.microsoft.com/playwright@sha256:" + "2" * 64,
        "mcr.microsoft.com/playwright:v1.60.0-noble@sha256:" + "2" * 64,
    ):
        assert module._PLAYWRIGHT_IMAGE_RE.fullmatch(image_ref) is not None


def test_receipt_ledger_parser_accepts_dash_prefixed_urlsafe_public_key() -> None:
    module = _receipt_script_module()
    public_key = base64.urlsafe_b64encode(bytes([0xF8]) + bytes(31)).decode("ascii").rstrip("=")

    args = module._parse_args(  # type: ignore[attr-defined]
        [
            "ledger",
            "--receipt",
            "receipt.json",
            "--ledger",
            "activation-ledger.jsonl",
            "--high-watermark",
            "activation-high-watermark.json",
            "--durable-floor",
            "activation-durable-floor.json",
            "--durable-history",
            "activation-durable-history.jsonl",
            "--durable-anchor",
            "activation-durable-anchor.jsonl",
            "--public-key",
            public_key,
            "--evidence-dir",
            "evidence",
            "--review-allowlist",
            "review-allowlist.json",
            "--review-challenge",
            "review-challenge.json",
        ]
    )

    assert public_key.startswith("-")
    assert args.public_key == public_key


def _tool_sha256(name: str) -> str:
    return hashlib.sha256(_tool_path(name).read_bytes()).hexdigest()


def _tool_path(name: str) -> Path:
    candidates = [
        Path("/usr/local/bin") / name,
        Path("/usr/bin") / name,
        Path("/bin") / name,
        *sorted(Path("/usr/lib/postgresql").glob(f"*/bin/{name}")),
    ]
    for candidate in candidates:
        resolved = candidate.resolve()
        if (
            candidate.is_file()
            and not candidate.is_symlink()
            and resolved.name == name
            and resolved.is_file()
        ):
            return resolved
    raise AssertionError(f"test tool is missing: {name}")


@pytest.fixture
def linux_tmp_path() -> Iterator[Path]:
    with TemporaryDirectory(prefix="pinvi-m05-receipt-", dir="/tmp") as temp_dir:
        yield Path(temp_dir)


def test_m05_signer_seals_checked_evidence_and_settings_accepts_it(
    linux_tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    tmp_path = linux_tmp_path
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(mode=0o700)
    review_challenge_id = "66666666-6666-4666-8666-666666666666"
    review_response_nonce = "A" * 43
    review_response_paths = {
        "01a02ce8-22cf-70b2-92cc-7dc3af16a915": tmp_path / "helmholtz-review.txt",
        "01a02ce8-25b4-79f2-90e0-49a5c2f7cfc2": tmp_path / "ampere-review.txt",
    }
    review_response_hashes: dict[str, str] = {}
    reviewer_private_keys = {
        agent_id: Ed25519PrivateKey.generate() for agent_id in review_response_paths
    }
    review_ids = {
        "01a02ce8-22cf-70b2-92cc-7dc3af16a915": "44444444-4444-4444-8444-444444444444",
        "01a02ce8-25b4-79f2-90e0-49a5c2f7cfc2": "55555555-5555-4555-8555-555555555555",
    }
    reviewer_roster_path = tmp_path / "reviewer-roster.json"
    _write_json(
        reviewer_roster_path,
        {
            "agent_ids": list(review_response_paths),
            "public_keys": {
                agent_id: base64.urlsafe_b64encode(
                    private_key.public_key().public_bytes(
                        serialization.Encoding.Raw,
                        serialization.PublicFormat.Raw,
                    )
                )
                .decode("ascii")
                .rstrip("=")
                for agent_id, private_key in reviewer_private_keys.items()
            },
            "version": 2,
        },
    )
    for agent_id, response_path in review_response_paths.items():
        summary = "GO no P0/P1 findings"
        signature_payload = {
            "agent_id": agent_id,
            "challenge_id": review_challenge_id,
            "commit": PINVI_REVISION,
            "p0_p1": 0,
            "pr_url": "https://github.com/digitie/pinvi/pull/466",
            "review_id": review_ids[agent_id],
            "review_nonce": review_response_nonce,
            "summary": summary,
            "verdict": "GO",
        }
        review_signature = (
            base64.urlsafe_b64encode(
                reviewer_private_keys[agent_id].sign(
                    json.dumps(
                        signature_payload,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                )
            )
            .decode("ascii")
            .rstrip("=")
        )
        response = (
            "verdict: GO\n"
            "p0_p1: 0\n"
            f"review_id: {review_ids[agent_id]}\n"
            f"reviewer_agent_id: {agent_id}\n"
            f"agent_id: {agent_id}\n"
            f"review_nonce: {review_response_nonce}\n"
            f"commit: {PINVI_REVISION}\n"
            f"reviewed_commit: {PINVI_REVISION}\n"
            "pr_url: https://github.com/digitie/pinvi/pull/466\n"
            f"challenge_id: {review_challenge_id}\n"
            f"summary: {summary}\n"
            f"review_signature: {review_signature}\n"
        )
        response_path.write_text(response, encoding="utf-8")
        response_path.chmod(0o600)
        review_response_hashes[agent_id] = hashlib.sha256(response.encode()).hexdigest()
    review_challenge_path = tmp_path / "review-challenge.json"
    _write_json(
        review_challenge_path,
        {
            "agent_ids": list(review_response_paths),
            "challenge_id": review_challenge_id,
            "commit": PINVI_REVISION,
            "pr_url": "https://github.com/digitie/pinvi/pull/466",
            "response_paths": {
                agent_id: str(path) for agent_id, path in review_response_paths.items()
            },
            "response_nonce_sha256": hashlib.sha256(
                review_response_nonce.encode("ascii")
            ).hexdigest(),
            "version": 2,
        },
    )
    _write_json(
        evidence_dir / "reviews.json",
        [
            {
                "agent_id": "01a02ce8-22cf-70b2-92cc-7dc3af16a915",
                "challenge_id": review_challenge_id,
                "commit": PINVI_REVISION,
                "p0_p1": 0,
                "pr_url": "https://github.com/digitie/pinvi/pull/466",
                "review_id": "44444444-4444-4444-8444-444444444444",
                "reviewer_id": "01a02ce8-22cf-70b2-92cc-7dc3af16a915",
                "response_sha256": review_response_hashes["01a02ce8-22cf-70b2-92cc-7dc3af16a915"],
                "summary": "GO: no P0/P1 findings",
                "summary_sha256": hashlib.sha256(b"GO: no P0/P1 findings").hexdigest(),
                "verdict": "GO",
            },
            {
                "agent_id": "01a02ce8-25b4-79f2-90e0-49a5c2f7cfc2",
                "challenge_id": review_challenge_id,
                "commit": PINVI_REVISION,
                "p0_p1": 0,
                "pr_url": "https://github.com/digitie/pinvi/pull/466",
                "review_id": "55555555-5555-4555-8555-555555555555",
                "reviewer_id": "01a02ce8-25b4-79f2-90e0-49a5c2f7cfc2",
                "response_sha256": review_response_hashes["01a02ce8-25b4-79f2-90e0-49a5c2f7cfc2"],
                "summary": "GO: no P0/P1 findings",
                "summary_sha256": hashlib.sha256(b"GO: no P0/P1 findings").hexdigest(),
                "verdict": "GO",
            },
        ],
    )
    review_allowlist_path = tmp_path / "reviews-allowlist.json"
    _write_json(
        review_allowlist_path,
        [
            {
                "agent_id": "01a02ce8-22cf-70b2-92cc-7dc3af16a915",
                "challenge_id": review_challenge_id,
                "commit": PINVI_REVISION,
                "pr_url": "https://github.com/digitie/pinvi/pull/466",
                "response_sha256": review_response_hashes["01a02ce8-22cf-70b2-92cc-7dc3af16a915"],
                "review_id": "44444444-4444-4444-8444-444444444444",
            },
            {
                "agent_id": "01a02ce8-25b4-79f2-90e0-49a5c2f7cfc2",
                "challenge_id": review_challenge_id,
                "commit": PINVI_REVISION,
                "pr_url": "https://github.com/digitie/pinvi/pull/466",
                "response_sha256": review_response_hashes["01a02ce8-25b4-79f2-90e0-49a5c2f7cfc2"],
                "review_id": "55555555-5555-4555-8555-555555555555",
            },
        ],
    )
    m04_created_at = int(time.time())
    ui_run = {
        "assertions": ["status", "action", "old_feature", "replacement_feature", "impact_count"],
        "event_id": "11111111-1111-4111-8111-111111111111",
        "impact_count": 1,
        "old_feature_id": "feature-old",
        "pinvi_api_endpoint": "http://127.0.0.1:12801",
        "pinvi_detail_sha256": "d" * 64,
        "replacement_feature_id": "feature-new",
        "source_revision": PINVI_REVISION,
        "status": "passed",
        "verification_id": "22222222-2222-4222-8222-222222222222",
        "playwright_runner_image_id": "sha256:" + "9" * 64,
        "playwright_runner_image_ref": "mcr.microsoft.com/playwright:v1.60.0-noble@sha256:"
        + "8" * 64,
    }
    _write_json(evidence_dir / "ui-run.json", ui_run)
    ui_run_sha256 = hashlib.sha256((evidence_dir / "ui-run.json").read_bytes()).hexdigest()
    _write_json(
        evidence_dir / "live-ui.json",
        {
            "event_id": "11111111-1111-4111-8111-111111111111",
            "event_sha256": "a" * 64,
            "m04_attestation_sha256": "f" * 64,
            "m04_created_at": m04_created_at,
            "m04_feature_request_id": "33333333-3333-4333-8333-333333333333",
            "m04_map_feature_uuid": "44444444-4444-4444-8444-444444444444",
            "m04_map_pending_receipt_sha256": "2" * 64,
            "m04_map_provenance_sha256": "3" * 64,
            "m04_map_request_sha256": "4" * 64,
            "m04_pinvi_approval_sha256": "5" * 64,
            "m04_server_side_chain_verified": True,
            "m04_verification_id": "22222222-2222-4222-8222-222222222222",
            "map_admin_endpoint": "http://127.0.0.1:12701",
            "map_ack_sha256": "b" * 64,
            "map_local_receipt_sha256": "1" * 64,
            "map_snapshot_after_sha256": "c" * 64,
            "map_snapshot_before_sha256": "c" * 64,
            "pinvi_source_revision": PINVI_REVISION,
            "pinvi_api_endpoint": "http://127.0.0.1:12801",
            "pinvi_web_endpoint": "http://127.0.0.1:12805",
            "pinvi_receipt_sha256": "1" * 64,
            "pinvi_snapshot_after_sha256": "d" * 64,
            "pinvi_snapshot_before_sha256": "d" * 64,
            "old_feature_id": ui_run["old_feature_id"],
            "replacement_feature_id": ui_run["replacement_feature_id"],
            "impact_count": ui_run["impact_count"],
            "pinvi_detail_sha256": ui_run["pinvi_detail_sha256"],
            "runner_exit_code": 0,
            "server_side_ack_verified": True,
            "status": "passed",
            "ui_evidence_sha256": ui_run_sha256,
            "verification_id": "22222222-2222-4222-8222-222222222222",
            "playwright_runner_image_id": "sha256:" + "9" * 64,
            "playwright_runner_image_ref": "mcr.microsoft.com/playwright:v1.60.0-noble@sha256:"
            + "8" * 64,
        },
    )
    source_identity = {
        "database": "source",
        "database_oid": "100",
        "host": "db",
        "hostaddr": "127.0.0.1",
        "port": "5432",
        "schema_exists": True,
        "server_version_num": "160000",
        "sslmode": "prefer",
        "system_identifier": "1",
        "user": "pinvi_owner",
    }
    source_after_backup_identity = source_identity.copy()
    target_before_restore_identity = {
        "database": "pinvi_m05_restore_target",
        "database_oid": "200",
        "host": "db",
        "hostaddr": "127.0.0.1",
        "port": "5432",
        "schema_exists": False,
        "server_version_num": "160000",
        "sslmode": "prefer",
        "system_identifier": "1",
        "user": "pinvi_owner",
    }
    target_identity = {
        "database": "pinvi_m05_restore_target",
        "database_oid": "200",
        "host": "db",
        "hostaddr": "127.0.0.1",
        "port": "5432",
        "schema_exists": True,
        "server_version_num": "160000",
        "sslmode": "prefer",
        "system_identifier": "1",
        "user": "pinvi_app",
    }
    runtime_identity = target_identity.copy()
    fence_before_restore_identity = target_before_restore_identity.copy()
    fence_before_restore_identity["user"] = "pinvi_fence"
    fence_identity = target_identity.copy()
    fence_identity["user"] = "pinvi_fence"
    restore_tool_manifest_path = tmp_path / "restore-tool-trust.json"
    restore_tool_manifest = {
        "tools": {
            name: {
                "path": str(_tool_path(name)),
                "sha256": _tool_sha256(name),
            }
            for name in ("bash", "git", "pg_dump", "pg_restore", "psql")
        },
        "version": 1,
    }
    _write_json(restore_tool_manifest_path, restore_tool_manifest)
    restore_tool_manifest_sha256 = hashlib.sha256(
        restore_tool_manifest_path.read_bytes()
    ).hexdigest()
    monkeypatch.setenv("PINVI_M05_RESTORE_TOOL_TRUST_MANIFEST", str(restore_tool_manifest_path))
    _write_json(
        evidence_dir / "restore.json",
        {
            "backup_runner_sha256": _script_sha256("backup-db.sh"),
            "backup_tool_path": str(_tool_path("pg_dump")),
            "backup_tool_sha256": _tool_sha256("pg_dump"),
            "bash_tool_path": "/usr/bin/bash",
            "bash_tool_sha256": _tool_sha256("bash"),
            "environment": "staging",
            "fresh_target_verified": True,
            "fence_db_identity": fence_identity,
            "fence_db_identity_before_restore": fence_before_restore_identity,
            "fence_db_identity_before_restore_sha256": _identity_sha256(
                fence_before_restore_identity
            ),
            "fence_db_identity_sha256": _identity_sha256(fence_identity),
            "fence_role": "pinvi_fence",
            "fence_role_verified": True,
            "git_tool_path": str(_tool_path("git")),
            "git_tool_sha256": _tool_sha256("git"),
            "psql_tool_path": str(_tool_path("psql")),
            "psql_tool_sha256": _tool_sha256("psql"),
            "dump_sha256": "c" * 64,
            "execution_id": "33333333-3333-4333-8333-333333333333",
            "no_owner_restore": True,
            "provisioner_login_disabled": True,
            "provisioner_role": "pinvi_restore_provisioner",
            "restore_command": (
                "pg_restore --clean --if-exists --exit-on-error --no-owner --no-privileges"
            ),
            "restore_output_sha256": "2" * 64,
            "restore_db_runner_sha256": _script_sha256("restore-db.sh"),
            "hotswap_runner_sha256": _script_sha256("restore-hotswap.sh"),
            "restore_runner_sha256": _script_sha256("restore-staging-drill.sh"),
            "m05_restore_drill_sha256": _script_sha256("m05_restore_drill.py"),
            "restore_tool_path": str(_tool_path("pg_restore")),
            "restore_tool_sha256": _tool_sha256("pg_restore"),
            "tool_trust_manifest_path": str(restore_tool_manifest_path),
            "tool_trust_manifest_sha256": restore_tool_manifest_sha256,
            "runtime_db_identity": runtime_identity,
            "runtime_role": "pinvi_app",
            "runtime_role_verified": True,
            "source_db_identity": source_identity,
            "source_db_identity_after_backup": source_after_backup_identity,
            "source_db_identity_after_backup_sha256": _identity_sha256(
                source_after_backup_identity
            ),
            "source_db_identity_sha256": _identity_sha256(source_identity),
            "source_revision": PINVI_REVISION,
            "staging_role": "pinvi_owner",
            "staging_role_verified": True,
            "status": "passed",
            "target_db_identity": target_identity,
            "target_db_identity_before_restore": target_before_restore_identity,
            "target_db_identity_before_restore_sha256": _identity_sha256(
                target_before_restore_identity
            ),
            "target_db_identity_sha256": _identity_sha256(target_identity),
            "target_recreated": True,
            "trigger_guard_verified": True,
            "runtime_db_identity_sha256": _identity_sha256(runtime_identity),
            "hotswap_success": True,
            "hotswap_success_marker": "RESTORE_PHASE=switching:success:schema-swap completed",
            "hotswap_success_output_sha256": "f" * 64,
            "hotswap_schema_oid_before": "300",
            "hotswap_schema_oid_after": "400",
            "hotswap_previous_schema_oid": "300",
            "hotswap_previous_schema_present": True,
            "hotswap_restore_schema_absent": True,
            "hotswap_advisory_lock_released": True,
            "hotswap_fence_restored": True,
            "hotswap_executor_reconnect_fenced": True,
        },
    )
    _write_json(
        evidence_dir / "map-pair.json",
        _map_pair_evidence(),
    )
    _write_json(
        evidence_dir / "pinvi-images.json",
        {
            name: {
                "container_id": "d" * 64,
                "digest": digest,
                "environment": "staging",
                "image_id": digest,
                "compose_project": "pinvi-m05",
                "compose_service": {
                    "api": "app-api",
                    "web": "app-web",
                    "dagster": "app-dagster",
                }[name],
                "revision_label": PINVI_REVISION,
                "source_revision": PINVI_REVISION,
                "started_at": "2026-08-23T00:00:00.000000000Z",
            }
            for name, digest in PINVI_DIGESTS.items()
        },
    )

    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(
        config_module,
        "PINVI_M05_ACTIVATION_RECEIPT_PUBLIC_KEY_SHA256",
        _test_trust_anchor_sha256(private_key),
    )
    private_key_path = tmp_path / "activation-key.pem"
    private_key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_key_path.chmod(0o600)

    evidence_hashes = {
        name: hashlib.sha256((evidence_dir / f"{name}.json").read_bytes()).hexdigest()
        for name in ("ui-run", "live-ui", "map-pair", "pinvi-images", "restore", "reviews")
    }
    attestation_payload = {
        "created_at": int(time.time()),
        "event_id": "11111111-1111-4111-8111-111111111111",
        "evidence_sha256": evidence_hashes,
        "map_ack_sha256": "b" * 64,
        "m04_attestation_sha256": "f" * 64,
        "m04_created_at": m04_created_at,
        "m04_feature_request_id": "33333333-3333-4333-8333-333333333333",
        "m04_map_feature_uuid": "44444444-4444-4444-8444-444444444444",
        "m04_map_pending_receipt_sha256": "2" * 64,
        "m04_map_provenance_sha256": "3" * 64,
        "m04_map_request_sha256": "4" * 64,
        "m04_pinvi_approval_sha256": "5" * 64,
        "m04_server_side_chain_verified": True,
        "m04_verification_id": "22222222-2222-4222-8222-222222222222",
        "local_receipt_sha256": "1" * 64,
        "map_admin_endpoint": "http://127.0.0.1:12701",
        "map_snapshot_sha256": "c" * 64,
        "old_feature_id": ui_run["old_feature_id"],
        "replacement_feature_id": ui_run["replacement_feature_id"],
        "impact_count": ui_run["impact_count"],
        "pinvi_detail_sha256": ui_run["pinvi_detail_sha256"],
        "pinvi_snapshot_sha256": "d" * 64,
        "pinvi_api_endpoint": "http://127.0.0.1:12801",
        "pinvi_web_endpoint": "http://127.0.0.1:12805",
        "pinvi_source_revision": PINVI_REVISION,
        "playwright_runner_image_id": "sha256:" + "9" * 64,
        "playwright_runner_image_ref": "mcr.microsoft.com/playwright:v1.60.0-noble@sha256:"
        + "8" * 64,
        "scope": "staging",
        "status": "passed",
        "verification_id": "22222222-2222-4222-8222-222222222222",
        "version": 3,
    }
    attestation_bytes = json.dumps(
        attestation_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    _write_json(
        evidence_dir / "attestation.json",
        {
            "payload": attestation_payload,
            "signature": base64.urlsafe_b64encode(private_key.sign(attestation_bytes))
            .decode("ascii")
            .rstrip("="),
        },
    )
    receipt_path = tmp_path / "activation-receipt.json"
    script = Path(__file__).resolve().parents[4] / "scripts/m05_activation_receipt.py"
    completed = subprocess.run(  # noqa: S603 - invokes the repository-pinned Python test helper
        [
            sys.executable,
            str(script),
            "create",
            "--evidence-dir",
            str(evidence_dir),
            "--private-key",
            str(private_key_path),
            "--output",
            str(receipt_path),
            "--scope",
            "staging",
            "--pinvi-source-revision",
            PINVI_REVISION,
            "--activation-generation",
            "2",
            "--review-allowlist",
            str(review_allowlist_path),
            "--review-challenge",
            str(review_challenge_path),
            "--review-response-nonce",
            review_response_nonce,
            "--reviewer-roster",
            str(reviewer_roster_path),
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PINVI_M05_RECEIPT_TEST_MODE": "1"},
    )
    public_key = next(
        line.removeprefix("public_key=")
        for line in completed.stdout.splitlines()
        if line.startswith("public_key=")
    )
    receipt = receipt_path.read_text(encoding="utf-8")
    ledger_path = tmp_path / "activation-ledger.jsonl"
    high_watermark_path = tmp_path / "activation-high-watermark.json"
    durable_floor_path = tmp_path / "activation-durable-floor.json"
    durable_history_path = tmp_path / "activation-durable-history.jsonl"
    anchor_dir = tmp_path / "anchor"
    anchor_dir.mkdir(mode=0o700)
    durable_anchor_path = anchor_dir / "activation-durable-anchor.jsonl"
    ledger_completed = subprocess.run(  # noqa: S603 - invokes the repository-pinned Python test helper
        [
            sys.executable,
            str(script),
            "ledger",
            "--receipt",
            str(receipt_path),
            "--ledger",
            str(ledger_path),
            "--high-watermark",
            str(high_watermark_path),
            "--durable-floor",
            str(durable_floor_path),
            "--durable-history",
            str(durable_history_path),
            "--durable-anchor",
            str(durable_anchor_path),
            f"--public-key={public_key}",
            "--evidence-dir",
            str(evidence_dir),
            "--review-allowlist",
            str(review_allowlist_path),
            "--review-challenge",
            str(review_challenge_path),
            "--review-response-nonce",
            review_response_nonce,
            "--reviewer-roster",
            str(reviewer_roster_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PINVI_M05_RECEIPT_TEST_MODE": "1"},
    )
    assert ledger_completed.returncode == 0, ledger_completed.stderr
    tampered_ui_run = dict(ui_run)
    tampered_ui_run["impact_count"] = 2
    _write_json(evidence_dir / "ui-run.json", tampered_ui_run)
    tampered_ledger = subprocess.run(  # noqa: S603 - reuses the pinned ledger command
        ledger_completed.args,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PINVI_M05_RECEIPT_TEST_MODE": "1"},
    )
    assert tampered_ledger.returncode != 0
    monkeypatch.setenv("PINVI_SOURCE_REVISION", PINVI_REVISION)
    high_watermark = json.loads(high_watermark_path.read_text(encoding="utf-8"))
    assert high_watermark == {
        "generation": 2,
        "receipt_sha256": hashlib.sha256(receipt.encode("utf-8")).hexdigest(),
    }
    assert json.loads(durable_floor_path.read_text(encoding="utf-8")) == {"generation": 2}
    assert len(durable_history_path.read_text(encoding="utf-8").splitlines()) == 1
    assert len(durable_anchor_path.read_text(encoding="utf-8").splitlines()) == 1
    monkeypatch.setattr(config_module, "_runtime_container_id", lambda: "d" * 64)
    monkeypatch.setattr(
        config_module,
        "_validate_m05_runtime_dependencies_live",
        lambda **_: None,
    )
    runtime_attestation_path = evidence_dir / "runtime-attestation.json"
    runtime_payload = json.loads(runtime_attestation_path.read_text(encoding="utf-8"))["payload"]
    receipt_payload = json.loads(receipt)["payload"]
    assert isinstance(runtime_payload, dict)
    assert isinstance(receipt_payload, dict)
    lease_directory = tmp_path / "runtime-lease"
    lease_directory.mkdir(mode=0o700)
    lease_private_key = Ed25519PrivateKey.generate()
    lease_public_key = lease_private_key.public_key().public_bytes_raw()
    lease_key_id = hashlib.sha256(lease_public_key).hexdigest()
    _write_json(
        lease_directory / "trust.json",
        {
            "key_id": lease_key_id,
            "public_key": base64.urlsafe_b64encode(lease_public_key).decode("ascii").rstrip("="),
            "version": 1,
        },
    )
    lease_payload = {
        "activation_generation": receipt_payload["activation_generation"],
        "activation_nonce": receipt_payload["activation_nonce"],
        "dependency_snapshot_sha256": hashlib.sha256(
            json.dumps(
                runtime_payload["dependencies"],
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest(),
        "expires_at": int(time.time()) + 60,
        "issued_at": int(time.time()) - 1,
        "key_id": lease_key_id,
        "receipt_sha256": hashlib.sha256(receipt.encode("utf-8")).hexdigest(),
        "runtime_attestation_sha256": hashlib.sha256(
            runtime_attestation_path.read_bytes()
        ).hexdigest(),
        "scope": "staging",
        "sequence": 1,
        "version": 1,
    }
    lease_material = json.dumps(
        lease_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    _write_json(
        lease_directory / "current.json",
        {
            "payload": lease_payload,
            "signature": base64.urlsafe_b64encode(lease_private_key.sign(lease_material))
            .decode("ascii")
            .rstrip("="),
        },
    )
    loaded = Settings(
        _env_file=None,
        pinvi_environment="staging",
        pinvi_kor_travel_map_api_base_url="http://127.0.0.1:12701",
        pinvi_kor_travel_map_admin_base_url="http://127.0.0.1:12701",
        pinvi_kor_travel_map_ops_read_token="o" * 32,
        pinvi_kor_travel_map_ops_cancel_token="p" * 32,
        pinvi_kor_travel_map_feature_reference_reconciliation_enabled=True,
        pinvi_kor_travel_map_feature_reference_reconciliation_read_token=READ,
        pinvi_kor_travel_map_feature_reference_reconciliation_ack_token=ACK,
        pinvi_kor_travel_map_feature_reference_reconciliation_expected_openapi_sha256=(
            KOR_TRAVEL_MAP_SERVICE_OPENAPI_SHA256
        ),
        pinvi_kor_travel_map_feature_reference_reconciliation_expected_source_revision=(
            KOR_TRAVEL_MAP_SERVICE_RELEASE_REVISION
        ),
        pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt=receipt,
        pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt_public_key=public_key,
        pinvi_m05_runtime_attestation_path=str(runtime_attestation_path),
        pinvi_m05_runtime_lease_directory=str(lease_directory),
        pinvi_m05_activation_ledger_path=str(ledger_path),
        pinvi_m05_activation_high_watermark_path=str(high_watermark_path),
        pinvi_m05_activation_durable_floor_path=str(durable_floor_path),
        pinvi_m05_activation_durable_history_path=str(durable_history_path),
        pinvi_m05_activation_durable_anchor_path=str(durable_anchor_path),
        pinvi_m05_activation_pr_url="https://github.com/digitie/pinvi/pull/466",
        pinvi_api_image_digest=PINVI_DIGESTS["api"],
        pinvi_web_image_digest=PINVI_DIGESTS["web"],
        pinvi_dagster_image_digest=PINVI_DIGESTS["dagster"],
    )
    assert loaded.pinvi_kor_travel_map_feature_reference_reconciliation_enabled is True

    receipt_module = _receipt_script_module()
    restore_evidence = json.loads((evidence_dir / "restore.json").read_text(encoding="utf-8"))
    receipt_module._restore(  # type: ignore[attr-defined]
        restore_evidence,
        pinvi_source_revision=PINVI_REVISION,
        environment="staging",
        require_root_owned=False,
    )
    missing_fence = json.loads(json.dumps(restore_evidence))
    del missing_fence["fence_role"]
    with pytest.raises(receipt_module.ReceiptError, match="schema/status"):  # type: ignore[attr-defined]
        receipt_module._restore(  # type: ignore[attr-defined]
            missing_fence,
            pinvi_source_revision=PINVI_REVISION,
            environment="staging",
            require_root_owned=False,
        )
    mismatched_fence = json.loads(json.dumps(restore_evidence))
    mismatched_fence["fence_db_identity"]["hostaddr"] = "127.0.0.2"
    mismatched_fence["fence_db_identity_sha256"] = _identity_sha256(
        mismatched_fence["fence_db_identity"]
    )
    with pytest.raises(receipt_module.ReceiptError, match="target fence endpoint identity"):  # type: ignore[attr-defined]
        receipt_module._restore(  # type: ignore[attr-defined]
            mismatched_fence,
            pinvi_source_revision=PINVI_REVISION,
            environment="staging",
            require_root_owned=False,
        )


def test_map_pair_keeps_binding_revisions_and_digests_without_the_contract_copy() -> None:
    """v2 계약이 사본을 걷어낸 자리에 evidence 내부 결박이 남아 있는가.

    v1 계약은 Map revision과 runtime image digest를 **스스로 한 벌 더** 선언했고,
    수신자는 그 사본과 대조했다. v2는 그 선언을 없앤다(`T-VN-PAIR-V2`,
    `AGENTS.md` DO NOT 15) — 없어지는 것은 세 번째 선언이지 검증이 아니어야 한다.
    아래 변조는 계약이 아무 말도 하지 않는 v2에서도 전부 빨간불이어야 하고,
    변조하지 않은 evidence는 통과해야 한다(게이트가 공허하지 않다는 증거).
    """
    module = _receipt_module()
    expected = module._pair_provenance()
    assert "runtime_image_digests" in expected
    assert expected["runtime_image_digests"] == {}, "v2 계약은 image digest를 선언하지 않는다"
    assert "source_revision" not in expected["admin"], "v2 계약은 revision을 선언하지 않는다"

    # 픽스처의 표면 블록은 **생산자와 같은 방식**으로 만들어져야 한다. 손으로 적으면
    # 실제로 존재할 수 없는 문서가 되고, 그 문서가 v2 스키마 결함을 가렸다.
    baseline = _map_pair_evidence()
    for name in ("admin", "full", "service", "user"):
        assert baseline[name] == _PAIR_CONTRACT["map"][name]

    module._map_pair(baseline, expected, environment="staging")

    other_revision = "2" * 40
    other_digest = "sha256:" + "4" * 64

    def _runtime_artifact_revision(evidence: dict[str, object]) -> None:
        evidence["runtime"]["admin_openapi"]["source_revision"] = other_revision

    def _runtime_image_revision(evidence: dict[str, object]) -> None:
        evidence["runtime"]["api"]["revision_label"] = other_revision
        evidence["runtime"]["api"]["source_revision"] = other_revision

    def _pair_image_digest(evidence: dict[str, object]) -> None:
        evidence["admin_image_digest"] = other_digest

    def _runtime_image_digest(evidence: dict[str, object]) -> None:
        evidence["runtime"]["api"]["digest"] = other_digest
        evidence["runtime"]["api"]["image_id"] = other_digest

    def _surface_entry_shape(evidence: dict[str, object]) -> None:
        # v2 계약에는 없는 키다. evidence가 계약의 사본인 이상 이 모양은 생길 수
        # 없고, 스키마를 리터럴로 적어 두면 반대로 **정상 모양**이 거부된다.
        evidence["admin"] = {**evidence["admin"], "source_revision": _MAP_REVISION}

    def _surface_entry_digest(evidence: dict[str, object]) -> None:
        # evidence의 표면 블록이 계약과 한 필드라도 다르면 거부돼야 한다.
        evidence["admin"] = {**evidence["admin"], "openapi_sha256": "3" * 64}

    def _service_surface_revision(evidence: dict[str, object]) -> None:
        # service 표면의 revision을 pinned Map revision으로 채우는 실수 —
        # 적대 리뷰 P0이 지목한 바로 그것이다.
        evidence["runtime"]["service_openapi"]["source_revision"] = _MAP_REVISION

    for label, mutate in (
        ("runtime OpenAPI artifact revision", _runtime_artifact_revision),
        ("runtime image revision", _runtime_image_revision),
        ("pair image digest", _pair_image_digest),
        ("runtime image digest", _runtime_image_digest),
        ("surface entry shape", _surface_entry_shape),
        ("surface entry digest", _surface_entry_digest),
        ("service surface revision", _service_surface_revision),
    ):
        evidence = _map_pair_evidence()
        mutate(evidence)
        try:
            module._map_pair(evidence, expected, environment="staging")
        except module.ReceiptError:
            continue
        pytest.fail(f"{label} 변조가 통과했다 — evidence 내부 결박이 사라졌다")
