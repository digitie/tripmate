"""M05 paired consumer의 default-off credential/pin config gate."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from app.core import config as config_module
from app.core.config import (
    KOR_TRAVEL_MAP_M05_ADMIN_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_M05_ADMIN_RUNTIME_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_M05_ADMIN_SOURCE_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_M05_FULL_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_M05_FULL_RUNTIME_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_M05_FULL_SOURCE_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_M05_SERVICE_RUNTIME_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_M05_SERVICE_SOURCE_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_M05_USER_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_M05_USER_RUNTIME_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_M05_USER_SOURCE_OPERATION_CONTRACT_SHA256,
    KOR_TRAVEL_MAP_SERVICE_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_SERVICE_RELEASE_REVISION,
    Settings,
)

READ = "r" * 32
ACK = "a" * 32
PINVI_REVISION = "f" * 40
PUBLIC_KEY_PRIVATE = Ed25519PrivateKey.from_private_bytes(b"m05-ed25519-private-key-32bytes!")
LEASE_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = (
    base64.urlsafe_b64encode(PUBLIC_KEY_PRIVATE.public_key().public_bytes_raw())
    .decode("ascii")
    .rstrip("=")
)
TEST_TRUST_ANCHOR_SHA256 = hashlib.sha256(
    PUBLIC_KEY_PRIVATE.public_key().public_bytes_raw()
).hexdigest()
IMAGE_DIGESTS = {
    "pinvi_api_image_digest": "sha256:" + "1" * 64,
    "pinvi_web_image_digest": "sha256:" + "2" * 64,
    "pinvi_dagster_image_digest": "sha256:" + "3" * 64,
}


@pytest.fixture(autouse=True)
def _use_test_activation_trust_anchor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        config_module,
        "PINVI_M05_ACTIVATION_RECEIPT_PUBLIC_KEY_SHA256",
        TEST_TRUST_ANCHOR_SHA256,
    )
    monkeypatch.setattr(config_module, "_runtime_container_id", lambda: "d" * 64)
    monkeypatch.setattr(
        config_module,
        "_validate_m05_runtime_dependencies_live",
        lambda **_kwargs: None,
    )


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, pinvi_environment="test", **overrides)  # type: ignore[arg-type]


def _production_settings(**overrides: object) -> Settings:
    receipt = overrides.get(
        "pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt"
    )
    receipt_path_value = overrides.get(
        "pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt_path"
    )
    if receipt is None and isinstance(receipt_path_value, str) and receipt_path_value:
        receipt = Path(receipt_path_value).read_text(encoding="utf-8")
    if isinstance(receipt, str) and receipt.startswith("{"):
        try:
            payload = json.loads(receipt)["payload"]
        except (KeyError, TypeError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict):
            ledger_dir = tempfile.TemporaryDirectory(prefix="pinvi-m05-ledger-", dir="/tmp")
            ledger_path = Path(ledger_dir.name) / "activation-ledger.jsonl"
            runtime_attestation_path = _write_runtime_attestation(
                Path(ledger_dir.name), receipt, payload
            )
            overrides["pinvi_m05_runtime_attestation_path"] = str(runtime_attestation_path)
            lease_directory = Path(ledger_dir.name) / "runtime-lease"
            _write_runtime_lease(
                lease_directory,
                receipt=receipt,
                runtime_attestation_path=runtime_attestation_path,
                payload=payload,
            )
            overrides["pinvi_m05_runtime_lease_directory"] = str(lease_directory)
            record = {
                "activation_expires_at": payload["activation_expires_at"],
                "activation_generation": payload["activation_generation"],
                "activation_issued_at": payload["activation_issued_at"],
                "activation_nonce": payload["activation_nonce"],
                "previous_record_sha256": "0" * 64,
                "receipt_sha256": hashlib.sha256(receipt.encode()).hexdigest(),
                "scope": payload["scope"],
                "source_revision": payload["pinvi_source_revision"],
            }
            record["record_sha256"] = hashlib.sha256(
                json.dumps(
                    record, ensure_ascii=False, separators=(",", ":"), sort_keys=True
                ).encode("utf-8")
            ).hexdigest()
            ledger_path.write_text(
                json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8"
            )
            ledger_path.chmod(0o600)
            high_watermark_path = Path(ledger_dir.name) / "activation-high-watermark.json"
            high_watermark_path.write_text(
                json.dumps(
                    {
                        "generation": payload["activation_generation"],
                        "receipt_sha256": hashlib.sha256(receipt.encode()).hexdigest(),
                    },
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            high_watermark_path.chmod(0o600)
            durable_floor_path = Path(ledger_dir.name) / "activation-durable-floor.json"
            durable_floor_path.write_text(
                json.dumps({"generation": payload["activation_generation"]}),
                encoding="utf-8",
            )
            durable_floor_path.chmod(0o600)
            durable_history_path = Path(ledger_dir.name) / "activation-durable-history.jsonl"
            durable_history = {
                "generation": payload["activation_generation"],
                "previous_record_sha256": "0" * 64,
                "receipt_sha256": hashlib.sha256(receipt.encode()).hexdigest(),
            }
            durable_history["record_sha256"] = hashlib.sha256(
                json.dumps(
                    durable_history,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
            durable_history_path.write_text(
                json.dumps(durable_history, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            durable_history_path.chmod(0o600)
            anchor_dir = Path(ledger_dir.name) / "anchor"
            anchor_dir.mkdir(mode=0o700)
            durable_anchor_path = anchor_dir / "activation-durable-anchor.jsonl"
            durable_anchor_path.write_text(
                json.dumps(durable_history, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            durable_anchor_path.chmod(0o600)
            overrides["pinvi_m05_activation_ledger_path"] = str(ledger_path)
            overrides["pinvi_m05_activation_high_watermark_path"] = str(high_watermark_path)
            overrides["pinvi_m05_activation_durable_floor_path"] = str(durable_floor_path)
            overrides["pinvi_m05_activation_durable_history_path"] = str(durable_history_path)
            overrides["pinvi_m05_activation_durable_anchor_path"] = str(durable_anchor_path)
            loaded = Settings(_env_file=None, pinvi_environment="production", **overrides)  # type: ignore[arg-type]
            ledger_dir.cleanup()
            return loaded
    return Settings(_env_file=None, pinvi_environment="production", **overrides)  # type: ignore[arg-type]


#: v2 pair 계약은 Map revision과 runtime image digest를 선언하지 않는다
#: (`T-VN-PAIR-V2`). 그 값의 생산자는 pin registry이고, PinVi에는 **서명된 receipt**가
#: 실어 온다 — 그래서 이 테스트도 계약이 아니라 receipt 쪽 값으로 payload를 만든다.
_MAP_REVISION = "1" * 40
_MAP_IMAGE_DIGESTS = {
    "admin": "sha256:" + "1" * 64,
    "api": "sha256:" + "2" * 64,
    "frontend": "sha256:" + "3" * 64,
}


def _receipt_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "activation_expires_at": int(time.time()) + 3600,
        "activation_generation": 2,
        "activation_issued_at": int(time.time()) - 60,
        "activation_nonce": "22222222-2222-4222-8222-222222222222",
        "activation_attestation_sha256": "0" * 64,
        "adversarial_reviews": [
            {
                "agent_id": "01a02ce8-22cf-70b2-92cc-7dc3af16a915",
                "commit": PINVI_REVISION,
                "challenge_id": "33333333-3333-4333-8333-333333333333",
                "p0_p1": 0,
                "pr_url": "https://github.com/digitie/pinvi/pull/466",
                "review_id": "44444444-4444-4444-8444-444444444444",
                "reviewer_id": "01a02ce8-22cf-70b2-92cc-7dc3af16a915",
                "response_sha256": "1" * 64,
                "summary": "GO: no P0/P1 findings",
                "summary_sha256": hashlib.sha256(b"GO: no P0/P1 findings").hexdigest(),
                "verdict": "GO",
            },
            {
                "agent_id": "01a02ce8-25b4-79f2-90e0-49a5c2f7cfc2",
                "commit": PINVI_REVISION,
                "challenge_id": "33333333-3333-4333-8333-333333333333",
                "p0_p1": 0,
                "pr_url": "https://github.com/digitie/pinvi/pull/466",
                "review_id": "55555555-5555-4555-8555-555555555555",
                "reviewer_id": "01a02ce8-25b4-79f2-90e0-49a5c2f7cfc2",
                "response_sha256": "2" * 64,
                "summary": "GO: no P0/P1 findings",
                "summary_sha256": hashlib.sha256(b"GO: no P0/P1 findings").hexdigest(),
                "verdict": "GO",
            },
        ],
        "live_ui_e2e": "passed",
        "live_ui_event_id": "11111111-1111-4111-8111-111111111111",
        "live_ui_evidence_sha256": "a" * 64,
        "ui_run_evidence_sha256": "9" * 64,
        "live_ui_map_admin_endpoint": "http://127.0.0.1:12701",
        "live_ui_map_ack_sha256": "b" * 64,
        "live_ui_local_receipt_sha256": "1" * 64,
        "live_ui_map_snapshot_sha256": "c" * 64,
        "live_ui_pinvi_api_endpoint": "http://127.0.0.1:12801",
        "live_ui_pinvi_snapshot_sha256": "d" * 64,
        "live_ui_pinvi_web_endpoint": "http://127.0.0.1:12805",
        "live_ui_playwright_runner_image_id": "sha256:" + "8" * 64,
        "live_ui_playwright_runner_image_ref": "mcr.microsoft.com/playwright:v1.60.0-noble@sha256:"
        + "7" * 64,
        "live_ui_verification_id": "22222222-2222-4222-8222-222222222222",
        "m04_attestation_sha256": "1" * 64,
        "m04_created_at": int(time.time()) - 90,
        "m04_feature_request_id": "33333333-3333-4333-8333-333333333333",
        "m04_map_feature_uuid": "44444444-4444-4444-8444-444444444444",
        "m04_map_pending_receipt_sha256": "2" * 64,
        "m04_map_provenance_sha256": "3" * 64,
        "m04_map_request_sha256": "4" * 64,
        "m04_pinvi_approval_sha256": "5" * 64,
        "m04_verification_id": "22222222-2222-4222-8222-222222222222",
        "m05_old_feature_id": "feature-old",
        "m05_replacement_feature_id": "feature-new",
        "m05_impact_count": 1,
        "m05_pinvi_detail_sha256": "6" * 64,
        "map_admin_openapi_sha256": KOR_TRAVEL_MAP_M05_ADMIN_OPENAPI_SHA256,
        "map_admin_runtime_openapi_sha256": "9" * 64,
        "map_admin_runtime_operation_contract_sha256": KOR_TRAVEL_MAP_M05_ADMIN_RUNTIME_OPERATION_CONTRACT_SHA256,
        "map_admin_source_operation_contract_sha256": KOR_TRAVEL_MAP_M05_ADMIN_SOURCE_OPERATION_CONTRACT_SHA256,
        "map_admin_source_revision": _MAP_REVISION,
        "map_admin_image_digest": _MAP_IMAGE_DIGESTS["admin"],
        "map_admin_container_id": "a" * 64,
        "map_api_image_digest": _MAP_IMAGE_DIGESTS["api"],
        "map_api_container_id": "b" * 64,
        "map_frontend_image_digest": _MAP_IMAGE_DIGESTS["frontend"],
        "map_frontend_container_id": "c" * 64,
        "map_full_openapi_sha256": KOR_TRAVEL_MAP_M05_FULL_OPENAPI_SHA256,
        "map_full_runtime_openapi_sha256": "8" * 64,
        "map_full_runtime_operation_contract_sha256": KOR_TRAVEL_MAP_M05_FULL_RUNTIME_OPERATION_CONTRACT_SHA256,
        "map_full_source_operation_contract_sha256": KOR_TRAVEL_MAP_M05_FULL_SOURCE_OPERATION_CONTRACT_SHA256,
        "map_full_source_revision": _MAP_REVISION,
        "map_pair_evidence_sha256": "c" * 64,
        "map_service_openapi_sha256": KOR_TRAVEL_MAP_SERVICE_OPENAPI_SHA256,
        "map_service_runtime_openapi_sha256": "a" * 64,
        "map_service_runtime_operation_contract_sha256": KOR_TRAVEL_MAP_M05_SERVICE_RUNTIME_OPERATION_CONTRACT_SHA256,
        "map_service_source_operation_contract_sha256": KOR_TRAVEL_MAP_M05_SERVICE_SOURCE_OPERATION_CONTRACT_SHA256,
        "map_service_source_revision": KOR_TRAVEL_MAP_SERVICE_RELEASE_REVISION,
        "map_user_openapi_sha256": KOR_TRAVEL_MAP_M05_USER_OPENAPI_SHA256,
        "map_user_runtime_openapi_sha256": "b" * 64,
        "map_user_runtime_operation_contract_sha256": KOR_TRAVEL_MAP_M05_USER_RUNTIME_OPERATION_CONTRACT_SHA256,
        "map_user_source_operation_contract_sha256": KOR_TRAVEL_MAP_M05_USER_SOURCE_OPERATION_CONTRACT_SHA256,
        "map_user_source_revision": _MAP_REVISION,
        "pinvi_api_image_digest": IMAGE_DIGESTS["pinvi_api_image_digest"],
        "pinvi_api_container_id": "d" * 64,
        "pinvi_dagster_image_digest": IMAGE_DIGESTS["pinvi_dagster_image_digest"],
        "pinvi_dagster_container_id": "e" * 64,
        "pinvi_image_evidence_sha256": "d" * 64,
        "pinvi_source_revision": PINVI_REVISION,
        "pinvi_web_image_digest": IMAGE_DIGESTS["pinvi_web_image_digest"],
        "pinvi_web_container_id": "f" * 64,
        "restore_drill": "passed",
        "restore_evidence_sha256": "e" * 64,
        "review_evidence_sha256": "f" * 64,
        "scope": "production",
        "version": 2,
    }
    payload.update(overrides)
    return payload


def _signed_receipt(payload: dict[str, object]) -> str:
    material = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    signature = base64.urlsafe_b64encode(PUBLIC_KEY_PRIVATE.sign(material.encode("utf-8")))
    return json.dumps(
        {"payload": payload, "signature": signature.decode("ascii").rstrip("=")},
        separators=(",", ":"),
    )


def _write_runtime_attestation(directory: Path, receipt: str, payload: dict[str, object]) -> Path:
    def dependency(
        container_field: str, digest_field: str, revision_field: str
    ) -> dict[str, object]:
        service_by_container = {
            "map_admin_container_id": ("map-m05", "admin"),
            "map_api_container_id": ("map-m05", "api"),
            "map_frontend_container_id": ("map-m05", "frontend"),
            "pinvi_api_container_id": ("pinvi-m05", "app-api"),
            "pinvi_web_container_id": ("pinvi-m05", "app-web"),
            "pinvi_dagster_container_id": ("pinvi-m05", "app-dagster"),
        }
        compose_project, compose_service = service_by_container[container_field]
        return {
            "container_id": payload[container_field],
            "digest": payload[digest_field],
            "environment": payload["scope"],
            "image_id": payload[digest_field],
            "compose_project": compose_project,
            "compose_service": compose_service,
            "revision_label": payload[revision_field],
            "source_revision": payload[revision_field],
            "started_at": "2026-08-24T00:00:00.000000000Z",
        }

    runtime_payload = {
        "activation_generation": payload["activation_generation"],
        "activation_nonce": payload["activation_nonce"],
        "created_at": int(time.time()),
        "dependencies": {
            "map_admin": dependency(
                "map_admin_container_id", "map_admin_image_digest", "map_admin_source_revision"
            ),
            "map_api": dependency(
                "map_api_container_id", "map_api_image_digest", "map_admin_source_revision"
            ),
            "map_frontend": dependency(
                "map_frontend_container_id",
                "map_frontend_image_digest",
                "map_admin_source_revision",
            ),
            "pinvi_api": dependency(
                "pinvi_api_container_id", "pinvi_api_image_digest", "pinvi_source_revision"
            ),
            "pinvi_web": dependency(
                "pinvi_web_container_id", "pinvi_web_image_digest", "pinvi_source_revision"
            ),
            "pinvi_dagster": dependency(
                "pinvi_dagster_container_id", "pinvi_dagster_image_digest", "pinvi_source_revision"
            ),
        },
        "endpoints": {
            "map_admin": payload["live_ui_map_admin_endpoint"],
            "pinvi_api": payload["live_ui_pinvi_api_endpoint"],
            "pinvi_web": payload["live_ui_pinvi_web_endpoint"],
        },
        "pinvi_source_revision": payload["pinvi_source_revision"],
        "receipt_sha256": hashlib.sha256(receipt.encode("utf-8")).hexdigest(),
        "scope": payload["scope"],
        "version": 2,
    }
    canonical = json.dumps(
        runtime_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    path = directory / "runtime-attestation.json"
    path.write_text(
        json.dumps(
            {
                "payload": runtime_payload,
                "signature": base64.urlsafe_b64encode(PUBLIC_KEY_PRIVATE.sign(canonical))
                .decode("ascii")
                .rstrip("="),
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def _write_runtime_lease(
    directory: Path,
    *,
    receipt: str,
    runtime_attestation_path: Path,
    payload: dict[str, object],
) -> None:
    directory.mkdir(mode=0o700)
    public_key = LEASE_PRIVATE_KEY.public_key().public_bytes_raw()
    key_id = hashlib.sha256(public_key).hexdigest()
    trust = {
        "key_id": key_id,
        "public_key": base64.urlsafe_b64encode(public_key).decode("ascii").rstrip("="),
        "version": 1,
    }
    (directory / "trust.json").write_text(
        json.dumps(trust, separators=(",", ":")), encoding="utf-8"
    )
    (directory / "trust.json").chmod(0o600)
    runtime_payload = json.loads(runtime_attestation_path.read_text(encoding="utf-8"))["payload"]
    assert isinstance(runtime_payload, dict)
    lease_payload = {
        "activation_generation": payload["activation_generation"],
        "activation_nonce": payload["activation_nonce"],
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
        "key_id": key_id,
        "receipt_sha256": hashlib.sha256(receipt.encode("utf-8")).hexdigest(),
        "runtime_attestation_sha256": hashlib.sha256(
            runtime_attestation_path.read_bytes()
        ).hexdigest(),
        "scope": payload["scope"],
        "sequence": 1,
        "version": 1,
    }
    material = json.dumps(
        lease_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    (directory / "current.json").write_text(
        json.dumps(
            {
                "payload": lease_payload,
                "signature": base64.urlsafe_b64encode(LEASE_PRIVATE_KEY.sign(material))
                .decode("ascii")
                .rstrip("="),
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    (directory / "current.json").chmod(0o600)


def _production_activation_values(receipt: str) -> dict[str, object]:
    return {
        "pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt": receipt,
        "pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt_public_key": PUBLIC_KEY,
        **IMAGE_DIGESTS,
    }


def _enabled_values() -> dict[str, object]:
    return {
        "pinvi_kor_travel_map_feature_reference_reconciliation_enabled": True,
        "pinvi_kor_travel_map_feature_reference_reconciliation_read_token": READ,
        "pinvi_kor_travel_map_feature_reference_reconciliation_ack_token": ACK,
        "pinvi_kor_travel_map_feature_reference_reconciliation_expected_openapi_sha256": (
            KOR_TRAVEL_MAP_SERVICE_OPENAPI_SHA256
        ),
        "pinvi_kor_travel_map_feature_reference_reconciliation_expected_source_revision": (
            KOR_TRAVEL_MAP_SERVICE_RELEASE_REVISION
        ),
    }


def test_reconciliation_network_is_default_off_and_empty_tokens_are_unset() -> None:
    loaded = _settings(
        pinvi_kor_travel_map_feature_reference_reconciliation_read_token="",
        pinvi_kor_travel_map_feature_reference_reconciliation_ack_token="",
    )
    assert loaded.pinvi_kor_travel_map_feature_reference_reconciliation_enabled is False
    assert loaded.pinvi_kor_travel_map_feature_reference_reconciliation_read_token is None
    assert loaded.pinvi_kor_travel_map_feature_reference_reconciliation_ack_token is None
    assert (
        loaded.pinvi_kor_travel_map_feature_reference_reconciliation_blocked_recheck_seconds == 30
    )


def test_empty_cache_target_contract_generation_env_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_COMMAND_TOKEN", "")
    monkeypatch.setenv("PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_CONSUMER_TOKEN", "")
    monkeypatch.setenv("PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_RESTORE_FENCE_TOKEN", "")
    monkeypatch.setenv("PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_RECOVERY_TOKEN", "")
    monkeypatch.setenv("PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_EXPECTED_CONTRACT_GENERATION", "")

    loaded = _settings()

    assert loaded.pinvi_kor_travel_map_cache_target_command_token is None
    assert loaded.pinvi_kor_travel_map_cache_target_consumer_token is None
    assert loaded.pinvi_kor_travel_map_cache_target_restore_fence_token is None
    assert loaded.pinvi_kor_travel_map_cache_target_recovery_token is None
    assert loaded.pinvi_kor_travel_map_cache_target_expected_contract_generation is None


@pytest.mark.parametrize("value", (0, 0.9, 3600.1, float("inf"), float("nan")))
def test_reconciliation_blocked_recheck_is_finite_bounded(value: float) -> None:
    with pytest.raises(ValidationError):
        _settings(
            pinvi_kor_travel_map_feature_reference_reconciliation_blocked_recheck_seconds=value
        )


def test_enabled_reconciliation_requires_distinct_credentials_and_exact_vendor_pin() -> None:
    with pytest.raises(ValidationError, match="READ_TOKEN"):
        _settings(pinvi_kor_travel_map_feature_reference_reconciliation_enabled=True)
    with pytest.raises(ValidationError, match="scoped Map service tokens must differ"):
        _settings(
            **{
                **_enabled_values(),
                "pinvi_kor_travel_map_feature_reference_reconciliation_ack_token": READ,
            },
        )
    with pytest.raises(ValidationError, match="must match the vendored service contract"):
        _settings(
            **{
                **_enabled_values(),
                "pinvi_kor_travel_map_feature_reference_reconciliation_expected_openapi_sha256": "b"
                * 64,
            },
        )
    assert _settings(
        **_enabled_values()
    ).pinvi_kor_travel_map_feature_reference_reconciliation_enabled


@pytest.mark.parametrize(
    "overrides",
    (
        {"kor_travel_map_feature_request_token": READ},
        {"pinvi_kor_travel_map_cache_target_consumer_token": READ},
        {"pinvi_kor_travel_map_service_token": READ},
    ),
)
def test_reconciliation_tokens_cannot_reuse_other_map_boundary(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match=r"must differ|must not reuse"):
        _settings(**{**_enabled_values(), **overrides})


def test_production_reconciliation_enable_requires_activation_receipt() -> None:
    with pytest.raises(ValueError, match=r"ACTIVATION_RECEIPT.*required"):
        _production_settings(
            pinvi_kor_travel_map_api_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_admin_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_ops_read_token="o" * 32,
            pinvi_kor_travel_map_ops_cancel_token="c" * 32,
            **_enabled_values(),
        )


def test_production_reconciliation_accepts_current_paired_activation_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PINVI_SOURCE_REVISION", PINVI_REVISION)
    loaded = _production_settings(
        pinvi_kor_travel_map_api_base_url="http://127.0.0.1:12701",
        pinvi_kor_travel_map_admin_base_url="http://127.0.0.1:12701",
        pinvi_kor_travel_map_ops_read_token="o" * 32,
        pinvi_kor_travel_map_ops_cancel_token="c" * 32,
        **_production_activation_values(_signed_receipt(_receipt_payload())),
        **_enabled_values(),
    )
    assert loaded.pinvi_kor_travel_map_feature_reference_reconciliation_enabled is True


def test_production_reconciliation_accepts_secure_mounted_activation_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PINVI_SOURCE_REVISION", PINVI_REVISION)
    with tempfile.TemporaryDirectory(prefix="pinvi-m05-receipt-", dir="/tmp") as directory:
        receipt_path = Path(directory) / "activation-receipt.json"
        receipt_path.write_text(_signed_receipt(_receipt_payload()), encoding="utf-8")
        receipt_path.chmod(0o600)
        loaded = _production_settings(
            pinvi_kor_travel_map_api_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_admin_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt_path=str(
                receipt_path
            ),
            pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt_public_key=PUBLIC_KEY,
            pinvi_kor_travel_map_ops_read_token="o" * 32,
            pinvi_kor_travel_map_ops_cancel_token="c" * 32,
            **IMAGE_DIGESTS,
            **_enabled_values(),
        )
    assert loaded.pinvi_kor_travel_map_feature_reference_reconciliation_enabled is True


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("live_ui_e2e", "skipped", "live UI E2E"),
        ("map_service_source_revision", "0" * 40, "Map pair"),
        # v2 계약이 revision 사본을 걷어낸 세 표면. 대조 상대가 사라진 자리를 비워
        # 두면 형식조차 보증되지 않고, 세 표면이 서로 다른 Map을 가리켜도 통과한다.
        # admin·full·user는 하나의 Map revision에서 나온다(적대 리뷰 P2).
        ("map_full_source_revision", "0" * 40, "not the pinned Map revision"),
        ("map_user_source_revision", "0" * 40, "not the pinned Map revision"),
        ("map_admin_source_revision", "z" * 40, "Map source revision is invalid"),
        ("map_user_source_revision", "1" * 39, "Map source revision is invalid"),
        ("pinvi_source_revision", "0" * 40, "Pinvi source revision"),
        ("pinvi_api_image_digest", "sha256:" + "0" * 64, "image digest"),
    ),
)
def test_production_reconciliation_rejects_stale_activation_receipt(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    message: str,
) -> None:
    monkeypatch.setenv("PINVI_SOURCE_REVISION", PINVI_REVISION)
    receipt = _receipt_payload(**{field: value})
    with pytest.raises(ValueError, match=message):
        _production_settings(
            pinvi_kor_travel_map_api_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_admin_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_ops_read_token="o" * 32,
            pinvi_kor_travel_map_ops_cancel_token="c" * 32,
            **_production_activation_values(_signed_receipt(receipt)),
            **_enabled_values(),
        )


def test_production_reconciliation_rejects_receipt_secret_leaks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "UNIQUE-M05-ACTIVATION-RECEIPT-SECRET"
    with pytest.raises(ValidationError) as captured:
        _production_settings(
            pinvi_kor_travel_map_api_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_admin_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_ops_read_token="o" * 32,
            pinvi_kor_travel_map_ops_cancel_token="c" * 32,
            **_production_activation_values(secret),
            **_enabled_values(),
        )
    assert secret not in repr(captured.value.errors())
    assert secret not in str(captured.value)


def test_scoped_token_validation_errors_redact_secret_input() -> None:
    secret = "UNIQUE-SCOPED-TOKEN-TO-REDACT"
    with pytest.raises(ValidationError) as captured:
        _settings(
            **{
                **_enabled_values(),
                "pinvi_kor_travel_map_feature_reference_reconciliation_read_token": secret,
            }
        )
    assert secret not in repr(captured.value.errors())
    assert secret not in str(captured.value)


@pytest.mark.parametrize(
    "field",
    ("version", "scope"),
)
def test_production_reconciliation_rejects_boolean_numeric_receipt_fields(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    monkeypatch.setenv("PINVI_SOURCE_REVISION", PINVI_REVISION)
    receipt = _receipt_payload(**{field: True})
    with pytest.raises(ValueError, match=r"M05 activation|production v2"):
        _production_settings(
            pinvi_kor_travel_map_api_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_admin_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_ops_read_token="o" * 32,
            pinvi_kor_travel_map_ops_cancel_token="c" * 32,
            **_production_activation_values(_signed_receipt(receipt)),
            **_enabled_values(),
        )


def test_production_reconciliation_rejects_duplicate_receipt_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PINVI_SOURCE_REVISION", PINVI_REVISION)
    receipt = _signed_receipt(_receipt_payload()).replace('"version":2', '"version":2,"version":2')
    with pytest.raises(ValueError, match="duplicate keys"):
        _production_settings(
            pinvi_kor_travel_map_api_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_admin_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_ops_read_token="o" * 32,
            pinvi_kor_travel_map_ops_cancel_token="c" * 32,
            **_production_activation_values(receipt),
            **_enabled_values(),
        )


def test_production_reconciliation_rejects_invalid_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PINVI_SOURCE_REVISION", PINVI_REVISION)
    receipt = _receipt_payload()
    broken = json.loads(_signed_receipt(receipt))
    broken["signature"] = "A" * 86
    with pytest.raises(ValueError, match="signature is invalid"):
        _production_settings(
            pinvi_kor_travel_map_api_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_admin_base_url="http://127.0.0.1:12701",
            pinvi_kor_travel_map_ops_read_token="o" * 32,
            pinvi_kor_travel_map_ops_cancel_token="c" * 32,
            **_production_activation_values(json.dumps(broken, separators=(",", ":"))),
            **_enabled_values(),
        )


def test_compose_and_examples_keep_m05_credentials_api_only_and_default_off() -> None:
    root = Path(__file__).resolve().parents[4]
    compose = (root / "infra/docker-compose.app.yml").read_text(encoding="utf-8")
    prod = (root / "infra/.env.prod.example").read_text(encoding="utf-8")
    example = (root / ".env.example").read_text(encoding="utf-8")
    for variable in (
        "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_READ_TOKEN",
        "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACK_TOKEN",
        "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_BLOCKED_RECHECK_SECONDS",
        "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT",
        "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT_PUBLIC_KEY",
        "PINVI_M05_RUNTIME_LEASE_DIRECTORY",
        "PINVI_M05_RUNTIME_LEASE_MAX_LIFETIME_SECONDS",
        "PINVI_API_IMAGE_DIGEST",
        "PINVI_WEB_IMAGE_DIGEST",
        "PINVI_DAGSTER_IMAGE_DIGEST",
    ):
        assert variable in compose
        assert f"{variable}=" in prod
        assert f"{variable}=" in example
    assert "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ENABLED=false" in prod
    assert "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ENABLED=false" in example

    api_block = compose.split("  app-api:", maxsplit=1)[1].split("  app-migrator:", maxsplit=1)[0]
    for service_start, service_end in (
        ("  app-migrator:", "  app-web:"),
        ("  app-web:", "  app-dagster:"),
        ("  app-dagster:", "  cadvisor:"),
    ):
        service_block = compose.split(service_start, maxsplit=1)[1].split(service_end, maxsplit=1)[
            0
        ]
        for variable in (
            "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT",
            "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT_PUBLIC_KEY",
            "PINVI_API_IMAGE_DIGEST",
            "PINVI_WEB_IMAGE_DIGEST",
            "PINVI_DAGSTER_IMAGE_DIGEST",
        ):
            assert variable not in service_block
    assert "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT" in api_block
    assert "kor-travel-map-m05-pair-provenance-v1.json" in (root / "apps/api/Dockerfile").read_text(
        encoding="utf-8"
    )


def test_m05_docker_identity_does_not_expose_engine_socket() -> None:
    root = Path(__file__).resolve().parents[4]
    compose = (root / "infra/docker-compose.app.yml").read_text(encoding="utf-8")

    assert "source: /var/run/docker.sock" not in compose
    assert "target: /var/run/docker.sock" not in compose
    assert "PINVI_M05_RUNTIME_LIVE_CHECK" in compose
    assert "PINVI_DOCKER_SOCKET_HOST_PATH" not in compose
    assert "PINVI_M05_RUNTIME_LEASE_PRIVATE_KEY" not in compose
    app_api_block = compose.split("  app-api:", maxsplit=1)[1].split("  app-backup:", maxsplit=1)[0]
    assert "PINVI_M05_RUNTIME_LEASE_HOST_DIR" in app_api_block
    assert "target: ${PINVI_M05_RUNTIME_LEASE_DIRECTORY:-/run/pinvi/m05/lease}" in app_api_block
    assert "source: ${PINVI_RESTORE_TRUSTED_BACKUP_HOST_DIR" not in app_api_block
    assert "target: /var/lib/pinvi/restore-trust" not in app_api_block
    assert "target: /var/lib/pinvi/backup-catalog" in app_api_block
    with pytest.raises(RuntimeError, match="identity input"):
        config_module._m05_docker_inspect(
            "fake-docker.sock",
            container_id="d" * 64,
            timeout_seconds=1.0,
        )


def test_m05_evidence_runtime_uses_non_owner_database_login() -> None:
    root = Path(__file__).resolve().parents[4]
    compose = (root / "infra/docker-compose.app.yml").read_text(encoding="utf-8")
    bootstrap = (root / "infra/postgres/bootstrap-pinvi-runtime-role.sh").read_text(
        encoding="utf-8"
    )
    migration = (
        root / "apps/api/alembic/versions/20260824_0101_m05_activation_contract.py"
    ).read_text(encoding="utf-8")
    docker_app = (root / "scripts/docker-app.sh").read_text(encoding="utf-8")
    deploy = (root / "scripts/deploy-node.sh").read_text(encoding="utf-8")
    api_block, _ = compose.split("  app-migrator:", maxsplit=1)

    assert "app-db-runtime-role:" in compose
    assert (
        "PINVI_DATABASE_URL: postgresql+asyncpg://${PINVI_APP_DB_USER:-pinvi_app}:"
        "${PINVI_APP_DB_PASSWORD:-pinvi_app_smoke}@app-postgres:5432/pinvi" in api_block
    )
    assert "PINVI_MIGRATOR_DATABASE_URL" not in compose
    for source in (docker_app, deploy):
        assert 'local service="app-migrator"' in source
        assert 'service="app-legacy-rebaseline-migrator"' in source
        assert '"$service" pinvi-admin-bootstrap' in source
        assert "reject_explicit_migrator_database_url()" in source
        assert "PINVI_MIGRATOR_DATABASE_URL is unsupported" in source
    for source in (docker_app, deploy):
        assert "compose run --rm" in source
        assert "app-db-runtime-role" in source
    assert "NOSUPERUSER" in bootstrap
    assert "NOINHERIT" in bootstrap
    assert "0101이 catalog fingerprint·handoff를 완료한 뒤 app runtime 권한" in bootstrap
    assert "ALTER DEFAULT PRIVILEGES FOR ROLE" in migration
    assert 'PINVI_DB_HOST="${PINVI_DB_HOST:-app-postgres}"' in bootstrap
    assert 'PINVI_DB_PORT="${PINVI_DB_PORT:-5432}"' in bootstrap
    assert (
        "until psql --no-psqlrc --no-password --tuples-only --no-align "
        '--host="${PINVI_DB_HOST}" --port="${PINVI_DB_PORT}"' in bootstrap
    )
    assert "--command='SELECT 1'" in bootstrap
    assert '[ "$attempt" -ge 90 ]' in bootstrap
    assert "FROM pg_auth_members membership" in bootstrap
    assert "membership.member = runtime.oid" in bootstrap
    assert "membership.roleid = runtime.oid" in bootstrap
    assert "CREATE SCHEMA IF NOT EXISTS x_extension AUTHORIZATION" in bootstrap
    assert "ALTER SCHEMA x_extension OWNER TO" in bootstrap
    assert "REVOKE ALL ON SCHEMA x_extension FROM PUBLIC;" in bootstrap
    assert 'GRANT USAGE ON SCHEMA x_extension TO :"app_role", :"schema_owner", ' in bootstrap
    assert "has_schema_privilege(runtime.oid, 'app', 'CREATE')" in bootstrap
    assert "FROM pg_proc procedure" in bootstrap
    assert "FROM pg_type type_row" in bootstrap
    assert "FROM pg_extension extension_row" in bootstrap
    assert "extension_row.extowner = :'bootstrap_owner'::regrole" in bootstrap
    assert "relation.relowner AS owner_oid" in bootstrap
    assert "(SELECT nspowner FROM app_schema) = :'schema_owner'::regrole" in bootstrap
    assert "NOT pg_has_role(migrator.oid, (SELECT oid FROM database_owner), 'MEMBER')" in bootstrap
