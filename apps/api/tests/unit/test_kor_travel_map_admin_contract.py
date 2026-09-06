"""kor-travel-map Admin OpenAPI의 Pinvi feature 소비 계약 게이트 (T-VN-42)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from app.schemas.admin import AdminFeatureDetailCuration, AdminFeatureWeatherMetric
from tests.unit._kor_travel_map_snapshot_pin import (
    SNAPSHOT,
    SNAPSHOT_SHA256,
    UPSTREAM_COMMIT,
)

_M05_PAIR = (
    Path(__file__).resolve().parents[4] / "contracts" / "kor-travel-map-m05-pair-provenance-v1.json"
)
_SNAPSHOT = SNAPSHOT
_UPSTREAM_COMMIT = UPSTREAM_COMMIT
_SNAPSHOT_SHA256 = SNAPSHOT_SHA256

_ADMIN_FEATURE_QUERY_PARAMETERS = {
    "q",
    "kind",
    "category",
    "lifecycle_state",
    "publication_state",
    "quality_state",
    "provider_dataset_id",
    "has_coord",
    "has_issue",
    "issue_type",
    "updated_from",
    "updated_to",
    "include_ended",
    "page_size",
    "cursor",
    "sort",
    "order",
}


def _spec() -> dict[str, Any]:
    loaded = json.loads(_SNAPSHOT.read_bytes())
    assert isinstance(loaded, dict)
    return loaded


def _schema(spec: dict[str, Any], name: str) -> dict[str, Any]:
    return spec["components"]["schemas"][name]


def _response_ref(operation: dict[str, Any]) -> str:
    return operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]


def _query_names(operation: dict[str, Any]) -> set[str]:
    return {
        parameter["name"]
        for parameter in operation.get("parameters", [])
        if parameter["in"] == "query"
    }


def test_admin_snapshot_is_byte_pinned_to_a_reviewed_map_revision() -> None:
    assert _UPSTREAM_COMMIT == "3c5076a05890b0c5337e63ece7cf6a055bf86203"
    assert hashlib.sha256(_SNAPSHOT.read_bytes()).hexdigest() == _SNAPSHOT_SHA256


def test_m05_pair_admin_and_full_are_bound_to_the_admin_vendor() -> None:
    pair = json.loads(_M05_PAIR.read_bytes())
    assert isinstance(pair, dict)
    map_pair = pair["map"]
    assert isinstance(map_pair, dict)
    for name in ("admin", "full"):
        entry = map_pair[name]
        assert isinstance(entry, dict)
        assert entry["openapi_sha256"] == _SNAPSHOT_SHA256
        assert entry["source_revision"] == _UPSTREAM_COMMIT


def test_manual_feature_provenance_exposes_separate_opaque_id_and_uuid() -> None:
    spec = _spec()
    operation = spec["paths"]["/v1/admin/features/{feature_id}/creation-provenance"]["get"]

    assert operation["security"] == [{"AdminBFF": []}]
    assert operation["parameters"] == [
        {
            "in": "path",
            "name": "feature_id",
            "required": True,
            "schema": {"title": "Feature Id", "type": "string"},
        }
    ]
    assert _response_ref(operation) == "#/components/schemas/AdminManualFeatureProvenanceResponse"
    data = _schema(spec, "AdminManualFeatureProvenanceData")
    assert {"feature_id", "feature_uuid", "claim", "origin"} == set(data["required"])
    assert data["properties"]["feature_id"] == {
        "title": "Feature Id",
        "type": "string",
    }
    assert data["properties"]["feature_uuid"] == {
        "format": "uuid",
        "title": "Feature Uuid",
        "type": "string",
    }


def test_manual_feature_create_contract_is_exact_but_not_yet_consumed() -> None:
    spec = _spec()
    operation = spec["paths"]["/v1/admin/features"]["post"]

    # 두 scheme는 OR 대안이 아니라 같은 security requirement 안의 AND다.
    assert operation["security"] == [{"AdminBFF": [], "AdminFeatureCreateBFF": []}]

    parameters = operation["parameters"]
    assert len(parameters) == 1
    idempotency_key = parameters[0]
    assert {
        "name": idempotency_key["name"],
        "in": idempotency_key["in"],
        "required": idempotency_key["required"],
        "type": idempotency_key["schema"]["type"],
        "format": idempotency_key["schema"]["format"],
    } == {
        "name": "Idempotency-Key",
        "in": "header",
        "required": True,
        "type": "string",
        "format": "uuid",
    }

    assert operation["requestBody"] == {
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/AdminFeatureCreateRequest"}
            }
        },
        "required": True,
    }
    request_schema = _schema(spec, "AdminFeatureCreateRequest")
    assert request_schema["additionalProperties"] is False
    assert set(request_schema["required"]) == {
        "name",
        "category",
        "coord",
        "marker_icon",
        "marker_color",
        "kind",
        "reason",
    }
    assert {
        "feature_id",
        "idempotency_key",
        "operator",
        "actor",
        "requested_by",
        "request_id",
        "command_id",
        "row_revision",
        "status",
        "lifecycle_state",
        "publication_state",
        "quality_state",
        "creation_origin",
    }.isdisjoint(request_schema["properties"])

    created = operation["responses"]["201"]
    assert created["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AdminManualFeatureCreateResponse"
    }
    assert set(created["headers"]) == {
        "ETag",
        "Location",
        "X-Request-ID",
        "Idempotency-Replayed",
    }
    assert created["headers"]["Idempotency-Replayed"]["schema"] == {
        "enum": ["true"],
        "type": "string",
    }
    assert all(
        created["headers"][name]["schema"]["type"] == "string"
        for name in ("ETag", "Location", "X-Request-ID")
    )


def test_feature_request_approve_terminal_headers_are_exact() -> None:
    operation = _spec()["paths"]["/v1/admin/feature-requests/{request_id}/approve"]["post"]

    assert operation["responses"]["200"]["headers"] == {
        "ETag": {
            "description": "승인 또는 exact-conflict winner Feature의 strong entity tag.",
            "schema": {"type": "string"},
        },
        "Location": {
            "description": "승인 또는 exact-conflict winner Feature의 canonical resource URI.",
            "schema": {"format": "uri-reference", "type": "string"},
        },
    }


def test_admin_feature_paths_auth_responses_and_query_sets_are_exact() -> None:
    spec = _spec()
    operations = {
        "/v1/admin/features": spec["paths"]["/v1/admin/features"]["get"],
        "/v1/admin/features/{feature_id}": spec["paths"]["/v1/admin/features/{feature_id}"]["get"],
        "/v1/admin/features/{feature_id}/weather": spec["paths"][
            "/v1/admin/features/{feature_id}/weather"
        ]["get"],
    }
    assert all(operation["security"] == [{"AdminBFF": []}] for operation in operations.values())
    assert _query_names(operations["/v1/admin/features"]) == _ADMIN_FEATURE_QUERY_PARAMETERS
    assert _query_names(operations["/v1/admin/features/{feature_id}"]) == set()
    assert _query_names(operations["/v1/admin/features/{feature_id}/weather"]) == set()
    assert _response_ref(operations["/v1/admin/features"]) == (
        "#/components/schemas/AdminFeaturesListResponse"
    )
    assert _response_ref(operations["/v1/admin/features/{feature_id}"]) == (
        "#/components/schemas/AdminFeatureDetailResponse"
    )
    assert _response_ref(operations["/v1/admin/features/{feature_id}/weather"]) == (
        "#/components/schemas/FeatureWeatherResponse"
    )


def test_admin_feature_response_containers_keep_consumed_item_refs() -> None:
    spec = _spec()
    assert _schema(spec, "AdminFeaturesListResponse")["properties"]["data"]["$ref"] == (
        "#/components/schemas/AdminFeaturesListData"
    )
    assert _schema(spec, "AdminFeaturesListData")["properties"]["items"]["items"]["$ref"] == (
        "#/components/schemas/AdminFeatureRecord"
    )
    assert _schema(spec, "AdminFeatureDetailResponse")["properties"]["data"]["$ref"] == (
        "#/components/schemas/AdminFeatureDetailData"
    )
    detail = _schema(spec, "AdminFeatureDetailData")["properties"]
    assert detail["feature"]["$ref"] == ("#/components/schemas/AdminFeatureDetailFeatureRecord")
    assert {
        name: detail[name]["items"]["$ref"]
        for name in (
            "sources",
            "issues",
            "overrides",
            "state_transitions",
            "files",
            "curations",
        )
    } == {
        "sources": "#/components/schemas/AdminFeatureDetailSourceRecord",
        "issues": "#/components/schemas/AdminFeatureDetailIssueRecord",
        "overrides": "#/components/schemas/AdminFeatureDetailOverrideRecord",
        "state_transitions": ("#/components/schemas/AdminFeatureStateTransitionAuditRecord"),
        "files": "#/components/schemas/AdminFeatureDetailFileRecord",
        "curations": "#/components/schemas/AdminCurationItemView",
    }


def test_admin_feature_state_axes_transition_and_curation_shapes_are_pinned() -> None:
    spec = _spec()
    for name in ("AdminFeatureRecord", "AdminFeatureDetailFeatureRecord"):
        schema = _schema(spec, name)
        assert {
            "lifecycle_state",
            "publication_state",
            "quality_state",
        } <= set(schema["required"])
        assert "status" not in schema["properties"]
        assert schema["properties"]["lifecycle_state"]["enum"] == ["active", "retired"]
        assert schema["properties"]["publication_state"]["enum"] == [
            "draft",
            "published",
            "suppressed",
        ]
        assert schema["properties"]["quality_state"]["enum"] == [
            "valid",
            "quarantined",
        ]

    transition = _schema(spec, "AdminFeatureStateTransitionAuditRecord")
    assert set(transition["required"]) == {
        "transition_id",
        "to_lifecycle_state",
        "to_publication_state",
        "to_quality_state",
        "transition_kind",
        "reason_code",
        "principal",
        "occurred_at",
        "row_revision",
    }
    assert transition["properties"]["occurred_at"] == {
        "format": "date-time",
        "title": "Occurred At",
        "type": "string",
    }
    assert transition["properties"]["row_revision"]["minimum"] == 1.0

    curation = _schema(spec, "AdminCurationItemView")
    consumed_curation_fields = {
        "curation_item_id",
        "collection_id",
        "collection_key",
        "title",
        "edition_key",
        "theme_slug",
        "theme_name",
        "theme_group",
        "feature_id",
        "feature_name",
        "feature_kind",
        "feature_category",
        "place_name",
        "address_hint",
        "status",
        "sort_order",
        "item_title",
        "item_summary",
        "curation_relation",
        "reuse_policy",
        "row_revision",
        "updated_at",
    }
    assert consumed_curation_fields <= set(curation["required"])
    assert consumed_curation_fields <= set(curation["properties"])
    assert set(AdminFeatureDetailCuration.model_fields) == consumed_curation_fields
    assert curation["properties"]["curation_item_id"]["format"] == "uuid"
    assert curation["properties"]["collection_id"]["format"] == "uuid"
    assert curation["properties"]["status"]["enum"] == [
        "candidate",
        "included",
        "rejected",
        "archived",
    ]
    assert curation["properties"]["curation_relation"]["enum"] == [
        "primary_stop",
        "food_stop",
        "cafe_stop",
        "bookstore_stop",
        "nearby_option",
        "accessibility_support",
        "pet_support",
        "family_support",
        "theme_area_anchor",
    ]
    assert curation["properties"]["reuse_policy"]["enum"] == [
        "allowed",
        "blocked",
        "manual_review",
    ]
    assert curation["properties"]["row_revision"]["pattern"] == "^[1-9][0-9]*$"
    assert curation["properties"]["updated_at"]["format"] == "date-time"
    for name in (
        "feature_id",
        "feature_name",
        "feature_kind",
        "feature_category",
        "address_hint",
        "item_title",
        "item_summary",
    ):
        assert {"type": "null"} in curation["properties"][name]["anyOf"]


def test_admin_weather_card_keeps_the_fields_pinvi_projects() -> None:
    spec = _spec()
    weather_response = _schema(spec, "FeatureWeatherResponse")
    assert weather_response["properties"]["data"]["$ref"] == (
        "#/components/schemas/WeatherCardData"
    )
    weather = _schema(spec, "WeatherCardData")
    assert {"feature_id", "is_stale", "source_styles", "metrics"} <= set(weather["required"])
    assert {"selected_at", "latest_at"} <= set(weather["properties"])
    assert {
        tuple(sorted(item.items())) for item in weather["properties"]["selected_at"]["anyOf"]
    } == {
        (("format", "date-time"), ("type", "string")),
        (("type", "null"),),
    }
    assert weather["properties"]["metrics"]["items"]["$ref"] == (
        "#/components/schemas/WeatherMetricOut"
    )
    metric = _schema(spec, "WeatherMetricOut")
    required_metric_fields = {
        "forecast_style",
        "metric_key",
        "provider_dataset_id",
        "dataset_key",
        "dataset_display_name",
        "known_at",
    }
    assert set(metric["required"]) == required_metric_fields
    assert required_metric_fields <= set(AdminFeatureWeatherMetric.model_fields)
    assert metric["properties"]["provider_dataset_id"]["type"] == "integer"
    assert metric["properties"]["known_at"]["format"] == "date-time"
