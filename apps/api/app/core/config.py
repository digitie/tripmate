"""환경변수 + 설정 (pydantic-settings).

루트 `.env.example` 항목과 동기.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import os
import re
import socket
import stat
import time
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, NoReturn, Self, cast
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import (
    Field,
    PrivateAttr,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.m05_runtime_lease import (
    M05RuntimeLeaseBinding,
    M05RuntimeLeaseError,
    M05RuntimeLeaseVerifier,
)

PinviEnvironment = Literal["development", "test", "smoke", "isolated", "staging", "production"]
_STRICT_RESTORE_EXECUTOR_ENVIRONMENTS = frozenset({"staging", "production"})
_SERVICE_PROVENANCE_FILENAME = "kor-travel-map-service-provenance-v1.json"
_PACKAGED_SERVICE_PROVENANCE_PATH = f"_contract_data/{_SERVICE_PROVENANCE_FILENAME}"
_M05_PAIR_PROVENANCE_FILENAME = "kor-travel-map-m05-pair-provenance-v1.json"
_PACKAGED_M05_PAIR_PROVENANCE_PATH = f"_contract_data/{_M05_PAIR_PROVENANCE_FILENAME}"
_M05_ACTIVATION_TRUST_FILENAME = "pinvi-m05-activation-receipt-trust-v1.json"
_M05_REVIEWER_ROSTER_FILENAME = "pinvi-m05-reviewer-roster-v1.json"
_M05_ACTIVATION_PR_URL = "https://github.com/digitie/pinvi/pull/466"
_CONTAINER_ID_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")


class _DuplicateJsonKeyError(ValueError):
    """activation receipt의 중복 키를 fail-closed로 거부한다."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise _DuplicateJsonKeyError
        payload[key] = value
    return payload


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _ledger_record_hash(record: dict[str, object]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
    return hashlib.sha256(_canonical_json(unsigned)).hexdigest()


def _decode_canonical_reviewer_public_key(value: object) -> bytes | None:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is None:
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (binascii.Error, ValueError):
        return None
    if (
        len(decoded) != 32
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        return None
    try:
        Ed25519PublicKey.from_public_bytes(decoded)
    except ValueError:
        return None
    return decoded


def _runtime_container_id() -> str | None:
    """현재 API 프로세스가 속한 Docker cgroup의 실제 container ID를 읽는다."""

    for path in (Path("/proc/self/cgroup"), Path("/proc/1/cpuset")):
        try:
            matches = _CONTAINER_ID_RE.findall(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        if matches:
            return cast(str, matches[-1])
    return None


def _m05_docker_request(
    path: Path, *, request_path: str, timeout_seconds: float
) -> dict[str, object]:
    """canonical Docker Engine socket에서 제한된 JSON 응답을 읽는다."""

    if not request_path.startswith("/") or any(character in request_path for character in "\r\n"):
        raise RuntimeError("M05 runtime Docker request path is invalid")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout_seconds)
    try:
        connection.connect(str(path))
        connection.sendall(
            (f"GET {request_path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n").encode(
                "ascii"
            )
        )
        response = http.client.HTTPResponse(connection)
        response.begin()
        if response.status != 200:
            raise RuntimeError("M05 runtime Docker request returned a non-success status")
        raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise RuntimeError("M05 runtime Docker response is too large")
    except (OSError, http.client.HTTPException) as exc:
        raise RuntimeError("M05 runtime Docker identity could not be inspected") from exc
    finally:
        connection.close()
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKeyError) as exc:
        raise RuntimeError("M05 runtime Docker response is invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError("M05 runtime Docker response is not an object")
    return cast(dict[str, object], value)


def _m05_docker_inspect(
    socket_path: str, *, container_id: str, timeout_seconds: float
) -> dict[str, object]:
    """canonical Docker Engine socket에서 engine과 container metadata를 읽는다."""

    path = Path(socket_path)
    if (
        socket_path != "/var/run/docker.sock"
        or not path.is_absolute()
        or path.is_symlink()
        or not path.is_socket()
        or not re.fullmatch(r"[0-9a-f]{64}", container_id)
    ):
        raise RuntimeError("M05 runtime Docker identity input is invalid")
    try:
        socket_metadata = path.stat()
    except OSError as exc:
        raise RuntimeError("M05 runtime Docker socket could not be inspected") from exc
    if socket_metadata.st_uid != 0 or stat.S_IMODE(socket_metadata.st_mode) & 0o002:
        raise RuntimeError("M05 runtime Docker socket is not trusted")
    engine = _m05_docker_request(path, request_path="/info", timeout_seconds=timeout_seconds)
    if (
        not isinstance(engine.get("ID"), str)
        or not engine["ID"]
        or not isinstance(engine.get("ServerVersion"), str)
        or not engine["ServerVersion"]
        or not isinstance(engine.get("DockerRootDir"), str)
        or not str(engine["DockerRootDir"]).startswith("/")
    ):
        raise RuntimeError("M05 runtime Docker Engine identity is invalid")
    return _m05_docker_request(
        path,
        request_path=f"/containers/{container_id}/json",
        timeout_seconds=timeout_seconds,
    )


def _validate_m05_runtime_dependencies_live(
    *,
    dependencies: dict[str, object],
    endpoints: dict[str, object],
    socket_path: str,
    timeout_seconds: float,
    environment: str,
) -> None:
    """서명된 snapshot의 여섯 dependency를 startup 시점의 Docker 상태와 대조한다."""

    endpoint_ports: dict[str, tuple[int, int]] = {
        "map_admin": (13701, 12701),
        "pinvi_api": (8000, 12801),
        "pinvi_web": (3000, 12805),
    }
    for name, raw_dependency in dependencies.items():
        if not isinstance(raw_dependency, dict):
            raise RuntimeError(f"M05 runtime dependency is not an object: {name}")
        container_id = raw_dependency.get("container_id")
        digest = raw_dependency.get("digest")
        source_revision = raw_dependency.get("source_revision")
        started_at = raw_dependency.get("started_at")
        compose_project = raw_dependency.get("compose_project")
        compose_service = raw_dependency.get("compose_service")
        if not all(
            isinstance(value, str)
            for value in (
                container_id,
                digest,
                source_revision,
                started_at,
                compose_project,
                compose_service,
            )
        ):
            raise RuntimeError(f"M05 runtime dependency fields are invalid: {name}")
        live = _m05_docker_inspect(
            socket_path,
            container_id=cast(str, container_id),
            timeout_seconds=timeout_seconds,
        )
        live_id = live.get("Id")
        live_image = live.get("Image")
        state = live.get("State")
        config = live.get("Config")
        if not isinstance(state, dict) or state.get("Running") is not True:
            raise RuntimeError(f"M05 runtime dependency is not running: {name}")
        if live_id != container_id or live_image != digest or state.get("StartedAt") != started_at:
            raise RuntimeError(f"M05 runtime dependency identity drifted: {name}")
        if not isinstance(config, dict) or not isinstance(config.get("Labels"), dict):
            raise RuntimeError(f"M05 runtime dependency labels are missing: {name}")
        labels = cast(dict[str, object], config["Labels"])
        if (
            labels.get("io.pinvi.build.environment") != environment
            or labels.get("org.opencontainers.image.revision") != source_revision
            or labels.get("com.docker.compose.project") != compose_project
            or labels.get("com.docker.compose.service") != compose_service
        ):
            raise RuntimeError(f"M05 runtime dependency labels drifted: {name}")
        endpoint_binding = endpoint_ports.get(name)
        if endpoint_binding is None:
            continue
        raw_endpoint = endpoints.get(name)
        if not isinstance(raw_endpoint, str):
            raise RuntimeError(f"M05 runtime endpoint is missing: {name}")
        parsed_endpoint = urlsplit(raw_endpoint)
        if (
            parsed_endpoint.scheme != "http"
            or parsed_endpoint.hostname != "127.0.0.1"
            or parsed_endpoint.port != endpoint_binding[1]
            or parsed_endpoint.path not in {"", "/"}
            or parsed_endpoint.query
            or parsed_endpoint.fragment
        ):
            raise RuntimeError(f"M05 runtime endpoint is not canonical: {name}")
        network = live.get("NetworkSettings")
        ports = network.get("Ports") if isinstance(network, dict) else None
        bindings = ports.get(f"{endpoint_binding[0]}/tcp") if isinstance(ports, dict) else None
        if not isinstance(bindings, list) or not any(
            isinstance(binding, dict)
            and binding.get("HostIp") == "127.0.0.1"
            and str(binding.get("HostPort")) == str(endpoint_binding[1])
            for binding in bindings
        ):
            raise RuntimeError(f"M05 runtime endpoint binding drifted: {name}")


def _raise_redacted_settings_error(message: str) -> NoReturn:
    """SecretStr가 포함된 Settings 검증 오류에서 raw input을 보존하지 않는다."""

    raise ValidationError.from_exception_data(
        "Settings",
        [
            {
                "type": "value_error",
                "loc": (),
                "input": "<redacted>",
                "ctx": {"error": ValueError(message)},
            }
        ],
    )


def _service_provenance_text() -> str:
    packaged = files("app").joinpath(_PACKAGED_SERVICE_PROVENANCE_PATH)
    if packaged.is_file():
        return packaged.read_text(encoding="utf-8")

    for directory in Path(__file__).resolve().parents:
        candidate = directory / "contracts" / _SERVICE_PROVENANCE_FILENAME
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise RuntimeError(f"Map service provenance file is missing: {_SERVICE_PROVENANCE_FILENAME}")


def _m05_pair_provenance_text() -> str:
    packaged = files("app").joinpath(_PACKAGED_M05_PAIR_PROVENANCE_PATH)
    if packaged.is_file():
        return packaged.read_text(encoding="utf-8")

    for directory in Path(__file__).resolve().parents:
        candidate = directory / "contracts" / _M05_PAIR_PROVENANCE_FILENAME
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise RuntimeError(f"Map M05 pair provenance file is missing: {_M05_PAIR_PROVENANCE_FILENAME}")


def _m05_activation_trust_text() -> str:
    packaged = files("app").joinpath(f"_contract_data/{_M05_ACTIVATION_TRUST_FILENAME}")
    if packaged.is_file():
        return packaged.read_text(encoding="utf-8")

    for directory in Path(__file__).resolve().parents:
        candidate = directory / "contracts" / _M05_ACTIVATION_TRUST_FILENAME
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise RuntimeError(
        f"M05 activation trust anchor file is missing: {_M05_ACTIVATION_TRUST_FILENAME}"
    )


def _m05_reviewer_roster_text() -> str:
    packaged = files("app").joinpath(f"_contract_data/{_M05_REVIEWER_ROSTER_FILENAME}")
    if packaged.is_file():
        return packaged.read_text(encoding="utf-8")

    for directory in Path(__file__).resolve().parents:
        candidate = directory / "contracts" / _M05_REVIEWER_ROSTER_FILENAME
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise RuntimeError(f"M05 reviewer roster file is missing: {_M05_REVIEWER_ROSTER_FILENAME}")


def _required_string(payload: dict[str, object], field: str, pattern: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise RuntimeError(f"Map service provenance {field} is invalid")
    return value


def _capability_generation(capabilities: dict[str, object], name: str) -> int:
    capability = capabilities.get(name)
    if not isinstance(capability, dict):
        raise RuntimeError(f"Map service provenance capability {name} is missing")
    generation = capability.get("generation")
    if type(generation) is not int or generation < 1:
        raise RuntimeError(f"Map service provenance capability {name} generation is invalid")
    return generation


def _validate_production_map_root_url(value: str, *, env_name: str) -> None:
    try:
        base_url = urlsplit(value)
        hostname = base_url.hostname
        port = base_url.port
    except ValueError as exc:
        raise ValueError(
            f"production {env_name} must be an allowed root HTTP(S) URL on port 12701"
        ) from exc
    if (
        base_url.scheme not in {"http", "https"}
        or hostname not in {"127.0.0.1", "host.docker.internal"}
        or port != 12701
        or base_url.path not in {"", "/"}
        or base_url.username is not None
        or base_url.password is not None
        or bool(base_url.query)
        or bool(base_url.fragment)
    ):
        raise ValueError(f"production {env_name} must be an allowed root HTTP(S) URL on port 12701")


def _load_service_provenance() -> tuple[str, str, int, int, int, int, int]:
    raw = json.loads(_service_provenance_text(), object_pairs_hook=_reject_duplicate_json_keys)
    if not isinstance(raw, dict):
        raise RuntimeError("Map service provenance must be an object")
    payload = cast(dict[str, object], raw)
    if set(payload) != {
        "capabilities",
        "map_release_revision",
        "service_openapi_sha256",
        "version",
    }:
        raise RuntimeError("Map service provenance fields are invalid")
    if type(payload["version"]) is not int or payload["version"] != 1:
        raise RuntimeError("Map service provenance version is unsupported")
    capabilities_value = payload["capabilities"]
    if not isinstance(capabilities_value, dict):
        raise RuntimeError("Map service provenance capabilities are invalid")
    capabilities = cast(dict[str, object], capabilities_value)
    if set(capabilities) != {
        "cache_target",
        "c6c_cancel_probe",
        "curation_snapshot",
        "feature_request",
        "feature_reference_reconciliation",
    }:
        raise RuntimeError("Map service provenance capability inventory is invalid")
    return (
        _required_string(payload, "service_openapi_sha256", r"[0-9a-f]{64}"),
        _required_string(payload, "map_release_revision", r"[0-9a-f]{40}"),
        _capability_generation(capabilities, "cache_target"),
        _capability_generation(capabilities, "c6c_cancel_probe"),
        _capability_generation(capabilities, "curation_snapshot"),
        _capability_generation(capabilities, "feature_request"),
        _capability_generation(capabilities, "feature_reference_reconciliation"),
    )


#: v1 봉투는 Map revision과 runtime image digest를 **스스로 선언**한다. 그 선언이 pin
#: registry의 선언과 겹쳐서, Map이 한 줄만 바뀌어도 PinVi 커밋이 강제됐다 — 2026-09-01
#: 이후 재핀 12건 전부가 rebuild를 끌고 왔고 그중 10건은 상류 OpenAPI가 바이트 동일했다
#: (`AGENTS.md` DO NOT 15 이중 선언). v2는 그 두 필드를 걷어내고 생산자를 pin registry
#: 하나로 둔다.
_M05_PAIR_V1_ENVELOPE_KEYS = {"map", "runtime_image_digests", "version"}
_M05_PAIR_V2_ENVELOPE_KEYS = {"map", "version"}
_M05_PAIR_V1_ENTRY_KEYS = {
    "openapi_sha256",
    "runtime_operation_contract_sha256",
    "source_canonical_sha256",
    "source_operation_contract_sha256",
    "source_revision",
}
_M05_PAIR_V2_ENTRY_KEYS = _M05_PAIR_V1_ENTRY_KEYS - {"source_revision"}


def _load_m05_pair_provenance() -> tuple[
    dict[str, tuple[str, str | None, str, str]],
    dict[str, str],
    dict[str, dict[str, str]],
    int,
]:
    """v1·v2 봉투를 모두 읽는다.

    v2에서는 surface의 `source_revision`과 최상위 `runtime_image_digests`가 없다. 그
    자리를 **조용히 비우지 않는다** — 튜플 자리에는 `None`을 두고, 그 값을 실제로
    쓰는 활성화 경로는 무엇을 배선해야 하는지 이름을 대며 fail-close한다. 조용히
    건너뛰면 v2가 검사를 통과시키는 것처럼 보이기 때문이다.
    """

    raw = json.loads(_m05_pair_provenance_text(), object_pairs_hook=_reject_duplicate_json_keys)
    if not isinstance(raw, dict) or type(raw.get("version")) is not int:
        raise RuntimeError("Map M05 pair provenance envelope is invalid")
    version = raw["version"]
    if version == 1:
        expected_envelope = _M05_PAIR_V1_ENVELOPE_KEYS
        expected_entry = _M05_PAIR_V1_ENTRY_KEYS
    elif version == 2:
        expected_envelope = _M05_PAIR_V2_ENVELOPE_KEYS
        expected_entry = _M05_PAIR_V2_ENTRY_KEYS
    else:
        raise RuntimeError("Map M05 pair provenance envelope is invalid")
    if set(raw) != expected_envelope:
        raise RuntimeError("Map M05 pair provenance envelope is invalid")
    map_value = raw["map"]
    if not isinstance(map_value, dict) or set(map_value) != {"admin", "full", "service", "user"}:
        raise RuntimeError("Map M05 pair provenance inventory is invalid")

    runtime_image_digests: dict[str, str] = {}
    if version == 1:
        runtime_images = raw["runtime_image_digests"]
        if not isinstance(runtime_images, dict) or set(runtime_images) != {
            "admin",
            "api",
            "frontend",
        }:
            raise RuntimeError("Map M05 runtime image digest inventory is invalid")
        runtime_image_digests = {
            name: _required_string(runtime_images, name, r"sha256:[0-9a-f]{64}")
            for name in ("admin", "api", "frontend")
        }

    result: dict[str, tuple[str, str | None, str, str]] = {}
    details: dict[str, dict[str, str]] = {}
    for name in ("admin", "full", "service", "user"):
        entry = map_value[name]
        if not isinstance(entry, dict) or set(entry) != expected_entry:
            raise RuntimeError(f"Map M05 pair provenance entry is invalid: {name}")
        openapi_sha256 = _required_string(entry, "openapi_sha256", r"[0-9a-f]{64}")
        runtime_operation_contract_sha256 = _required_string(
            entry, "runtime_operation_contract_sha256", r"[0-9a-f]{64}"
        )
        source_canonical_sha256 = _required_string(
            entry, "source_canonical_sha256", r"[0-9a-f]{64}"
        )
        source_operation_contract_sha256 = _required_string(
            entry, "source_operation_contract_sha256", r"[0-9a-f]{64}"
        )
        source_revision = (
            _required_string(entry, "source_revision", r"[0-9a-f]{40}") if version == 1 else None
        )
        result[name] = (
            openapi_sha256,
            source_revision,
            source_canonical_sha256,
            runtime_operation_contract_sha256,
        )
        details[name] = {
            "source_canonical_sha256": source_canonical_sha256,
            "source_operation_contract_sha256": source_operation_contract_sha256,
            "runtime_operation_contract_sha256": runtime_operation_contract_sha256,
        }
    return result, runtime_image_digests, details, version


def _load_m05_activation_public_key_sha256() -> str:
    raw = json.loads(_m05_activation_trust_text(), object_pairs_hook=_reject_duplicate_json_keys)
    if (
        not isinstance(raw, dict)
        or set(raw) != {"public_key_sha256", "reviewer_roster_sha256", "version"}
        or type(raw["version"]) is not int
        or raw["version"] != 1
    ):
        raise RuntimeError("M05 activation trust anchor envelope is invalid")
    return _required_string(raw, "public_key_sha256", r"[0-9a-f]{64}")


def _load_m05_reviewer_agent_ids() -> frozenset[str]:
    raw = json.loads(_m05_reviewer_roster_text(), object_pairs_hook=_reject_duplicate_json_keys)
    if (
        not isinstance(raw, dict)
        or set(raw) != {"agent_ids", "public_keys", "version"}
        or type(raw["version"]) is not int
        or raw["version"] != 2
        or not isinstance(raw["agent_ids"], list)
        or len(raw["agent_ids"]) != 2
    ):
        raise RuntimeError("M05 reviewer roster envelope is invalid")
    result: set[str] = set()
    for agent_id in raw["agent_ids"]:
        if not isinstance(agent_id, str):
            raise RuntimeError("M05 reviewer roster agent ID is invalid")
        try:
            if str(UUID(agent_id)) != agent_id:
                raise ValueError
        except ValueError as exc:
            raise RuntimeError("M05 reviewer roster agent ID is invalid") from exc
        result.add(agent_id)
    if len(result) != 2:
        raise RuntimeError("M05 reviewer roster agents are not distinct")
    public_keys = raw["public_keys"]
    if (
        not isinstance(public_keys, dict)
        or set(public_keys) != result
        or any(
            _decode_canonical_reviewer_public_key(value) is None for value in public_keys.values()
        )
    ):
        raise RuntimeError("M05 reviewer roster public keys are invalid")
    trust = json.loads(_m05_activation_trust_text(), object_pairs_hook=_reject_duplicate_json_keys)
    if (
        not isinstance(trust, dict)
        or not isinstance(trust.get("reviewer_roster_sha256"), str)
        or hashlib.sha256(_m05_reviewer_roster_text().encode("utf-8")).hexdigest()
        != trust["reviewer_roster_sha256"]
    ):
        raise RuntimeError("M05 reviewer roster is not bound to the activation trust anchor")
    return frozenset(result)


(
    KOR_TRAVEL_MAP_SERVICE_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_SERVICE_RELEASE_REVISION,
    KOR_TRAVEL_MAP_CACHE_TARGET_CAPABILITY_GENERATION,
    KOR_TRAVEL_MAP_C6C_CANCEL_PROBE_CAPABILITY_GENERATION,
    KOR_TRAVEL_MAP_CURATION_SNAPSHOT_CAPABILITY_GENERATION,
    KOR_TRAVEL_MAP_FEATURE_REQUEST_CAPABILITY_GENERATION,
    KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_CAPABILITY_GENERATION,
) = _load_service_provenance()
(
    _M05_MAP_PAIR_PROVENANCE,
    _M05_MAP_RUNTIME_IMAGE_DIGESTS,
    _M05_MAP_PAIR_DETAILS,
    _M05_MAP_PAIR_ENVELOPE_VERSION,
) = _load_m05_pair_provenance()
PINVI_M05_ACTIVATION_RECEIPT_PUBLIC_KEY_SHA256 = _load_m05_activation_public_key_sha256()
PINVI_M05_REVIEWER_AGENT_IDS = _load_m05_reviewer_agent_ids()
if _M05_MAP_PAIR_PROVENANCE["service"][0] != KOR_TRAVEL_MAP_SERVICE_OPENAPI_SHA256 or (
    # v2 계약은 revision을 선언하지 않는다 — 그 대조는 pin registry가 소유한다.
    _M05_MAP_PAIR_ENVELOPE_VERSION == 1
    and _M05_MAP_PAIR_PROVENANCE["service"][1] != KOR_TRAVEL_MAP_SERVICE_RELEASE_REVISION
):
    raise RuntimeError("Map M05 pair service provenance does not match the service provenance")
(
    KOR_TRAVEL_MAP_M05_ADMIN_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_M05_ADMIN_SOURCE_REVISION,
) = _M05_MAP_PAIR_PROVENANCE["admin"][:2]
(
    KOR_TRAVEL_MAP_M05_FULL_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_M05_FULL_SOURCE_REVISION,
) = _M05_MAP_PAIR_PROVENANCE["full"][:2]
(
    KOR_TRAVEL_MAP_M05_USER_OPENAPI_SHA256,
    KOR_TRAVEL_MAP_M05_USER_SOURCE_REVISION,
) = _M05_MAP_PAIR_PROVENANCE["user"][:2]
KOR_TRAVEL_MAP_M05_ADMIN_SOURCE_CANONICAL_SHA256 = _M05_MAP_PAIR_DETAILS["admin"][
    "source_canonical_sha256"
]
KOR_TRAVEL_MAP_M05_FULL_SOURCE_CANONICAL_SHA256 = _M05_MAP_PAIR_DETAILS["full"][
    "source_canonical_sha256"
]
KOR_TRAVEL_MAP_M05_USER_SOURCE_CANONICAL_SHA256 = _M05_MAP_PAIR_DETAILS["user"][
    "source_canonical_sha256"
]
KOR_TRAVEL_MAP_M05_SERVICE_SOURCE_CANONICAL_SHA256 = _M05_MAP_PAIR_DETAILS["service"][
    "source_canonical_sha256"
]
KOR_TRAVEL_MAP_M05_ADMIN_SOURCE_OPERATION_CONTRACT_SHA256 = _M05_MAP_PAIR_DETAILS["admin"][
    "source_operation_contract_sha256"
]
KOR_TRAVEL_MAP_M05_FULL_SOURCE_OPERATION_CONTRACT_SHA256 = _M05_MAP_PAIR_DETAILS["full"][
    "source_operation_contract_sha256"
]
KOR_TRAVEL_MAP_M05_SERVICE_SOURCE_OPERATION_CONTRACT_SHA256 = _M05_MAP_PAIR_DETAILS["service"][
    "source_operation_contract_sha256"
]
KOR_TRAVEL_MAP_M05_USER_SOURCE_OPERATION_CONTRACT_SHA256 = _M05_MAP_PAIR_DETAILS["user"][
    "source_operation_contract_sha256"
]
KOR_TRAVEL_MAP_M05_ADMIN_RUNTIME_OPERATION_CONTRACT_SHA256 = _M05_MAP_PAIR_DETAILS["admin"][
    "runtime_operation_contract_sha256"
]
KOR_TRAVEL_MAP_M05_FULL_RUNTIME_OPERATION_CONTRACT_SHA256 = _M05_MAP_PAIR_DETAILS["full"][
    "runtime_operation_contract_sha256"
]
KOR_TRAVEL_MAP_M05_SERVICE_RUNTIME_OPERATION_CONTRACT_SHA256 = _M05_MAP_PAIR_DETAILS["service"][
    "runtime_operation_contract_sha256"
]
KOR_TRAVEL_MAP_M05_USER_RUNTIME_OPERATION_CONTRACT_SHA256 = _M05_MAP_PAIR_DETAILS["user"][
    "runtime_operation_contract_sha256"
]
KOR_TRAVEL_MAP_M05_ADMIN_IMAGE_DIGEST = _M05_MAP_RUNTIME_IMAGE_DIGESTS.get("admin")
KOR_TRAVEL_MAP_M05_API_IMAGE_DIGEST = _M05_MAP_RUNTIME_IMAGE_DIGESTS.get("api")
KOR_TRAVEL_MAP_M05_FRONTEND_IMAGE_DIGEST = _M05_MAP_RUNTIME_IMAGE_DIGESTS.get("frontend")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,
    )

    _m05_runtime_dependencies: dict[str, object] = PrivateAttr(default_factory=dict)
    _m05_runtime_endpoints: dict[str, object] = PrivateAttr(default_factory=dict)
    _m05_runtime_attestation_sha256: str = PrivateAttr(default="")
    _m05_runtime_dependency_snapshot_sha256: str = PrivateAttr(default="")
    _m05_runtime_lease_verifier: M05RuntimeLeaseVerifier | None = PrivateAttr(default=None)

    def __init__(self, **data: Any) -> None:
        """설정 검증 오류의 input 필드에서 SecretStr 원문을 제거한다."""

        try:
            super().__init__(**data)
        except ValidationError as exc:
            redacted_errors: list[dict[str, Any]] = [
                {
                    "type": "value_error",
                    "loc": error.get("loc", ()),
                    "input": "<redacted>",
                    "ctx": {
                        "error": ValueError(str(error.get("msg", "settings validation failed")))
                    },
                }
                for error in exc.errors()
            ]
            raise ValidationError.from_exception_data(
                "Settings", cast(Any, redacted_errors)
            ) from exc

    # 환경
    pinvi_environment: PinviEnvironment = "development"

    # Database
    pinvi_database_url: str = Field(
        default="postgresql+asyncpg://pinvi:pinvi_dev_password@localhost:5432/pinvi"
    )
    pinvi_database_pool_size: int = 10

    # JWT / 세션
    pinvi_jwt_secret_key: str = Field(default="pinvi-local-jwt-secret-change-me", min_length=32)
    pinvi_access_token_minutes: int = 10
    pinvi_refresh_token_days: int = 7
    pinvi_admin_session_ttl: int = 3600
    pinvi_mcp_jwt_secret: str = Field(default="pinvi-local-mcp-secret-change-me", min_length=32)
    pinvi_mcp_token_default_days: int = 30
    pinvi_mcp_rate_limit_per_minute: int = 60

    # Resend
    pinvi_resend_api_key: str = ""
    pinvi_resend_api_base_url: str = "https://api.resend.com"
    pinvi_resend_from_email: str = "Pinvi <noreply@send.pinvi.local>"
    pinvi_resend_timeout_seconds: int = 5
    pinvi_resend_webhook_secret: str = ""
    pinvi_resend_webhook_allow_unsigned: bool = False
    pinvi_email_outbox_worker_enabled: bool = True
    pinvi_email_outbox_drain_interval_seconds: float = 5.0
    pinvi_email_outbox_batch_size: int = 50
    # 미인증 로그인/재발송 요청 시 가입 인증 메일 재발송 최소 간격(초). 같은 사용자 중복 발송 방지.
    pinvi_email_verification_resend_cooldown_seconds: int = 60
    pinvi_web_base_url: str = "http://localhost:12805"
    pinvi_dagster_base_url: str = "http://localhost:12802"
    pinvi_email_verification_path: str = "/verify-email"
    pinvi_auth_reset_path: str = Field(
        default="/reset-password",
        validation_alias="PINVI_PASSWORD_RESET_PATH",
    )

    # OAuth (Sprint 2부터 실제 사용)
    pinvi_google_oauth_client_id: str = ""
    pinvi_google_oauth_client_secret: str = ""
    pinvi_naver_oauth_client_id: str = ""
    pinvi_naver_oauth_client_secret: str = ""
    pinvi_kakao_oauth_rest_api_key: str = ""
    pinvi_kakao_oauth_client_secret: str = ""
    pinvi_oauth_callback_base_url: str = "http://localhost:12801"

    # 외부 장소 provider(표시 전용, ADR-054 / docs/integrations/kakao-naver-local.md)
    # Kakao Local은 기존 OAuth REST 키(pinvi_kakao_oauth_rest_api_key)를 재사용한다(신규 키 없음).
    pinvi_kakao_local_enabled: bool = True
    pinvi_kakao_local_base_url: str = "https://dapi.kakao.com"
    # Naver Local은 OAuth 로그인용과 다른 검색 API 전용 앱 credential(SecretStr).
    pinvi_naver_local_enabled: bool = True
    pinvi_naver_local_base_url: str = "https://openapi.naver.com"
    pinvi_naver_search_client_id: SecretStr = SecretStr("")
    pinvi_naver_search_client_secret: SecretStr = SecretStr("")
    # 공통 전송/보강 정책
    pinvi_place_provider_timeout_seconds: float = 2.5
    pinvi_place_provider_max_attempts: int = 2
    # K: 내부 결과(feature+my_poi+address)가 이 수 미만일 때만 Kakao/Naver를 호출한다.
    pinvi_place_search_internal_threshold: int = 5
    pinvi_place_search_cache_ttl_seconds: int = 60
    pinvi_oauth_state_ttl_seconds: int = 600
    pinvi_oauth_http_timeout_seconds: int = 5
    # 모바일 OAuth: callback이 이 앱 딥링크로 1회용 code를 실어 리다이렉트한다(ADR-044/032).
    pinvi_mobile_oauth_redirect: str = "pinvi://oauth"
    pinvi_mobile_oauth_exchange_ttl_seconds: int = 120

    # RustFS (S3 호환 객체 저장소)
    pinvi_rustfs_endpoint_url: str = "http://localhost:12101"
    pinvi_rustfs_public_endpoint_url: str = "http://127.0.0.1:12101"
    pinvi_rustfs_bucket: str = "pinvi-media"
    pinvi_rustfs_access_key_id: str = "rustfsadmin"
    pinvi_rustfs_secret_access_key: str = "rustfsadmin"  # noqa: S105 - 로컬 dev 기본값
    pinvi_rustfs_presigned_url_expires_seconds: int = 900
    pinvi_rustfs_max_upload_bytes: int = 10_485_760
    pinvi_rustfs_allowed_content_types: list[str] = Field(
        default_factory=lambda: [
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/gif",
            "video/mp4",
            "application/pdf",
        ]
    )
    pinvi_rustfs_public_base_url: str = ""
    # Trip/POI 첨부 개수 상한(남용 방지, T-105)
    pinvi_max_attachments_per_target: int = 30

    # kor-travel-map 독립 프로그램 (지도 feature OpenAPI HTTP, ADR-026/027)
    # `docs/integrations/kor-travel-map-rest-api.md` §1 — 전 표면 API/Admin API :12701.
    pinvi_kor_travel_map_api_base_url: str = "http://localhost:12701"
    # admin feature change(`/v1/admin/features*`, T-180)도 같은 호스트 :12701.
    pinvi_kor_travel_map_admin_base_url: str = "http://localhost:12701"
    # 인증은 인프라 계층(reverse proxy / IP allowlist). 설정 시 X-Kor-Travel-Map-Service-Token 전달.
    pinvi_kor_travel_map_service_token: str = ""
    # public REST의 X-Kor-Travel-Map-Api-Key header. 미설정 시 PINVI_VWORLD_API_KEY 사용.
    pinvi_kor_travel_map_public_api_key: str = ""
    # admin-path 전용 서비스 토큰(미설정 시 공용 service token fallback).
    # §7 확정(kor_travel_map T-217c): 운영 인증은 인프라 계층(SSO/IP allowlist) — token은 선택 pass-through.
    pinvi_kor_travel_map_admin_service_token: str = ""
    # kor-travel-map ADR-060: admin proxy gate가 켜진 운영 API에는 secret + actor 헤더가 필요.
    pinvi_kor_travel_map_admin_proxy_secret: str = ""
    pinvi_kor_travel_map_admin_actor: str = "pinvi-admin"
    # 범용 Feature 요청 큐 write 전용 principal. admin/public/general service token fallback 금지.
    kor_travel_map_feature_request_token: SecretStr | None = None
    # canonical /v1/ops/datasets*·/v1/ops/pipeline* 전용 server principal.
    # read/cancel 자격을 분리하고 요청 actor 대신 map 서버의 고정 actor를 사용한다.
    pinvi_kor_travel_map_ops_read_token: SecretStr | None = None
    pinvi_kor_travel_map_ops_cancel_token: SecretStr | None = None
    # canonical curation collection/item snapshot read 전용 exact-scope credential.
    # admin/service/cache-target token으로 fallback하지 않는다.
    pinvi_kor_travel_map_curation_snapshot_token: SecretStr | None = None
    # T-VN-40C maintenance fence에서 legacy identity→canonical UUID mapping만 읽는 별도 principal.
    # snapshot read token과 공유하면 Map이 403으로 fail-close한다.
    pinvi_kor_travel_map_curation_cutover_mapping_token: SecretStr | None = None
    pinvi_kor_travel_map_timeout_seconds: float = Field(
        default=5.0,
        gt=0,
        allow_inf_nan=False,
    )
    pinvi_kor_travel_map_max_attempts: int = 3
    pinvi_kor_travel_map_batch_chunk_size: int = Field(
        default=200,
        ge=1,
        le=200,
    )  # /v1/features/batch cap

    # cache target generation/outbox paired worker (ADR-058). false여도 DB projection은 계속된다.
    pinvi_kor_travel_map_cache_target_sync_enabled: bool = False
    pinvi_kor_travel_map_cache_target_command_token: SecretStr | None = None
    pinvi_kor_travel_map_cache_target_consumer_token: SecretStr | None = None
    # restore/recovery job 전용이며 ordinary API runtime에는 주입하지 않는다.
    pinvi_kor_travel_map_cache_target_restore_fence_token: SecretStr | None = None
    pinvi_kor_travel_map_cache_target_recovery_token: SecretStr | None = None
    pinvi_kor_travel_map_cache_target_consumer_id: str = Field(
        default="pinvi-cache-target-consumer", min_length=1, max_length=64
    )
    pinvi_kor_travel_map_cache_target_batch_size: int = Field(default=100, ge=1, le=500)
    pinvi_kor_travel_map_cache_target_lease_seconds: int = Field(default=60, ge=10, le=300)
    pinvi_kor_travel_map_cache_target_poll_seconds: float = Field(
        default=1.0,
        ge=0.1,
        le=60,
        allow_inf_nan=False,
    )
    pinvi_kor_travel_map_cache_target_max_attempts: int = Field(default=5, ge=1, le=20)
    # paired OpenAPI가 확정될 때 배포 manifest가 exact 값을 넣는다. source revision은 vendored artifact
    # owner provenance이며 배포 이미지/Map /version revision이 아니다. 빈 값으로 enable할 수 없다.
    pinvi_kor_travel_map_cache_target_expected_openapi_sha256: str = ""
    pinvi_kor_travel_map_cache_target_expected_source_revision: str = ""
    pinvi_kor_travel_map_cache_target_expected_contract_generation: int | None = Field(
        default=None, gt=0
    )

    # T-VN-M05 Map retire event의 first paired consumer. worker와 service scope는
    # default-off이며 subscription activation/live proof 전 production enable을 거부한다.
    pinvi_kor_travel_map_feature_reference_reconciliation_enabled: bool = False
    pinvi_kor_travel_map_feature_reference_reconciliation_read_token: SecretStr | None = None
    pinvi_kor_travel_map_feature_reference_reconciliation_ack_token: SecretStr | None = None
    pinvi_kor_travel_map_feature_reference_reconciliation_poll_seconds: float = Field(
        default=1.0,
        ge=0.1,
        le=60,
        allow_inf_nan=False,
    )
    pinvi_kor_travel_map_feature_reference_reconciliation_blocked_recheck_seconds: float = Field(
        default=30.0,
        ge=1.0,
        le=3600.0,
        allow_inf_nan=False,
    )
    pinvi_kor_travel_map_feature_reference_reconciliation_expected_openapi_sha256: str = ""
    pinvi_kor_travel_map_feature_reference_reconciliation_expected_source_revision: str = ""
    # production enable은 paired live/restore/review evidence를 담은 immutable receipt가 있어야 한다.
    pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt: SecretStr | None = (
        None
    )
    # container ID가 receipt payload에 결박되므로 재생성 없는 bind-mounted receipt 경로를 지원한다.
    pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt_path: str = ""
    pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt_public_key: str = ""
    # receipt nonce/generation의 root-owned append-only ledger. staging/production enable 시 필수다.
    pinvi_m05_activation_ledger_path: str = ""
    # ledger와 분리된 root-owned high-watermark. 같은 generation의 다른 receipt replay도 거부한다.
    pinvi_m05_activation_high_watermark_path: str = ""
    # ledger/high-watermark와 분리된 root-owned monotonic floor. 함께 복원된 과거 snapshot을 거부한다.
    pinvi_m05_activation_durable_floor_path: str = ""
    # DB snapshot과 함께 복원되지 않는 별도 append-only monotonic history.
    pinvi_m05_activation_durable_history_path: str = ""
    # ledger snapshot과 분리된 외부 monotonic anchor. 운영에서는 별도 durable mount를 사용한다.
    pinvi_m05_activation_durable_anchor_path: str = ""
    # receipt가 봉인된 작업의 정본 PR URL.
    pinvi_m05_activation_pr_url: str = _M05_ACTIVATION_PR_URL
    # 배포자가 승인한 ledger generation. 이 값보다 낮은 receipt rollback은 거부한다.
    pinvi_m05_activation_min_generation: int = Field(default=1, ge=1)
    # immutable deploy wrapper가 대조한 세 Pinvi runtime image digest를 API에만 전달한다.
    pinvi_api_image_digest: str = ""
    pinvi_web_image_digest: str = ""
    pinvi_dagster_image_digest: str = ""
    # receipt와 같은 private key로 서명한 fresh dependency runtime snapshot.
    pinvi_m05_runtime_attestation_path: str = ""
    # root host watcher가 별도 Ed25519 key로 발급하는 120초 이하 runtime lease directory.
    # ordinary API에는 public trust/current lease만 read-only mount하며 signer/Docker socket은 주지 않는다.
    pinvi_m05_runtime_lease_directory: str = ""
    pinvi_m05_runtime_lease_max_lifetime_seconds: int = Field(default=120, ge=1, le=120)

    # kor-travel-geo v2 REST (geocoding/주소/행정구역, ADR-025) — `docs/integrations/kor-travel-geo.md`.
    pinvi_kor_travel_geo_base_url: str = "http://localhost:12501"
    pinvi_kor_travel_geo_timeout_seconds: float = 5.0
    pinvi_kor_travel_geo_max_attempts: int = 3

    # VWorld 지도 키 (ADR-043/048) — 웹은 빌드타임 NEXT_PUBLIC_VWORLD_API_KEY를 쓰지만,
    # 모바일 앱(`apps/mobile`)은 키를 번들하지 않고 GET /mobile/vworld/token 으로 인증 후
    # server-issued 키를 발급받는다(키 미설정 시 endpoint는 503). 같은 값이 kor-travel-geo
    # v2 REST의 공개 API `key` query로도 쓰이며, 별도 geo API key 설정은 두지 않는다.
    pinvi_vworld_api_key: str = ""
    pinvi_vworld_token_ttl_seconds: int = 600

    # Telegram Bot 알림 (T-106) — `docs/integrations/telegram.md`.
    # bot token 원본은 DB 저장 X(§1), 로그는 mask_token으로만(§9).
    pinvi_telegram_api_base: str = "https://api.telegram.org"
    pinvi_telegram_timeout_seconds: float = 5.0
    pinvi_telegram_bot_token_default: str = ""  # 시스템/Admin 봇
    pinvi_telegram_admin_chat_id: str = ""
    # outbox drain worker (§8)
    pinvi_telegram_outbox_worker_enabled: bool = True
    pinvi_telegram_outbox_drain_interval_seconds: float = 5.0
    pinvi_telegram_outbox_batch_size: int = 50

    # 위치 감사 async outbox drain worker (T-146 / D-20)
    pinvi_location_audit_outbox_worker_enabled: bool = True
    pinvi_location_audit_outbox_drain_interval_seconds: float = 1.0
    pinvi_location_audit_outbox_batch_size: int = 200

    # Retention execution kill-switch (T-276). Dry-run은 항상 허용, execute는 운영에서 명시적으로 연다.
    pinvi_retention_execute_enabled: bool = False
    pinvi_retention_execute_confirm_phrase: str = "EXECUTE RETENTION"

    # Feature 조회 process-local TTL 캐시 (T-146 / D-26)
    pinvi_feature_cache_enabled: bool = True
    pinvi_feature_cache_ttl_seconds: float = 60.0
    pinvi_feature_cache_max_size: int = 10000

    # CORS
    pinvi_cors_allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:12805", "http://127.0.0.1:12805"]
    )

    # Geofencing (ADR-018) — 기본은 비활성, 운영에서 3차 fallback으로 활성.
    pinvi_geofence_enabled: bool = False
    pinvi_geofence_allowed_countries: list[str] = Field(default_factory=lambda: ["KR"])
    pinvi_geofence_country_header: str = "CF-IPCountry"
    pinvi_geofence_trusted_proxy_header: str = "X-Pinvi-Geofence-Proxy"
    pinvi_geofence_trusted_proxy_secret: str = ""
    pinvi_geofence_trusted_proxy_cidrs: list[str] = Field(default_factory=list)
    pinvi_geofence_mtls_verified_header: str = ""
    pinvi_geofence_mtls_verified_value: str = "SUCCESS"
    pinvi_geofence_block_unknown: bool = False
    pinvi_geofence_bypass_paths: list[str] = Field(
        default_factory=lambda: [
            "/health",
            "/health/db",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
        ]
    )

    # HTTP rate limit (ADR-038 / T-195). backend=auto uses Postgres in production/staging
    # and process-local memory in development/test/smoke.
    pinvi_rate_limit_enabled: bool = True
    pinvi_rate_limit_backend: str = "auto"  # auto | memory | postgres
    pinvi_rate_limit_fail_open: bool = False
    pinvi_rate_limit_window_seconds: int = 60
    pinvi_rate_limit_public_per_minute: int = 60
    pinvi_rate_limit_authenticated_per_minute: int = 60
    pinvi_rate_limit_auth_per_minute: int = 5
    pinvi_rate_limit_oauth_per_minute: int = 10
    pinvi_rate_limit_storage_upload_per_minute: int = 30
    pinvi_rate_limit_feature_search_per_minute: int = 60
    pinvi_rate_limit_trip_export_per_minute: int = 20
    pinvi_rate_limit_shared_token_per_minute: int = 60
    pinvi_rate_limit_body_peek_max_bytes: int = 65_536
    pinvi_rate_limit_client_ip_header: str = ""
    pinvi_rate_limit_bypass_paths: list[str] = Field(
        default_factory=lambda: [
            "/health",
            "/health/db",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
        ]
    )

    # WebSocket safety guard (ADR-035)
    pinvi_ws_client_rate_per_second: int = 5
    pinvi_ws_client_rate_per_minute: int = 60
    pinvi_ws_rate_limit_close_grace_seconds: float = 30.0
    pinvi_ws_max_connections_per_trip: int = 10
    pinvi_ws_max_connections_total: int = 200
    pinvi_ws_send_timeout_seconds: float = 2.0
    # handshake-time reject(accept→close) 사이 settle. 101 upgrade를 별도 backend write로
    # flush해 close code가 리버스 프록시 edge를 건너 살아남게 한다(미적용 시 브라우저가
    # 4401/4403 등 대신 1006을 관측 — kor-travel-map C7 #809/#820과 동일 계층 문제). 0..5s.
    pinvi_ws_handshake_close_settle_seconds: float = 0.25
    # settle은 accept 이후(cap/rate-limit 이전) 소켓을 잠깐 붙잡으므로, 미인증 reject flood가
    # settle로 FD를 증폭하지 못하게 동시 settle 수를 cap한다(초과분은 settle 없이 즉시 닫음).
    # 0이면 무제한. 정상 reject는 저volume이라 항상 cap 안에 든다.
    pinvi_ws_max_concurrent_reject_settles: int = 64

    # Sentry
    pinvi_sentry_dsn: str = ""
    pinvi_sentry_environment: str = "development"
    pinvi_sentry_release: str = ""
    pinvi_sentry_traces_sample_rate: float = 0.1
    pinvi_sentry_profiles_sample_rate: float = 0.0

    # Prometheus metrics (Sprint 5 observability)
    pinvi_prometheus_metrics_enabled: bool = True
    pinvi_prometheus_metrics_path: str = "/metrics"
    pinvi_prometheus_exclude_paths: list[str] = Field(
        default_factory=lambda: ["/health", "/health/db", "/metrics"]
    )

    # Admin system view (T-222) — Docker Engine read API collector. The socket is not
    # mounted by default in compose; missing/denied access is reported as unknown/down.
    pinvi_docker_socket_path: str = "/var/run/docker.sock"
    pinvi_docker_status_timeout_seconds: float = 2.0
    pinvi_docker_status_container_limit: int = 80
    # Signed M05 runtime attestation is the in-container source of truth. A live
    # Docker inspection, when explicitly enabled for a host-side maintenance
    # process, must never be enabled by the ordinary API compose service.
    pinvi_m05_runtime_live_check: bool = False

    # Backup / Restore (ADR-022)
    pinvi_backup_dir: str = ".tmp/backups"
    pinvi_backup_script_path: str = "scripts/backup-db.sh"
    pinvi_restore_script_path: str = "scripts/restore-db.sh"
    pinvi_restore_hotswap_script_path: str = "scripts/restore-hotswap.sh"
    pinvi_backup_timeout_seconds: int = 900
    pinvi_restore_timeout_seconds: int = 3600
    pinvi_backup_schema: str = "app"
    pinvi_backup_min_free_bytes: int = 1_073_741_824
    pinvi_restore_database_url: str = ""
    # Schema swap의 DB-level CONNECT fence에만 쓰는 target database owner URL.
    pinvi_restore_fence_database_url: str = ""
    pinvi_restore_hotswap_execute: bool = False
    # 운영 API restore는 canonical hotswap runner의 content digest를 배포 시 고정한다.
    pinvi_restore_hotswap_script_sha256: str = ""
    pinvi_restore_drain_command: str = ""
    pinvi_restore_allow_no_drain: bool = False
    # API-triggered swap은 외부 orchestrator가 write fence를 확인한 경우에만 허용한다.
    pinvi_restore_drain_verified: bool = False
    pinvi_restore_app_role: str = ""

    # Feature flag
    pinvi_enable_seed: bool = False

    @model_validator(mode="after")
    def validate_restore_executor_boundary(self) -> Self:
        """운영 API에는 schema-swap 실행 권한을 주지 않는다."""

        if self.pinvi_environment not in _STRICT_RESTORE_EXECUTOR_ENVIRONMENTS:
            return self
        forbidden: list[str] = []
        if self.pinvi_restore_database_url:
            forbidden.append("PINVI_RESTORE_DATABASE_URL")
        if self.pinvi_restore_fence_database_url:
            forbidden.append("PINVI_RESTORE_FENCE_DATABASE_URL")
        if self.pinvi_restore_hotswap_execute:
            forbidden.append("PINVI_RESTORE_HOTSWAP_EXECUTE")
        if self.pinvi_restore_drain_command:
            forbidden.append("PINVI_RESTORE_DRAIN_COMMAND")
        if self.pinvi_restore_allow_no_drain:
            forbidden.append("PINVI_RESTORE_ALLOW_NO_DRAIN")
        if self.pinvi_restore_drain_verified:
            forbidden.append("PINVI_RESTORE_DRAIN_VERIFIED")
        if self.pinvi_restore_app_role:
            forbidden.append("PINVI_RESTORE_APP_ROLE")
        if forbidden:
            joined = ", ".join(forbidden)
            raise ValueError(
                "staging/production API cannot receive schema-swap executor settings "
                f"({joined}); use the root-owned one-shot restore runner"
            )
        return self

    @model_validator(mode="after")
    def validate_kor_travel_map_ops(self) -> Self:
        """canonical ops URL과 read/cancel 자격을 fail-closed로 검증한다."""

        is_production = self.pinvi_environment == "production"
        if is_production:
            _validate_production_map_root_url(
                self.pinvi_kor_travel_map_admin_base_url,
                env_name="PINVI_KOR_TRAVEL_MAP_ADMIN_BASE_URL",
            )
            if (
                self.kor_travel_map_feature_request_token is not None
                or self.pinvi_kor_travel_map_feature_reference_reconciliation_read_token is not None
                or self.pinvi_kor_travel_map_feature_reference_reconciliation_ack_token is not None
            ):
                _validate_production_map_root_url(
                    self.pinvi_kor_travel_map_api_base_url,
                    env_name="PINVI_KOR_TRAVEL_MAP_API_BASE_URL",
                )

        read_token = (
            self.pinvi_kor_travel_map_ops_read_token.get_secret_value()
            if self.pinvi_kor_travel_map_ops_read_token is not None
            else ""
        )
        cancel_token = (
            self.pinvi_kor_travel_map_ops_cancel_token.get_secret_value()
            if self.pinvi_kor_travel_map_ops_cancel_token is not None
            else ""
        )
        if not read_token and not cancel_token and not is_production:
            return self
        if not read_token or not cancel_token:
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_OPS_READ_TOKEN and "
                "PINVI_KOR_TRAVEL_MAP_OPS_CANCEL_TOKEN must be configured together"
            )
        for env_name, token in (
            ("PINVI_KOR_TRAVEL_MAP_OPS_READ_TOKEN", read_token),
            ("PINVI_KOR_TRAVEL_MAP_OPS_CANCEL_TOKEN", cancel_token),
        ):
            if len(token) < 32:
                raise ValueError(f"{env_name} must contain at least 32 characters")
            if any(character.isspace() for character in token):
                raise ValueError(f"{env_name} must not contain whitespace")
        if read_token == cancel_token:
            raise ValueError("kor-travel-map ops read/cancel tokens must differ")
        return self

    @model_validator(mode="after")
    def validate_cache_target_sync(self) -> Self:
        """paired worker credential과 exact contract pin을 fallback 없이 검증한다."""

        role_fields = (
            (
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_COMMAND_TOKEN",
                self.pinvi_kor_travel_map_cache_target_command_token,
            ),
            (
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_CONSUMER_TOKEN",
                self.pinvi_kor_travel_map_cache_target_consumer_token,
            ),
            (
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_RESTORE_FENCE_TOKEN",
                self.pinvi_kor_travel_map_cache_target_restore_fence_token,
            ),
            (
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_RECOVERY_TOKEN",
                self.pinvi_kor_travel_map_cache_target_recovery_token,
            ),
        )
        role_tokens: list[tuple[str, str]] = []
        for env_name, secret in role_fields:
            if secret is None:
                continue
            token = secret.get_secret_value()
            if len(token) < 32:
                raise ValueError(f"{env_name} must contain at least 32 characters")
            if any(character.isspace() for character in token):
                raise ValueError(f"{env_name} must not contain whitespace")
            role_tokens.append((env_name, token))
        token_values = [token for _, token in role_tokens]
        if len(set(token_values)) != len(token_values):
            raise ValueError("kor-travel-map cache target role tokens must all differ")

        protected_map_credentials = {
            value
            for value in (
                self.pinvi_kor_travel_map_service_token.strip(),
                self.pinvi_kor_travel_map_admin_service_token.strip(),
                self.pinvi_kor_travel_map_admin_proxy_secret.strip(),
                self.pinvi_kor_travel_map_public_api_key.strip(),
                self.pinvi_vworld_api_key.strip(),
                self.pinvi_kor_travel_map_ops_read_token.get_secret_value()
                if self.pinvi_kor_travel_map_ops_read_token is not None
                else "",
                self.pinvi_kor_travel_map_ops_cancel_token.get_secret_value()
                if self.pinvi_kor_travel_map_ops_cancel_token is not None
                else "",
                self.pinvi_kor_travel_map_curation_snapshot_token.get_secret_value()
                if self.pinvi_kor_travel_map_curation_snapshot_token is not None
                else "",
                self.pinvi_kor_travel_map_curation_cutover_mapping_token.get_secret_value()
                if self.pinvi_kor_travel_map_curation_cutover_mapping_token is not None
                else "",
                self.kor_travel_map_feature_request_token.get_secret_value()
                if self.kor_travel_map_feature_request_token is not None
                else "",
                self.pinvi_kor_travel_map_feature_reference_reconciliation_read_token.get_secret_value()
                if self.pinvi_kor_travel_map_feature_reference_reconciliation_read_token is not None
                else "",
                self.pinvi_kor_travel_map_feature_reference_reconciliation_ack_token.get_secret_value()
                if self.pinvi_kor_travel_map_feature_reference_reconciliation_ack_token is not None
                else "",
            )
            if value
        }
        if any(token in protected_map_credentials for _, token in role_tokens):
            raise ValueError(
                "cache target role tokens must not reuse another Map trust-boundary credential"
            )

        if any(
            character.isspace() for character in self.pinvi_kor_travel_map_cache_target_consumer_id
        ):
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_CONSUMER_ID must not contain whitespace"
            )
        if not self.pinvi_kor_travel_map_cache_target_sync_enabled:
            return self
        if self.pinvi_environment == "production":
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_SYNC_ENABLED is forbidden in production "
                "until the root-owned final C7 enable boundary is implemented"
            )
        if self.pinvi_kor_travel_map_cache_target_command_token is None:
            raise ValueError("PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_COMMAND_TOKEN is required")
        if self.pinvi_kor_travel_map_cache_target_consumer_token is None:
            raise ValueError("PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_CONSUMER_TOKEN is required")
        openapi_sha = self.pinvi_kor_travel_map_cache_target_expected_openapi_sha256
        if len(openapi_sha) != 64 or openapi_sha != openapi_sha.lower():
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_EXPECTED_OPENAPI_SHA256 must be lowercase SHA-256 hex"
            )
        try:
            bytes.fromhex(openapi_sha)
        except ValueError as exc:
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_EXPECTED_OPENAPI_SHA256 must be lowercase SHA-256 hex"
            ) from exc
        if openapi_sha != KOR_TRAVEL_MAP_SERVICE_OPENAPI_SHA256:
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_EXPECTED_OPENAPI_SHA256 must match the vendored service contract"
            )
        source_revision = self.pinvi_kor_travel_map_cache_target_expected_source_revision
        if (
            len(source_revision) != 40
            or source_revision != source_revision.lower()
            or any(character not in "0123456789abcdef" for character in source_revision)
        ):
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_EXPECTED_SOURCE_REVISION must be a full lowercase git SHA"
            )
        if source_revision != KOR_TRAVEL_MAP_SERVICE_RELEASE_REVISION:
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_EXPECTED_SOURCE_REVISION must match the service contract Map release revision"
            )
        if (
            self.pinvi_kor_travel_map_cache_target_expected_contract_generation
            != KOR_TRAVEL_MAP_CACHE_TARGET_CAPABILITY_GENERATION
        ):
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_CACHE_TARGET_EXPECTED_CONTRACT_GENERATION must match the vendored service contract"
            )
        return self

    @field_validator(
        "pinvi_kor_travel_map_curation_snapshot_token",
        "pinvi_kor_travel_map_curation_cutover_mapping_token",
        "kor_travel_map_feature_request_token",
        "pinvi_kor_travel_map_cache_target_command_token",
        "pinvi_kor_travel_map_cache_target_consumer_token",
        "pinvi_kor_travel_map_cache_target_restore_fence_token",
        "pinvi_kor_travel_map_cache_target_recovery_token",
        "pinvi_kor_travel_map_feature_reference_reconciliation_read_token",
        "pinvi_kor_travel_map_feature_reference_reconciliation_ack_token",
        mode="before",
    )
    @classmethod
    def _empty_optional_secret_is_unset(cls, value: object) -> object:
        """빈 문자열은 미설정으로 본다.

        docker-manager/`infra/docker-compose.app.yml`은 미설정 토큰을 `${VAR:-}`(빈 문자열)로 주입한다.
        빈 값을 '설정된 토큰'으로 다루면 default-off worker의 선택적 credential도 길이 검증에서
        부팅하지 못한다. 공백 포함 값은 그대로 두어 아래 검증이 명시적으로 거부한다.
        """

        if value is None:
            return None
        raw = value.get_secret_value() if isinstance(value, SecretStr) else value
        if isinstance(raw, str) and raw == "":
            return None
        return value

    @field_validator(
        "pinvi_kor_travel_map_cache_target_expected_contract_generation",
        mode="before",
    )
    @classmethod
    def _empty_optional_contract_generation_is_unset(cls, value: object) -> object:
        """선택적 contract generation의 빈 env 값은 기본값 None으로 본다."""

        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def validate_scoped_service_principals(self) -> Self:
        """curation과 Feature 요청 write scope를 다른 Map trust boundary와 분리한다."""

        scoped_tokens = (
            (
                "PINVI_KOR_TRAVEL_MAP_CURATION_SNAPSHOT_TOKEN",
                self.pinvi_kor_travel_map_curation_snapshot_token,
            ),
            (
                "PINVI_KOR_TRAVEL_MAP_CURATION_CUTOVER_MAPPING_TOKEN",
                self.pinvi_kor_travel_map_curation_cutover_mapping_token,
            ),
            (
                "KOR_TRAVEL_MAP_FEATURE_REQUEST_TOKEN",
                self.kor_travel_map_feature_request_token,
            ),
            (
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_READ_TOKEN",
                self.pinvi_kor_travel_map_feature_reference_reconciliation_read_token,
            ),
            (
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACK_TOKEN",
                self.pinvi_kor_travel_map_feature_reference_reconciliation_ack_token,
            ),
        )
        values = [secret.get_secret_value() for _, secret in scoped_tokens if secret is not None]
        if len(values) != len(set(values)):
            raise ValueError("scoped Map service tokens must differ")
        protected = {
            value
            for value in (
                self.pinvi_kor_travel_map_service_token.strip(),
                self.pinvi_kor_travel_map_admin_service_token.strip(),
                self.pinvi_kor_travel_map_admin_proxy_secret.strip(),
                self.pinvi_kor_travel_map_public_api_key.strip(),
                self.pinvi_vworld_api_key.strip(),
                self.pinvi_kor_travel_map_ops_read_token.get_secret_value()
                if self.pinvi_kor_travel_map_ops_read_token is not None
                else "",
                self.pinvi_kor_travel_map_ops_cancel_token.get_secret_value()
                if self.pinvi_kor_travel_map_ops_cancel_token is not None
                else "",
                self.pinvi_kor_travel_map_cache_target_command_token.get_secret_value()
                if self.pinvi_kor_travel_map_cache_target_command_token is not None
                else "",
                self.pinvi_kor_travel_map_cache_target_consumer_token.get_secret_value()
                if self.pinvi_kor_travel_map_cache_target_consumer_token is not None
                else "",
                self.pinvi_kor_travel_map_cache_target_restore_fence_token.get_secret_value()
                if self.pinvi_kor_travel_map_cache_target_restore_fence_token is not None
                else "",
                self.pinvi_kor_travel_map_cache_target_recovery_token.get_secret_value()
                if self.pinvi_kor_travel_map_cache_target_recovery_token is not None
                else "",
            )
            if value
        }
        for env_name, secret in scoped_tokens:
            if secret is None:
                continue
            token = secret.get_secret_value()
            if len(token) < 32:
                raise ValueError(f"{env_name} must contain at least 32 characters")
            if any(character.isspace() for character in token):
                raise ValueError(f"{env_name} must not contain whitespace")
            if token in protected:
                raise ValueError(f"{env_name} must not reuse another Map trust-boundary credential")
        return self

    @model_validator(mode="after")
    def validate_feature_reference_reconciliation(self) -> Self:
        """M05 read/ACK consumer는 exact vendor와 paired activation receipt를 요구한다."""

        if not self.pinvi_kor_travel_map_feature_reference_reconciliation_enabled:
            return self
        read = self.pinvi_kor_travel_map_feature_reference_reconciliation_read_token
        ack = self.pinvi_kor_travel_map_feature_reference_reconciliation_ack_token
        if read is None:
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_READ_TOKEN is required"
            )
        if ack is None:
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACK_TOKEN is required"
            )
        expected_sha = (
            self.pinvi_kor_travel_map_feature_reference_reconciliation_expected_openapi_sha256
        )
        if expected_sha != KOR_TRAVEL_MAP_SERVICE_OPENAPI_SHA256:
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_EXPECTED_OPENAPI_SHA256 "
                "must match the vendored service contract"
            )
        expected_revision = (
            self.pinvi_kor_travel_map_feature_reference_reconciliation_expected_source_revision
        )
        if expected_revision != KOR_TRAVEL_MAP_SERVICE_RELEASE_REVISION:
            raise ValueError(
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_EXPECTED_SOURCE_REVISION "
                "must match the service contract Map release revision"
            )
        if self.pinvi_environment in {"staging", "production"}:
            self._validate_feature_reference_reconciliation_activation_receipt()
        return self

    def _validate_feature_reference_reconciliation_activation_receipt(self) -> None:
        """서명된 paired live/restore/review evidence 없이는 운영 활성화를 허용하지 않는다."""

        receipt_secret = (
            self.pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt
        )
        receipt_path_value = (
            self.pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt_path
        )
        if receipt_secret is not None and receipt_path_value:
            _raise_redacted_settings_error(
                "M05 activation receipt must use either an inline value or a mounted path"
            )
        if receipt_secret is None and receipt_path_value:
            receipt_path = Path(receipt_path_value)
            try:
                receipt_parent = receipt_path.parent
                receipt_stat = receipt_path.stat()
                parent_stat = receipt_parent.stat()
                if (
                    not receipt_path.is_absolute()
                    or receipt_path.is_symlink()
                    or not receipt_path.is_file()
                    or stat.S_IMODE(receipt_stat.st_mode) != 0o600
                    or receipt_stat.st_uid != os.geteuid()
                    or receipt_parent.is_symlink()
                    or not receipt_parent.is_dir()
                    or stat.S_IMODE(parent_stat.st_mode) & 0o022
                    or parent_stat.st_uid != os.geteuid()
                ):
                    raise OSError("activation receipt path permissions are invalid")
                receipt_secret = SecretStr(receipt_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError):
                _raise_redacted_settings_error(
                    "M05 activation receipt mounted path is not a secure regular file"
                )
        if receipt_secret is None:
            _raise_redacted_settings_error(
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT "
                f"is required in {self.pinvi_environment}"
            )
        try:
            envelope = json.loads(
                receipt_secret.get_secret_value(),
                object_pairs_hook=_reject_duplicate_json_keys,
            )
        except json.JSONDecodeError:
            _raise_redacted_settings_error(
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT "
                "must be valid JSON"
            )
        except _DuplicateJsonKeyError:
            _raise_redacted_settings_error(
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT "
                "must not contain duplicate keys"
            )
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            _raise_redacted_settings_error(
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT "
                "has an unsupported schema"
            )
        payload_value = envelope["payload"]
        signature = envelope["signature"]
        if not isinstance(payload_value, dict) or not isinstance(signature, str):
            _raise_redacted_settings_error(
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT "
                "has an unsupported signature envelope"
            )
        payload = cast(dict[str, object], payload_value)
        expected_payload_fields = {
            "activation_attestation_sha256",
            "activation_expires_at",
            "activation_generation",
            "activation_issued_at",
            "activation_nonce",
            "adversarial_reviews",
            "live_ui_e2e",
            "live_ui_event_id",
            "ui_run_evidence_sha256",
            "live_ui_evidence_sha256",
            "live_ui_map_ack_sha256",
            "live_ui_local_receipt_sha256",
            "live_ui_map_admin_endpoint",
            "live_ui_map_snapshot_sha256",
            "live_ui_pinvi_api_endpoint",
            "live_ui_pinvi_snapshot_sha256",
            "live_ui_pinvi_web_endpoint",
            "live_ui_playwright_runner_image_id",
            "live_ui_playwright_runner_image_ref",
            "live_ui_verification_id",
            "m04_attestation_sha256",
            "m04_created_at",
            "m04_feature_request_id",
            "m04_map_feature_uuid",
            "m04_map_pending_receipt_sha256",
            "m04_map_provenance_sha256",
            "m04_map_request_sha256",
            "m04_pinvi_approval_sha256",
            "m04_verification_id",
            "m05_old_feature_id",
            "m05_replacement_feature_id",
            "m05_impact_count",
            "m05_pinvi_detail_sha256",
            "map_admin_openapi_sha256",
            "map_admin_runtime_openapi_sha256",
            "map_admin_runtime_operation_contract_sha256",
            "map_admin_source_operation_contract_sha256",
            "map_admin_source_revision",
            "map_admin_image_digest",
            "map_admin_container_id",
            "map_api_image_digest",
            "map_api_container_id",
            "map_frontend_image_digest",
            "map_frontend_container_id",
            "map_full_openapi_sha256",
            "map_full_runtime_openapi_sha256",
            "map_full_runtime_operation_contract_sha256",
            "map_full_source_operation_contract_sha256",
            "map_full_source_revision",
            "map_pair_evidence_sha256",
            "map_service_openapi_sha256",
            "map_service_runtime_openapi_sha256",
            "map_service_runtime_operation_contract_sha256",
            "map_service_source_operation_contract_sha256",
            "map_service_source_revision",
            "map_user_openapi_sha256",
            "map_user_runtime_openapi_sha256",
            "map_user_runtime_operation_contract_sha256",
            "map_user_source_operation_contract_sha256",
            "map_user_source_revision",
            "pinvi_api_image_digest",
            "pinvi_api_container_id",
            "pinvi_dagster_image_digest",
            "pinvi_dagster_container_id",
            "pinvi_image_evidence_sha256",
            "pinvi_source_revision",
            "pinvi_web_container_id",
            "pinvi_web_image_digest",
            "restore_drill",
            "restore_evidence_sha256",
            "review_evidence_sha256",
            "scope",
            "version",
        }
        if set(payload) != expected_payload_fields:
            _raise_redacted_settings_error(
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT "
                "has an unsupported payload schema"
            )

        public_key_bytes = _decode_base64url(
            self.pinvi_kor_travel_map_feature_reference_reconciliation_activation_receipt_public_key,
            expected_length=32,
        )
        signature_bytes = _decode_base64url(signature, expected_length=64)
        if public_key_bytes is None or signature_bytes is None:
            _raise_redacted_settings_error(
                "M05 activation receipt public key and signature must be canonical base64url"
            )
        if (
            hashlib.sha256(public_key_bytes).hexdigest()
            != PINVI_M05_ACTIVATION_RECEIPT_PUBLIC_KEY_SHA256
        ):
            _raise_redacted_settings_error(
                "M05 activation receipt public key does not match the vendored trust anchor"
            )
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
                signature_bytes,
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            )
        except (InvalidSignature, ValueError, TypeError):
            _raise_redacted_settings_error("M05 activation receipt signature is invalid")

        if type(payload["version"]) is not int or payload["version"] != 2:
            _raise_redacted_settings_error(
                "PINVI_KOR_TRAVEL_MAP_FEATURE_REFERENCE_RECONCILIATION_ACTIVATION_RECEIPT "
                "M05 activation receipt must be v2"
            )
        if payload["scope"] != self.pinvi_environment:
            _raise_redacted_settings_error(
                "M05 activation receipt scope does not match the runtime environment"
            )
        generation = payload["activation_generation"]
        issued_at = payload["activation_issued_at"]
        expires_at = payload["activation_expires_at"]
        if (
            type(generation) is not int
            or generation < 1
            or type(issued_at) is not int
            or type(expires_at) is not int
            or expires_at <= issued_at
            or expires_at - issued_at > 7 * 24 * 60 * 60
            or issued_at > int(time.time()) + 60
            or expires_at <= int(time.time())
            or generation <= self.pinvi_m05_activation_min_generation
            or not _is_canonical_uuid(payload["activation_nonce"])
        ):
            _raise_redacted_settings_error(
                "M05 activation receipt freshness, generation, or nonce is invalid"
            )
        m04_created_at = payload["m04_created_at"]
        if (
            type(m04_created_at) is not int
            or m04_created_at <= 0
            or m04_created_at > issued_at + 60
            or issued_at - m04_created_at > 15 * 60
        ):
            _raise_redacted_settings_error(
                "M05 activation receipt M04 evidence is outside the activation window"
            )
        if (
            not isinstance(payload["pinvi_source_revision"], str)
            or re.fullmatch(r"[0-9a-f]{40}", payload["pinvi_source_revision"]) is None
            or payload["pinvi_source_revision"] != os.environ.get("PINVI_SOURCE_REVISION", "")
        ):
            _raise_redacted_settings_error(
                "M05 activation receipt Pinvi source revision must match PINVI_SOURCE_REVISION"
            )
        reviews = payload["adversarial_reviews"]
        if self.pinvi_m05_activation_pr_url != _M05_ACTIVATION_PR_URL:
            _raise_redacted_settings_error("M05 activation PR URL is not the pinned PR #466")
        if not isinstance(reviews, list) or len(reviews) != 2:
            _raise_redacted_settings_error("M05 activation requires two adversarial reviews")
        review_keys: set[tuple[str, str, str]] = set()
        reviewer_ids: set[str] = set()
        review_ids: set[str] = set()
        agent_ids: set[str] = set()
        challenge_ids: set[str] = set()
        for review in reviews:
            if not isinstance(review, dict) or set(review) != {
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
                _raise_redacted_settings_error("M05 adversarial review evidence schema is invalid")
            reviewer_id = review["reviewer_id"]
            review_id = review["review_id"]
            agent_id = review["agent_id"]
            challenge_id = review["challenge_id"]
            response_sha256 = review["response_sha256"]
            summary = review["summary"]
            summary_sha256 = review["summary_sha256"]
            if (
                not _is_canonical_uuid(reviewer_id)
                or not _is_canonical_uuid(review_id)
                or not isinstance(agent_id, str)
                or not _is_canonical_uuid(agent_id)
                or reviewer_id != agent_id
                or not isinstance(challenge_id, str)
                or not _is_canonical_uuid(challenge_id)
                or not isinstance(response_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", response_sha256) is None
                or not isinstance(review["pr_url"], str)
                or re.fullmatch(
                    r"https://github\.com/digitie/pinvi/pull/[1-9][0-9]*", review["pr_url"]
                )
                is None
                or review["pr_url"] != self.pinvi_m05_activation_pr_url
                or agent_id not in PINVI_M05_REVIEWER_AGENT_IDS
                or review["verdict"] != "GO"
                or not isinstance(summary, str)
                or not summary
                or any(character in "\r\n" for character in summary)
                or not isinstance(summary_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", summary_sha256) is None
                or hashlib.sha256(summary.encode("utf-8")).hexdigest() != summary_sha256
                or type(review["p0_p1"]) is not int
                or review["p0_p1"] != 0
                or not isinstance(review["commit"], str)
                or re.fullmatch(r"[0-9a-f]{40}", review["commit"]) is None
                or review["commit"] != payload["pinvi_source_revision"]
            ):
                _raise_redacted_settings_error(
                    "M05 activation requires two adversarial reviews with zero P0/P1 findings"
                )
            review_key = (reviewer_id, review_id, review["commit"])
            if (
                review_key in review_keys
                or reviewer_id in reviewer_ids
                or review_id in review_ids
                or agent_id in agent_ids
            ):
                _raise_redacted_settings_error(
                    "M05 activation requires two distinct adversarial reviews"
                )
            review_keys.add(review_key)
            reviewer_ids.add(reviewer_id)
            review_ids.add(review_id)
            agent_ids.add(agent_id)
            challenge_ids.add(challenge_id)
        if len(challenge_ids) != 1:
            _raise_redacted_settings_error(
                "M05 activation reviews must share one external challenge"
            )
        if payload["live_ui_e2e"] != "passed" or payload["restore_drill"] != "passed":
            _raise_redacted_settings_error(
                "M05 activation requires passed live UI E2E and restore drill evidence"
            )
        event_id = payload["live_ui_event_id"]
        if not _is_canonical_uuid(event_id):
            _raise_redacted_settings_error("M05 live UI evidence event ID is not canonical")

        for field in (
            "activation_attestation_sha256",
            "ui_run_evidence_sha256",
            "live_ui_evidence_sha256",
            "live_ui_map_ack_sha256",
            "live_ui_local_receipt_sha256",
            "live_ui_map_snapshot_sha256",
            "live_ui_pinvi_snapshot_sha256",
            "m04_attestation_sha256",
            "m04_map_pending_receipt_sha256",
            "m04_map_provenance_sha256",
            "m04_map_request_sha256",
            "m04_pinvi_approval_sha256",
            "m05_pinvi_detail_sha256",
            "map_admin_runtime_openapi_sha256",
            "map_admin_runtime_operation_contract_sha256",
            "map_admin_source_operation_contract_sha256",
            "map_full_runtime_openapi_sha256",
            "map_full_runtime_operation_contract_sha256",
            "map_full_source_operation_contract_sha256",
            "map_service_runtime_openapi_sha256",
            "map_service_runtime_operation_contract_sha256",
            "map_service_source_operation_contract_sha256",
            "map_user_runtime_openapi_sha256",
            "map_user_runtime_operation_contract_sha256",
            "map_user_source_operation_contract_sha256",
            "map_pair_evidence_sha256",
            "pinvi_image_evidence_sha256",
            "restore_evidence_sha256",
            "review_evidence_sha256",
        ):
            value = payload[field]
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                _raise_redacted_settings_error(f"M05 activation evidence hash is invalid: {field}")

        if (
            not isinstance(payload["live_ui_playwright_runner_image_id"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", payload["live_ui_playwright_runner_image_id"])
            is None
            or not isinstance(payload["live_ui_playwright_runner_image_ref"], str)
            or re.fullmatch(
                # 세 선언(여기 + scripts/m05_activation_{receipt,attestation}.py)이
                # 문자 단위로 같아야 한다 — tag는 optional이다. Manager가 고정한
                # runner 핀은 digest-only(`playwright@sha256:...`)라 tag를 강제하면
                # 같은 값이 한쪽에서만 거부된다.
                r"mcr\.microsoft\.com/playwright(?::[A-Za-z0-9][A-Za-z0-9._-]*)?"
                r"@sha256:[0-9a-f]{64}",
                payload["live_ui_playwright_runner_image_ref"],
            )
            is None
            or not _is_canonical_uuid(payload["live_ui_verification_id"])
            or payload["live_ui_verification_id"] != payload["activation_nonce"]
            or not _is_canonical_uuid(payload["m04_feature_request_id"])
            or not _is_canonical_uuid(payload["m04_map_feature_uuid"])
            or not _is_canonical_uuid(payload["m04_verification_id"])
            or payload["m04_verification_id"] != payload["activation_nonce"]
            or not _is_non_empty_token_free_string(payload["m05_old_feature_id"])
            or not _is_non_empty_token_free_string(payload["m05_replacement_feature_id"])
            or type(payload["m05_impact_count"]) is not int
            or payload["m05_impact_count"] < 0
        ):
            _raise_redacted_settings_error(
                "M05 live UI runner identity or verification nonce is invalid"
            )
        for endpoint_field in (
            "live_ui_map_admin_endpoint",
            "live_ui_pinvi_api_endpoint",
            "live_ui_pinvi_web_endpoint",
        ):
            endpoint = payload[endpoint_field]
            try:
                parsed_endpoint = urlsplit(endpoint) if isinstance(endpoint, str) else None
                endpoint_port = parsed_endpoint.port if parsed_endpoint is not None else None
            except ValueError:
                parsed_endpoint = None
                endpoint_port = None
            if (
                parsed_endpoint is None
                or parsed_endpoint.scheme != "http"
                or parsed_endpoint.hostname != "127.0.0.1"
                or endpoint_port is None
                or parsed_endpoint.path not in {"", "/"}
                or parsed_endpoint.query
                or parsed_endpoint.fragment
                or not isinstance(endpoint, str)
                or any(character.isspace() for character in endpoint)
            ):
                _raise_redacted_settings_error(
                    f"M05 activation receipt endpoint is not canonical: {endpoint_field}"
                )

        for container_field in (
            "map_admin_container_id",
            "map_api_container_id",
            "map_frontend_container_id",
            "pinvi_api_container_id",
            "pinvi_web_container_id",
            "pinvi_dagster_container_id",
        ):
            container_id = payload[container_field]
            if (
                not isinstance(container_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            ):
                _raise_redacted_settings_error(
                    f"M05 activation receipt container identity is invalid: {container_field}"
                )

        for field in ("live_ui_local_receipt_sha256",):
            if not isinstance(payload[field], str):
                _raise_redacted_settings_error(
                    f"M05 activation receipt terminal binding is invalid: {field}"
                )

        for field, expected in (
            ("map_admin_openapi_sha256", KOR_TRAVEL_MAP_M05_ADMIN_OPENAPI_SHA256),
            ("map_full_openapi_sha256", KOR_TRAVEL_MAP_M05_FULL_OPENAPI_SHA256),
            ("map_service_openapi_sha256", KOR_TRAVEL_MAP_SERVICE_OPENAPI_SHA256),
            ("map_user_openapi_sha256", KOR_TRAVEL_MAP_M05_USER_OPENAPI_SHA256),
            ("map_admin_source_revision", KOR_TRAVEL_MAP_M05_ADMIN_SOURCE_REVISION),
            ("map_full_source_revision", KOR_TRAVEL_MAP_M05_FULL_SOURCE_REVISION),
            ("map_service_source_revision", KOR_TRAVEL_MAP_SERVICE_RELEASE_REVISION),
            ("map_user_source_revision", KOR_TRAVEL_MAP_M05_USER_SOURCE_REVISION),
        ):
            if expected is None:
                # v2 계약은 Map revision을 선언하지 않는다 — 대조 상대가 사라지는 것이
                # v2의 목적이다(`T-VN-PAIR-V2`, `AGENTS.md` DO NOT 15 이중 선언 제거).
                #
                # 이 값을 보호하는 것은 계약의 사본이 아니라 **서명 사슬**이다:
                # pin registry → Manager가 유도 → Ed25519 서명 receipt → 여기서 서명 검증.
                # 계약이 두 번째로 선언하던 것을 걷어낸 것이지 검사를 잃은 것이 아니다.
                # 형식 검증(40-hex 등)은 payload 스키마 검사가 그대로 한다.
                continue
            if payload[field] != expected:
                _raise_redacted_settings_error(
                    f"M05 activation receipt Map pair field does not match: {field}"
                )

        for field, expected in (
            (
                "map_admin_runtime_operation_contract_sha256",
                KOR_TRAVEL_MAP_M05_ADMIN_RUNTIME_OPERATION_CONTRACT_SHA256,
            ),
            (
                "map_full_runtime_operation_contract_sha256",
                KOR_TRAVEL_MAP_M05_FULL_RUNTIME_OPERATION_CONTRACT_SHA256,
            ),
            (
                "map_service_runtime_operation_contract_sha256",
                KOR_TRAVEL_MAP_M05_SERVICE_RUNTIME_OPERATION_CONTRACT_SHA256,
            ),
            (
                "map_user_runtime_operation_contract_sha256",
                KOR_TRAVEL_MAP_M05_USER_RUNTIME_OPERATION_CONTRACT_SHA256,
            ),
            (
                "map_admin_source_operation_contract_sha256",
                KOR_TRAVEL_MAP_M05_ADMIN_SOURCE_OPERATION_CONTRACT_SHA256,
            ),
            (
                "map_full_source_operation_contract_sha256",
                KOR_TRAVEL_MAP_M05_FULL_SOURCE_OPERATION_CONTRACT_SHA256,
            ),
            (
                "map_service_source_operation_contract_sha256",
                KOR_TRAVEL_MAP_M05_SERVICE_SOURCE_OPERATION_CONTRACT_SHA256,
            ),
            (
                "map_user_source_operation_contract_sha256",
                KOR_TRAVEL_MAP_M05_USER_SOURCE_OPERATION_CONTRACT_SHA256,
            ),
        ):
            if payload[field] != expected:
                _raise_redacted_settings_error(
                    f"M05 activation receipt Map operation contract is not pinned: {field}"
                )

        for field in (
            "map_admin_image_digest",
            "map_api_image_digest",
            "map_frontend_image_digest",
            "pinvi_api_image_digest",
            "pinvi_dagster_image_digest",
            "pinvi_web_image_digest",
        ):
            value = payload[field]
            if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                _raise_redacted_settings_error(f"M05 image digest is invalid: {field}")

        for field, expected in (
            ("map_admin_image_digest", KOR_TRAVEL_MAP_M05_ADMIN_IMAGE_DIGEST),
            ("map_api_image_digest", KOR_TRAVEL_MAP_M05_API_IMAGE_DIGEST),
            ("map_frontend_image_digest", KOR_TRAVEL_MAP_M05_FRONTEND_IMAGE_DIGEST),
        ):
            if expected is None:
                # 같은 이유다 — v2 계약에는 runtime image digest가 없고, 그 값의 생산자는
                # Manager receipt(서명됨) 하나다. 형식 검증은 바로 위 루프가 한다.
                continue
            if payload[field] != expected:
                _raise_redacted_settings_error(
                    f"M05 activation receipt Map image digest does not match the pinned runtime: {field}"
                )

        if (
            payload["pinvi_api_image_digest"] != self.pinvi_api_image_digest
            or payload["pinvi_web_image_digest"] != self.pinvi_web_image_digest
            or payload["pinvi_dagster_image_digest"] != self.pinvi_dagster_image_digest
        ):
            _raise_redacted_settings_error(
                "M05 activation receipt Pinvi runtime image digest does not match the attested pair"
            )
        if self.pinvi_environment in {"staging", "production"}:
            runtime_container_id = _runtime_container_id()
            if runtime_container_id != payload["pinvi_api_container_id"]:
                _raise_redacted_settings_error(
                    "M05 activation receipt API container ID does not match the running container"
                )
        pinvi_source_revision = payload["pinvi_source_revision"]
        if (
            not isinstance(pinvi_source_revision, str)
            or re.fullmatch(r"[0-9a-f]{40}", pinvi_source_revision) is None
            or pinvi_source_revision != os.environ.get("PINVI_SOURCE_REVISION", "")
        ):
            _raise_redacted_settings_error(
                "M05 activation receipt Pinvi source revision must match PINVI_SOURCE_REVISION"
            )
        self._validate_m05_runtime_attestation(
            payload,
            receipt_secret=receipt_secret,
            public_key_bytes=public_key_bytes,
        )
        self._validate_m05_runtime_lease(payload, receipt_secret=receipt_secret)
        self._validate_m05_activation_ledger(payload, receipt_secret)

    def _validate_m05_runtime_attestation(
        self,
        receipt_payload: dict[str, object],
        *,
        receipt_secret: SecretStr,
        public_key_bytes: bytes,
    ) -> None:
        path = Path(self.pinvi_m05_runtime_attestation_path)
        try:
            parent = path.parent
            metadata = path.stat()
            parent_metadata = parent.stat()
            if (
                not path.is_absolute()
                or path.is_symlink()
                or not path.is_file()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
                or parent.is_symlink()
                or not parent.is_dir()
                or stat.S_IMODE(parent_metadata.st_mode) & 0o022
                or parent_metadata.st_uid != os.geteuid()
            ):
                raise OSError("runtime attestation permissions are invalid")
            raw = path.read_bytes()
            envelope = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKeyError):
            _raise_redacted_settings_error(
                "PINVI_M05_RUNTIME_ATTESTATION_PATH is not a secure valid JSON file"
            )
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            _raise_redacted_settings_error("M05 runtime attestation envelope is invalid")
        runtime_payload = envelope.get("payload")
        signature = envelope.get("signature")
        if not isinstance(runtime_payload, dict) or not isinstance(signature, str):
            _raise_redacted_settings_error("M05 runtime attestation signature envelope is invalid")
        runtime_signature = _decode_base64url(signature, expected_length=64)
        if runtime_signature is None:
            _raise_redacted_settings_error("M05 runtime attestation signature encoding is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
                runtime_signature,
                _canonical_json(runtime_payload),
            )
        except (InvalidSignature, ValueError, TypeError):
            _raise_redacted_settings_error("M05 runtime attestation signature is invalid")
        expected_fields = {
            "activation_generation",
            "activation_nonce",
            "created_at",
            "dependencies",
            "endpoints",
            "pinvi_source_revision",
            "receipt_sha256",
            "scope",
            "version",
        }
        if set(runtime_payload) != expected_fields or runtime_payload["version"] != 2:
            _raise_redacted_settings_error("M05 runtime attestation schema is invalid")
        if (
            runtime_payload["activation_generation"] != receipt_payload["activation_generation"]
            or runtime_payload["activation_nonce"] != receipt_payload["activation_nonce"]
            or runtime_payload["scope"] != self.pinvi_environment
            or runtime_payload["pinvi_source_revision"] != receipt_payload["pinvi_source_revision"]
            or runtime_payload["receipt_sha256"]
            != hashlib.sha256(receipt_secret.get_secret_value().encode("utf-8")).hexdigest()
            or type(runtime_payload["created_at"]) is not int
            or runtime_payload["created_at"] > int(time.time()) + 60
            or runtime_payload["created_at"]
            < cast(int, receipt_payload["activation_issued_at"]) - 60
            or runtime_payload["created_at"] > cast(int, receipt_payload["activation_expires_at"])
        ):
            _raise_redacted_settings_error("M05 runtime attestation freshness is invalid")
        dependencies = runtime_payload["dependencies"]
        endpoints = runtime_payload["endpoints"]
        if not isinstance(dependencies, dict) or set(dependencies) != {
            "map_admin",
            "map_api",
            "map_frontend",
            "pinvi_api",
            "pinvi_web",
            "pinvi_dagster",
        }:
            _raise_redacted_settings_error("M05 runtime attestation dependencies are invalid")
        if not isinstance(endpoints, dict) or set(endpoints) != {
            "map_admin",
            "pinvi_api",
            "pinvi_web",
        }:
            _raise_redacted_settings_error("M05 runtime attestation endpoints are invalid")
        endpoint_fields = {
            "map_admin": "live_ui_map_admin_endpoint",
            "pinvi_api": "live_ui_pinvi_api_endpoint",
            "pinvi_web": "live_ui_pinvi_web_endpoint",
        }
        for name, field in endpoint_fields.items():
            if endpoints[name] != receipt_payload[field]:
                _raise_redacted_settings_error(
                    f"M05 runtime attestation endpoint is not bound: {name}"
                )
        dependency_fields = {
            "map_admin": (
                "map_admin_container_id",
                "map_admin_image_digest",
                "map_admin_source_revision",
            ),
            "map_api": (
                "map_api_container_id",
                "map_api_image_digest",
                "map_admin_source_revision",
            ),
            "map_frontend": (
                "map_frontend_container_id",
                "map_frontend_image_digest",
                "map_admin_source_revision",
            ),
            "pinvi_api": (
                "pinvi_api_container_id",
                "pinvi_api_image_digest",
                "pinvi_source_revision",
            ),
            "pinvi_web": (
                "pinvi_web_container_id",
                "pinvi_web_image_digest",
                "pinvi_source_revision",
            ),
            "pinvi_dagster": (
                "pinvi_dagster_container_id",
                "pinvi_dagster_image_digest",
                "pinvi_source_revision",
            ),
        }
        for name, fields in dependency_fields.items():
            dependency = dependencies[name]
            if not isinstance(dependency, dict) or set(dependency) != {
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
                _raise_redacted_settings_error(
                    f"M05 runtime attestation dependency schema is invalid: {name}"
                )
            expected_container, expected_digest, expected_revision = fields
            if (
                dependency["container_id"] != receipt_payload[expected_container]
                or dependency["digest"] != receipt_payload[expected_digest]
                or dependency["image_id"] != dependency["digest"]
                or dependency["environment"] != self.pinvi_environment
                or dependency["source_revision"] != receipt_payload[expected_revision]
                or dependency["revision_label"] != dependency["source_revision"]
                or not isinstance(dependency["started_at"], str)
                or not dependency["started_at"]
                or not isinstance(dependency["container_id"], str)
                or re.fullmatch(r"[0-9a-f]{64}", dependency["container_id"]) is None
                or not isinstance(dependency["digest"], str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", dependency["digest"]) is None
            ):
                _raise_redacted_settings_error(
                    f"M05 runtime attestation dependency is not bound: {name}"
                )
        if self.pinvi_m05_runtime_live_check:
            if self.pinvi_docker_socket_path != "/var/run/docker.sock":
                _raise_redacted_settings_error(
                    "M05 runtime Docker socket must be the canonical local Engine socket"
                )
            try:
                _validate_m05_runtime_dependencies_live(
                    dependencies=cast(dict[str, object], dependencies),
                    endpoints=cast(dict[str, object], endpoints),
                    socket_path=self.pinvi_docker_socket_path,
                    timeout_seconds=self.pinvi_docker_status_timeout_seconds,
                    environment=self.pinvi_environment,
                )
            except RuntimeError as exc:
                _raise_redacted_settings_error(
                    f"M05 runtime attestation does not match live dependencies: {exc}"
                )
        self._m05_runtime_dependencies = cast(dict[str, object], dependencies)
        self._m05_runtime_endpoints = cast(dict[str, object], endpoints)
        self._m05_runtime_attestation_sha256 = hashlib.sha256(raw).hexdigest()
        self._m05_runtime_dependency_snapshot_sha256 = hashlib.sha256(
            _canonical_json(dependencies)
        ).hexdigest()
        runtime_container_id = _runtime_container_id()
        if runtime_container_id != dependencies["pinvi_api"]["container_id"]:
            _raise_redacted_settings_error(
                "M05 runtime attestation API container ID does not match the running container"
            )

    def _validate_m05_runtime_lease(
        self,
        receipt_payload: dict[str, object],
        *,
        receipt_secret: SecretStr,
    ) -> None:
        """root watcher lease가 현재 receipt/attestation과 분리 없이 결박됐는지 확인한다."""

        if (
            self.pinvi_environment not in {"staging", "production"}
            or not self.pinvi_kor_travel_map_feature_reference_reconciliation_enabled
        ):
            return
        try:
            verifier = M05RuntimeLeaseVerifier(
                directory=Path(self.pinvi_m05_runtime_lease_directory),
                binding=M05RuntimeLeaseBinding(
                    scope=self.pinvi_environment,
                    activation_generation=cast(int, receipt_payload["activation_generation"]),
                    activation_nonce=cast(str, receipt_payload["activation_nonce"]),
                    receipt_sha256=hashlib.sha256(
                        receipt_secret.get_secret_value().encode("utf-8")
                    ).hexdigest(),
                    runtime_attestation_sha256=self._m05_runtime_attestation_sha256,
                    dependency_snapshot_sha256=self._m05_runtime_dependency_snapshot_sha256,
                ),
                max_lifetime_seconds=self.pinvi_m05_runtime_lease_max_lifetime_seconds,
            )
            verifier.validate()
        except (M05RuntimeLeaseError, OSError, TypeError, ValueError):
            _raise_redacted_settings_error(
                "M05 runtime lease is absent, expired, or not bound to the active pair"
            )
        self._m05_runtime_lease_verifier = verifier

    def validate_m05_runtime_lease(self) -> None:
        """worker의 Map read·ACK 경계에서 현재 root watcher lease를 재확인한다."""

        if (
            self.pinvi_environment not in {"staging", "production"}
            or not self.pinvi_kor_travel_map_feature_reference_reconciliation_enabled
        ):
            return
        if self._m05_runtime_lease_verifier is None:
            raise RuntimeError("M05 runtime lease verifier is not loaded")
        try:
            self._m05_runtime_lease_verifier.validate()
        except M05RuntimeLeaseError as exc:
            raise RuntimeError("M05 runtime lease is invalid") from exc

    def validate_m05_runtime_dependencies_live(self) -> None:
        """M05 worker가 dependency container 교체를 감지할 때 재검증한다."""

        if (
            self.pinvi_environment not in {"staging", "production"}
            or not self.pinvi_m05_runtime_live_check
        ):
            return
        if not self._m05_runtime_dependencies or not self._m05_runtime_endpoints:
            raise RuntimeError("M05 runtime dependency snapshot is not loaded")
        try:
            _validate_m05_runtime_dependencies_live(
                dependencies=self._m05_runtime_dependencies,
                endpoints=self._m05_runtime_endpoints,
                socket_path=self.pinvi_docker_socket_path,
                timeout_seconds=self.pinvi_docker_status_timeout_seconds,
                environment=self.pinvi_environment,
            )
        except RuntimeError as exc:
            raise RuntimeError("M05 runtime dependency drift detected") from exc

    def _validate_m05_activation_ledger(
        self, payload: dict[str, object], receipt_secret: SecretStr
    ) -> None:
        ledger_path = Path(self.pinvi_m05_activation_ledger_path)
        high_watermark_path = Path(self.pinvi_m05_activation_high_watermark_path)
        durable_floor_path = Path(self.pinvi_m05_activation_durable_floor_path)
        durable_history_path = Path(self.pinvi_m05_activation_durable_history_path)
        durable_anchor_path = Path(self.pinvi_m05_activation_durable_anchor_path)
        try:
            ledger_parent = ledger_path.parent.resolve(strict=True)
            high_watermark_parent = high_watermark_path.parent.resolve(strict=True)
            durable_floor_parent = durable_floor_path.parent.resolve(strict=True)
            durable_history_parent = durable_history_path.parent.resolve(strict=True)
            durable_anchor_parent = durable_anchor_path.parent.resolve(strict=True)
        except OSError:
            _raise_redacted_settings_error(
                "M05 activation ledger parent directories are unreadable"
            )
        if (
            not self.pinvi_m05_activation_ledger_path
            or ledger_path.is_symlink()
            or not ledger_path.is_file()
            or not self.pinvi_m05_activation_high_watermark_path
            or high_watermark_path.is_symlink()
            or not high_watermark_path.is_file()
            or not self.pinvi_m05_activation_durable_floor_path
            or durable_floor_path.is_symlink()
            or not durable_floor_path.is_file()
            or not self.pinvi_m05_activation_durable_history_path
            or durable_history_path.is_symlink()
            or not durable_history_path.is_file()
            or not self.pinvi_m05_activation_durable_anchor_path
            or durable_anchor_path.is_symlink()
            or not durable_anchor_path.is_file()
        ):
            _raise_redacted_settings_error(
                "M05 activation ledger, high-watermark, and durable floor files are required"
            )
        try:
            ledger_stat = ledger_path.stat()
            ledger_lines = ledger_path.read_text(encoding="utf-8").splitlines()
            high_watermark_stat = high_watermark_path.stat()
            high_watermark = json.loads(
                high_watermark_path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
            )
            durable_floor_stat = durable_floor_path.stat()
            durable_floor = json.loads(
                durable_floor_path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
            )
            durable_history_stat = durable_history_path.stat()
            durable_history_lines = durable_history_path.read_text(encoding="utf-8").splitlines()
            durable_anchor_stat = durable_anchor_path.stat()
            durable_anchor_lines = durable_anchor_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            _raise_redacted_settings_error("M05 activation ledger files are unreadable")
        except (json.JSONDecodeError, _DuplicateJsonKeyError):
            _raise_redacted_settings_error("M05 activation high-watermark is invalid JSON")
        if (
            stat.S_IMODE(ledger_stat.st_mode) != 0o600
            or ledger_stat.st_uid != os.geteuid()
            or not ledger_lines
            or stat.S_IMODE(high_watermark_stat.st_mode) != 0o600
            or high_watermark_stat.st_uid != os.geteuid()
            or stat.S_IMODE(durable_floor_stat.st_mode) != 0o600
            or durable_floor_stat.st_uid != os.geteuid()
            or stat.S_IMODE(durable_history_stat.st_mode) != 0o600
            or durable_history_stat.st_uid != os.geteuid()
            or not durable_history_lines
            or stat.S_IMODE(durable_anchor_stat.st_mode) != 0o600
            or durable_anchor_stat.st_uid != os.geteuid()
            or not durable_anchor_lines
            or durable_anchor_path == durable_history_path
            or durable_anchor_path == ledger_path
            or durable_anchor_path == high_watermark_path
            or durable_anchor_path == durable_floor_path
            or durable_anchor_parent
            in {
                ledger_parent,
                high_watermark_parent,
                durable_floor_parent,
                durable_history_parent,
            }
            or any(
                parent.is_symlink()
                or not parent.is_dir()
                or stat.S_IMODE(parent.stat().st_mode) & 0o022
                or parent.stat().st_uid != os.geteuid()
                for parent in (
                    ledger_path.parent,
                    high_watermark_path.parent,
                    durable_floor_path.parent,
                    durable_history_path.parent,
                    durable_anchor_path.parent,
                )
            )
        ):
            _raise_redacted_settings_error(
                "M05 activation ledger files or durable anchor boundary are invalid"
            )
        if not isinstance(high_watermark, dict) or set(high_watermark) != {
            "generation",
            "receipt_sha256",
        }:
            _raise_redacted_settings_error("M05 activation high-watermark schema is invalid")
        high_watermark_generation = high_watermark["generation"]
        high_watermark_receipt_sha256 = high_watermark["receipt_sha256"]
        if (
            type(high_watermark_generation) is not int
            or high_watermark_generation < 1
            or high_watermark_generation < self.pinvi_m05_activation_min_generation
            or not isinstance(high_watermark_receipt_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", high_watermark_receipt_sha256) is None
        ):
            _raise_redacted_settings_error("M05 activation high-watermark fields are invalid")
        if not isinstance(durable_floor, dict) or set(durable_floor) != {"generation"}:
            _raise_redacted_settings_error("M05 activation durable floor schema is invalid")
        durable_floor_generation = durable_floor["generation"]
        if (
            type(durable_floor_generation) is not int
            or durable_floor_generation < 1
            or durable_floor_generation < self.pinvi_m05_activation_min_generation
        ):
            _raise_redacted_settings_error("M05 activation durable floor fields are invalid")
        durable_history_records: list[dict[str, object]] = []
        durable_history_previous_generation: int | None = None
        durable_history_previous_sha256 = "0" * 64
        for line in durable_history_lines:
            try:
                history_value = json.loads(line, object_pairs_hook=_reject_duplicate_json_keys)
            except (json.JSONDecodeError, _DuplicateJsonKeyError):
                _raise_redacted_settings_error(
                    "M05 activation durable history contains invalid JSON"
                )
            if not isinstance(history_value, dict) or set(history_value) != {
                "generation",
                "previous_record_sha256",
                "receipt_sha256",
                "record_sha256",
            }:
                _raise_redacted_settings_error("M05 activation durable history schema is invalid")
            history_record = cast(dict[str, object], history_value)
            history_generation = history_record["generation"]
            history_previous_sha256 = history_record["previous_record_sha256"]
            history_receipt_sha256 = history_record["receipt_sha256"]
            history_record_sha256 = history_record["record_sha256"]
            if (
                type(history_generation) is not int
                or history_generation < 1
                or (
                    durable_history_previous_generation is not None
                    and history_generation <= durable_history_previous_generation
                )
                or not isinstance(history_previous_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", history_previous_sha256) is None
                or history_previous_sha256 != durable_history_previous_sha256
                or not isinstance(history_receipt_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", history_receipt_sha256) is None
                or not isinstance(history_record_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", history_record_sha256) is None
                or history_record_sha256 != _ledger_record_hash(history_record)
            ):
                _raise_redacted_settings_error("M05 activation durable history fields are invalid")
            durable_history_previous_generation = history_generation
            durable_history_previous_sha256 = history_record_sha256
            durable_history_records.append(history_record)
        if not durable_history_records:
            _raise_redacted_settings_error("M05 activation durable history is empty")
        durable_anchor_records: list[dict[str, object]] = []
        durable_anchor_previous_generation: int | None = None
        durable_anchor_previous_sha256 = "0" * 64
        for line in durable_anchor_lines:
            try:
                anchor_value = json.loads(line, object_pairs_hook=_reject_duplicate_json_keys)
            except (json.JSONDecodeError, _DuplicateJsonKeyError):
                _raise_redacted_settings_error(
                    "M05 activation durable anchor contains invalid JSON"
                )
            if not isinstance(anchor_value, dict) or set(anchor_value) != {
                "generation",
                "previous_record_sha256",
                "receipt_sha256",
                "record_sha256",
            }:
                _raise_redacted_settings_error("M05 activation durable anchor schema is invalid")
            anchor_record = cast(dict[str, object], anchor_value)
            anchor_generation = anchor_record["generation"]
            anchor_previous_sha256 = anchor_record["previous_record_sha256"]
            anchor_receipt_sha256 = anchor_record["receipt_sha256"]
            anchor_record_sha256 = anchor_record["record_sha256"]
            if (
                type(anchor_generation) is not int
                or anchor_generation < 1
                or (
                    durable_anchor_previous_generation is not None
                    and anchor_generation <= durable_anchor_previous_generation
                )
                or not isinstance(anchor_previous_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", anchor_previous_sha256) is None
                or anchor_previous_sha256 != durable_anchor_previous_sha256
                or not isinstance(anchor_receipt_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", anchor_receipt_sha256) is None
                or not isinstance(anchor_record_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", anchor_record_sha256) is None
                or anchor_record_sha256 != _ledger_record_hash(anchor_record)
            ):
                _raise_redacted_settings_error("M05 activation durable anchor fields are invalid")
            durable_anchor_previous_generation = anchor_generation
            durable_anchor_previous_sha256 = anchor_record_sha256
            durable_anchor_records.append(anchor_record)
        if not durable_anchor_records:
            _raise_redacted_settings_error("M05 activation durable anchor is empty")
        records: list[dict[str, object]] = []
        activation_nonces: set[str] = set()
        previous_generation: int | None = None
        previous_record_sha256 = "0" * 64
        for line in ledger_lines:
            try:
                record = json.loads(line, object_pairs_hook=_reject_duplicate_json_keys)
            except (json.JSONDecodeError, _DuplicateJsonKeyError):
                _raise_redacted_settings_error(
                    "M05 activation receipt ledger contains invalid JSON"
                )
            if not isinstance(record, dict) or set(record) != {
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
                _raise_redacted_settings_error("M05 activation receipt ledger schema is invalid")
            record_object = cast(dict[str, object], record)
            generation = record_object["activation_generation"]
            issued_at = record_object["activation_issued_at"]
            expires_at = record_object["activation_expires_at"]
            scope = record_object["scope"]
            source_revision = record_object["source_revision"]
            record_previous_sha256 = record_object["previous_record_sha256"]
            record_sha256 = record_object["record_sha256"]
            if (
                type(generation) is not int
                or generation < 1
                or (previous_generation is not None and generation <= previous_generation)
                or type(issued_at) is not int
                or type(expires_at) is not int
                or expires_at <= issued_at
                or expires_at - issued_at > 7 * 24 * 60 * 60
                or not _is_canonical_uuid(record_object["activation_nonce"])
                or not isinstance(record_previous_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", record_previous_sha256) is None
                or record_previous_sha256 != previous_record_sha256
                or not isinstance(record_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", record_sha256) is None
                or not isinstance(record_object["receipt_sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", record_object["receipt_sha256"]) is None
                or not isinstance(scope, str)
                or scope not in {"staging", "production"}
                or not isinstance(source_revision, str)
                or re.fullmatch(r"[0-9a-f]{40}", source_revision) is None
            ):
                _raise_redacted_settings_error("M05 activation receipt ledger fields are invalid")
            activation_nonce = cast(str, record_object["activation_nonce"])
            if activation_nonce in activation_nonces:
                _raise_redacted_settings_error("M05 activation receipt ledger replays a nonce")
            activation_nonces.add(activation_nonce)
            if record_sha256 != _ledger_record_hash(record_object):
                _raise_redacted_settings_error(
                    "M05 activation receipt ledger hash chain is invalid"
                )
            previous_generation = generation
            previous_record_sha256 = record_sha256
            records.append(record_object)
        if not records:
            _raise_redacted_settings_error("M05 activation receipt ledger is empty")
        latest = records[-1]
        latest_generation = latest["activation_generation"]
        latest_receipt_sha256 = latest["receipt_sha256"]
        durable_history_latest = durable_history_records[-1]
        durable_history_latest_generation = durable_history_latest["generation"]
        durable_history_latest_receipt_sha256 = durable_history_latest["receipt_sha256"]
        durable_anchor_latest = durable_anchor_records[-1]
        durable_anchor_latest_generation = durable_anchor_latest["generation"]
        durable_anchor_latest_receipt_sha256 = durable_anchor_latest["receipt_sha256"]
        if (
            type(latest_generation) is not int
            or not isinstance(latest_receipt_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", latest_receipt_sha256) is None
            or high_watermark_generation != latest_generation
            or high_watermark_receipt_sha256 != latest_receipt_sha256
            or durable_floor_generation != high_watermark_generation
            or not isinstance(durable_history_latest_generation, int)
            or durable_history_latest_generation != high_watermark_generation
            or durable_history_latest_receipt_sha256 != high_watermark_receipt_sha256
            or not isinstance(durable_anchor_latest_generation, int)
            or durable_anchor_latest_generation != high_watermark_generation
            or durable_anchor_latest_receipt_sha256 != high_watermark_receipt_sha256
        ):
            _raise_redacted_settings_error(
                "M05 activation external monotonic floors do not match the latest ledger record"
            )
        receipt_sha256 = hashlib.sha256(
            receipt_secret.get_secret_value().encode("utf-8")
        ).hexdigest()
        activation_generation = payload["activation_generation"]
        if type(activation_generation) is not int:
            _raise_redacted_settings_error("M05 activation generation is invalid")
        if activation_generation < high_watermark_generation or (
            activation_generation == high_watermark_generation
            and receipt_sha256 != high_watermark_receipt_sha256
        ):
            _raise_redacted_settings_error(
                "M05 activation receipt is below or conflicts with the external high-watermark"
            )
        if (
            latest["activation_generation"] != payload["activation_generation"]
            or latest["activation_nonce"] != payload["activation_nonce"]
            or latest["activation_issued_at"] != payload["activation_issued_at"]
            or latest["activation_expires_at"] != payload["activation_expires_at"]
            or latest["receipt_sha256"] != receipt_sha256
            or latest["scope"] != payload["scope"]
            or latest["source_revision"] != payload["pinvi_source_revision"]
        ):
            _raise_redacted_settings_error(
                "M05 activation receipt does not match the latest ledger generation"
            )


def _decode_base64url(value: object, *, expected_length: int) -> bytes | None:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        return None
    if len(value) % 4 == 1:
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    if len(decoded) != expected_length or _base64url(decoded) != value:
        return None
    return decoded


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _is_canonical_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def _is_non_empty_token_free_string(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(character.isspace() for character in value)
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
