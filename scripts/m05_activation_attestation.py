#!/usr/bin/env python3
"""M05 live UI와 paired runtime의 원격 상태를 독립적으로 검증한다.

``live`` 명령은 다음 순서를 고정한다.

1. Map case detail과 PinVi local receipt를 읽는다.
2. 호출자가 넘긴 실제 Playwright 명령을 실행한다.
3. 같은 두 snapshot을 다시 읽고, read-only UI 흐름 중 drift가 없었는지 확인한다.
4. 컨테이너 image ID/OCI label과 vendored Map OpenAPI를 확인한다.
5. 검증 결과를 signer가 확인할 수 있는 signed attestation으로 봉인한다.

운영에서는 명령행에 secret을 넣지 않는다. Map proxy secret과 PinVi admin 자격은
각각 ``M05_MAP_ADMIN_PROXY_SECRET``, ``M05_PINVI_EMAIL``,
``M05_PINVI_PASSWORD`` 환경변수로만 받는다.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, nullcontext
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)
from uuid import UUID, uuid4

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ModuleNotFoundError as exc:
    if exc.name != "cryptography":
        raise
    _CRYPTOGRAPHY_AVAILABLE = False
else:
    _CRYPTOGRAPHY_AVAILABLE = True

_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PLAYWRIGHT_IMAGE_RE = re.compile(
    r"mcr\.microsoft\.com/playwright(?::[A-Za-z0-9][A-Za-z0-9._-]*)?@sha256:[0-9a-f]{64}\Z"
)
_PAIR_PATH = Path(__file__).resolve().parents[1] / (
    "contracts/kor-travel-map-m05-pair-provenance-v1.json"
)
#: 이 파일이 여러 곳에서 인용하는 `T-VN-PAIR-V2`의 정본 문서는 **Map 저장소**의
#: `docs/tasks-acceptance.md` 같은 이름 절이다(§3~§7이 v1 분기 제거 순서와 롤백을
#: 정한다). 이 저장소에는 없다 — 찾지 못해 코드에서 역추적하는 일이 없도록 여기 적는다.
#: service 표면의 릴리스 revision **정본**. v1 pair 계약은 이 값을 한 벌 더
#: 선언했고(`map.service.source_revision`), 그래서 이 문서가 갱신되지 않아도
#: pair 계약만 바뀌면 두 값이 갈라질 수 있었다. v2는 pair 쪽 사본을 걷어내고
#: 이 문서를 유일한 생산자로 둔다 — `app/core/config.py`가 활성화 receipt의
#: `map_service_source_revision`을 바로 이 값과 대조한다.
_SERVICE_PROVENANCE_PATH = Path(__file__).resolve().parents[1] / (
    "contracts/kor-travel-map-service-provenance-v1.json"
)
#: pair 계약이 담는 네 OpenAPI 표면.
_SURFACES = ("admin", "full", "service", "user")
#: 각 표면이 Map source의 어느 파일에서 나오는가. `admin`과 `full`이 같은 파일인
#: 것은 Map이 그 둘을 같은 문서로 내기 때문이다.
_SURFACE_PATHS = {
    "admin": "packages/kor-travel-map-api/openapi.json",
    "full": "packages/kor-travel-map-api/openapi.json",
    "service": "packages/kor-travel-map-api/openapi.service.json",
    "user": "packages/kor-travel-map-api/openapi.user.json",
}
_ISOLATED_RUNTIME_PROVENANCE_KIND = "m05-isolated-runtime-provenance-v1"
_HOST_TOOL_DIRECTORIES = (Path("/usr/bin"), Path("/bin"))
_M04_MAX_AGE_SECONDS = 15 * 60
_ED25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX = bytes.fromhex("302a300506032b6570032100")


class AttestationError(ValueError):
    """원격 live evidence가 attestation 계약을 위반했다."""


def _openssl_env() -> dict[str, str]:
    """host OpenSSL이 호출자 config/provider override를 상속하지 않게 한다."""

    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    }


@contextmanager
def _temporary_0600_file(raw: bytes) -> Iterator[str]:
    path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b", prefix="pinvi-m05-", dir="/tmp", delete=False
        ) as stream:
            path = stream.name
            os.fchmod(stream.fileno(), 0o600)
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
            ):
                raise AttestationError("OpenSSL temporary key file is unsafe")
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        yield path
    finally:
        if path is not None:
            try:
                os.unlink(path)
            except OSError as exc:
                raise AttestationError("OpenSSL temporary key cleanup failed") from exc


class _OpenSslEd25519PrivateKey:
    """host-only attestation을 위한 최소 Ed25519 signer다.

    Docker Manager의 offline wheelhouse에는 PinVi application dependency를 복제하지
    않는다. cryptography가 없는 trusted host에서는 system OpenSSL의 Ed25519 primitive만
    사용하며, key/payload는 0600 임시 regular file로 한 번의 child 호출에만 준다.
    """

    def __init__(self, raw: bytes) -> None:
        self._raw = raw
        self._assert_ed25519()

    def _run(
        self,
        arguments: list[str],
        *,
        key_option: str,
        payload: bytes | None = None,
    ) -> bytes:
        payload_context = (
            _temporary_0600_file(payload) if payload is not None else nullcontext(None)
        )
        with (
            _temporary_0600_file(self._raw) as key_path,
            payload_context as payload_path,
        ):
            command = [_host_tool("openssl"), *arguments, key_option, key_path]
            if payload_path is not None:
                command.extend(("-in", payload_path))
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    env=_openssl_env(),
                )
            except OSError as exc:
                raise AttestationError(
                    "OpenSSL Ed25519 operation could not run"
                ) from exc
        if completed.returncode != 0:
            raise AttestationError("OpenSSL Ed25519 operation failed")
        return completed.stdout

    def _assert_ed25519(self) -> None:
        details = self._run(["pkey", "-text", "-noout"], key_option="-in")
        if not details.startswith(b"ED25519 Private-Key:\n"):
            raise AttestationError("M05 private key is not Ed25519")

    def sign(self, payload: bytes) -> bytes:
        signature = self._run(
            ["pkeyutl", "-sign", "-rawin"], key_option="-inkey", payload=payload
        )
        if len(signature) != 64:
            raise AttestationError("OpenSSL Ed25519 signature is invalid")
        return signature

    def public_bytes_raw(self) -> bytes:
        encoded = self._run(["pkey", "-pubout", "-outform", "DER"], key_option="-in")
        if len(encoded) != len(
            _ED25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX
        ) + 32 or not encoded.startswith(_ED25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX):
            raise AttestationError("OpenSSL Ed25519 public key is invalid")
        return encoded[len(_ED25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX) :]


def _verify_ed25519_signature(
    public_key_bytes: bytes, signature: bytes, payload: bytes
) -> None:
    if len(public_key_bytes) != 32 or len(signature) != 64:
        raise AttestationError("M04 attestation signature is invalid")
    if _CRYPTOGRAPHY_AVAILABLE:
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
                signature, payload
            )
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise AttestationError("M04 attestation signature is invalid") from exc
        return

    public_key = _ED25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX + public_key_bytes
    with (
        _temporary_0600_file(public_key) as public_key_path,
        _temporary_0600_file(signature) as signature_path,
        _temporary_0600_file(payload) as payload_path,
    ):
        try:
            completed = subprocess.run(
                [
                    _host_tool("openssl"),
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    public_key_path,
                    "-in",
                    payload_path,
                    "-sigfile",
                    signature_path,
                ],
                check=False,
                capture_output=True,
                env=_openssl_env(),
            )
        except OSError as exc:
            raise AttestationError("OpenSSL Ed25519 operation could not run") from exc
    if completed.returncode != 0:
        raise AttestationError("M04 attestation signature is invalid")


def _host_tool(name: str) -> str:
    for directory in _HOST_TOOL_DIRECTORIES:
        candidate = directory / name
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        resolved = candidate.resolve()
        if resolved.parent in _HOST_TOOL_DIRECTORIES:
            return str(resolved)
    raise AttestationError(f"pinned host tool is missing: {name}")


class _NoRedirectHandler(HTTPRedirectHandler):
    """attestation HTTP probe가 다른 loopback 프로세스로 이동하지 않게 한다."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _git_env() -> dict[str, str]:
    """Git subprocess가 호출자의 config·hook·transport override를 상속하지 않게 한다."""

    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("GIT_"):
            env.pop(name)
    env.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
    )
    return env


def _docker_env() -> dict[str, str]:
    """Docker CLI가 원격 context·TLS·대체 config를 선택하지 않게 한다."""

    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("DOCKER_"):
            env.pop(name)
    env.update(
        {
            "DOCKER_HOST": "unix:///var/run/docker.sock",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
    )
    return env


def _direct_opener(*handlers: Any) -> Any:
    """환경변수 proxy와 redirect를 모두 배제한 HTTP opener를 만든다."""

    return build_opener(ProxyHandler({}), *handlers, _NoRedirectHandler())


def _assert_loopback_response(response: Any, *, expected_url: str) -> None:
    """HTTP 응답 URL과 실제 peer가 요청한 loopback endpoint인지 확인한다."""

    try:
        parsed = urlsplit(expected_url)
        host = parsed.hostname
    except ValueError as exc:
        raise AttestationError(f"live HTTP URL is invalid: {expected_url}") from exc
    if parsed.scheme != "http" or host not in {"127.0.0.1", "localhost"}:
        raise AttestationError("live HTTP probe must target a loopback HTTP endpoint")
    if response.geturl() != expected_url:
        raise AttestationError(f"live HTTP response origin changed: {expected_url}")

    raw = getattr(getattr(response, "fp", None), "raw", None)
    sock = getattr(raw, "_sock", None)
    if sock is None:
        raise AttestationError("live HTTP response peer could not be inspected")
    try:
        peer = sock.getpeername()
    except OSError as exc:
        raise AttestationError("live HTTP response peer could not be read") from exc
    peer_host = peer[0] if isinstance(peer, tuple) and peer else peer
    if peer_host not in {"127.0.0.1", "::1"}:
        raise AttestationError("live HTTP response peer is not loopback")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AttestationError("duplicate JSON key")
        result[key] = value
    return result


def _object(value: object, *, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AttestationError(f"{name} must be an object")
    return cast(dict[str, object], value)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _string(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        raise AttestationError(f"{name} must be a non-empty token-free string")
    return value


def _commit(value: object, *, name: str) -> str:
    value = _string(value, name=name)
    if _COMMIT_RE.fullmatch(value) is None:
        raise AttestationError(f"{name} must be a full lowercase commit")
    return value


def _uuid(value: object, *, name: str) -> str:
    value = _string(value, name=name)
    try:
        if str(UUID(value)) != value:
            raise ValueError
    except ValueError as exc:
        raise AttestationError(f"{name} must be a canonical UUID") from exc
    return value


def _container_id(value: object, *, name: str) -> str:
    value = _string(value, name=name)
    if re.fullmatch(r"[0-9a-f]{64}\Z", value) is None:
        raise AttestationError(f"{name} must be a canonical container ID")
    return value


def _read_json(path: Path) -> tuple[object, str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, AttestationError) as exc:
        raise AttestationError(f"invalid JSON evidence: {path.name}") from exc
    return value, _sha256(raw)


def _secure_read(path: Path, *, require_root_owned: bool, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AttestationError(f"{label} is not readable") from exc
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise AttestationError(f"{label} must be a 0600 regular file")
        if require_root_owned and metadata.st_uid != 0:
            raise AttestationError(f"{label} must be root-owned")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            return stream.read()
    finally:
        if fd != -1:
            os.close(fd)


def _write_json(path: Path, value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode(
        "utf-8"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise AttestationError(
            f"evidence output already exists or is unsafe: {path.name}"
        ) from exc
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd != -1:
            os.close(fd)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(path.parent, directory_flags)
    except OSError as exc:
        raise AttestationError(
            f"evidence output directory is not durable: {path.parent.name}"
        ) from exc
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        raise AttestationError(
            f"evidence output directory is not durable: {path.parent.name}"
        ) from exc
    finally:
        os.close(directory_fd)
    return _sha256(raw)


#: v1은 surface마다 `source_revision`을, 최상위에 `runtime_image_digests`를 갖는다.
#: 둘 다 pin registry/Manager receipt가 정본인 값의 **두 번째 선언**이라 v2가 걷어낸다
#: (`T-VN-PAIR-V2`, `AGENTS.md` DO NOT 15). v2에서는 그 값을 호출부가 배선해 준다.
_PAIR_V1_ENTRY_KEYS = {
    "openapi_sha256",
    "runtime_operation_contract_sha256",
    "source_canonical_sha256",
    "source_operation_contract_sha256",
    "source_revision",
}
_PAIR_V2_ENTRY_KEYS = _PAIR_V1_ENTRY_KEYS - {"source_revision"}


def _load_pair() -> tuple[dict[str, dict[str, str]], int]:
    raw, _ = _read_json(_PAIR_PATH)
    envelope = _object(raw, name="Map pair provenance")
    version = envelope.get("version")
    if version == 1:
        expected_envelope = {"map", "runtime_image_digests", "version"}
    elif version == 2:
        expected_envelope = {"map", "version"}
    else:
        raise AttestationError("Map pair provenance envelope is invalid")
    if set(envelope) != expected_envelope:
        raise AttestationError("Map pair provenance envelope is invalid")
    map_value = _object(envelope["map"], name="Map pair provenance map")
    if set(map_value) != {"admin", "full", "service", "user"}:
        raise AttestationError("Map pair provenance inventory is invalid")
    runtime_images: dict[str, object] = {}
    if version == 1:
        runtime_images = _object(
            envelope["runtime_image_digests"], name="Map runtime image digests"
        )
        if set(runtime_images) != {"admin", "api", "frontend"}:
            raise AttestationError("Map runtime image digest inventory is invalid")
    result: dict[str, dict[str, str]] = {}
    for name in ("admin", "full", "service", "user"):
        entry = _object(map_value[name], name=f"Map pair {name}")
        if set(entry) != (
            _PAIR_V1_ENTRY_KEYS if version == 1 else _PAIR_V2_ENTRY_KEYS
        ):
            raise AttestationError(f"Map pair {name} schema is invalid")
        digest = _string(entry["openapi_sha256"], name=f"{name}.openapi_sha256")
        if _SHA256_RE.fullmatch(digest) is None:
            raise AttestationError(f"{name}.openapi_sha256 is invalid")
        source_canonical = _string(
            entry["source_canonical_sha256"], name=f"{name}.source_canonical_sha256"
        )
        runtime_operation_contract = _string(
            entry["runtime_operation_contract_sha256"],
            name=f"{name}.runtime_operation_contract_sha256",
        )
        source_operation_contract = _string(
            entry["source_operation_contract_sha256"],
            name=f"{name}.source_operation_contract_sha256",
        )
        if (
            _SHA256_RE.fullmatch(source_canonical) is None
            or _SHA256_RE.fullmatch(runtime_operation_contract) is None
            or _SHA256_RE.fullmatch(source_operation_contract) is None
        ):
            raise AttestationError(f"{name} OpenAPI provenance hash is invalid")
        result[name] = {
            "openapi_sha256": digest,
            "runtime_operation_contract_sha256": runtime_operation_contract,
            "source_canonical_sha256": source_canonical,
            "source_operation_contract_sha256": source_operation_contract,
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
    result["runtime_image_digests"] = {}
    for name in ("admin", "api", "frontend") if version == 1 else ():
        digest = _string(runtime_images[name], name=f"runtime_image_digests.{name}")
        if _DIGEST_RE.fullmatch(digest) is None:
            raise AttestationError(f"runtime_image_digests.{name} is invalid")
        result["runtime_image_digests"][name] = digest
    return result, version


def _isolated_image_id(value: object, *, name: str) -> str:
    image_id = _string(value, name=name)
    if _DIGEST_RE.fullmatch(image_id) is None:
        raise AttestationError(f"{name} is invalid")
    return image_id


def _load_isolated_runtime_provenance(
    path: Path,
    *,
    pair: dict[str, dict[str, str]],
    pinvi_source_revision: str,
    expected_manager_source_revision: str,
    expected_pinset_sha256: str,
    expected_execution_identity_sha256: str,
    require_root_owned: bool,
) -> dict[str, object]:
    """Manager의 root-only isolated image/source receipt를 M05 runtime에 결박한다."""

    raw = _secure_read(
        path,
        require_root_owned=require_root_owned,
        label="M05 isolated runtime provenance",
    )
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, AttestationError) as exc:
        raise AttestationError("M05 isolated runtime provenance is invalid") from exc
    envelope = _object(value, name="M05 isolated runtime provenance")
    if (
        set(envelope)
        != {
            "kind",
            "execution_identity_sha256",
            "manager_source_revision",
            "map",
            "pinset_sha256",
            "pinvi",
            "transaction_id",
            "version",
        }
        or envelope["kind"] != _ISOLATED_RUNTIME_PROVENANCE_KIND
        or envelope["version"] != 1
    ):
        raise AttestationError("M05 isolated runtime provenance schema is invalid")
    manager_revision = _commit(
        envelope["manager_source_revision"], name="M05 isolated Manager source revision"
    )
    if manager_revision != _commit(
        expected_manager_source_revision, name="expected isolated Manager source revision"
    ):
        raise AttestationError("M05 isolated Manager source revision differs from expectation")
    pinset = _string(envelope["pinset_sha256"], name="M05 isolated pinset")
    transaction = _string(envelope["transaction_id"], name="M05 isolated transaction")
    if (
        _SHA256_RE.fullmatch(pinset) is None
        or re.fullmatch(r"[0-9a-f]{32}\Z", transaction) is None
    ):
        raise AttestationError("M05 isolated runtime provenance identity is invalid")
    if pinset != _string(expected_pinset_sha256, name="expected isolated pinset"):
        raise AttestationError("M05 isolated pinset differs from expectation")
    execution_identity = _string(
        envelope["execution_identity_sha256"], name="M05 isolated execution identity"
    )
    if _SHA256_RE.fullmatch(execution_identity) is None:
        raise AttestationError("M05 isolated execution identity is invalid")
    if execution_identity != _string(
        expected_execution_identity_sha256, name="expected isolated execution identity"
    ):
        raise AttestationError("M05 isolated execution identity differs from expectation")
    map_value = _object(envelope["map"], name="M05 isolated Map runtime")
    if set(map_value) != {
        "admin_image_id",
        "api_image_id",
        "frontend_image_id",
        "full_openapi_sha256",
        "source_revision",
    }:
        raise AttestationError("M05 isolated Map runtime schema is invalid")
    isolated_map_revision = _commit(
        map_value["source_revision"], name="M05 isolated Map source revision"
    )
    # v1 계약은 Map revision을 **스스로 선언**해서 여기서 교차 대조가 가능했다. v2는 그
    # 선언을 걷어냈고 정본은 Manager pin registry가 만든 이 envelope 하나다 — 대조 상대가
    # 사라지는 것이 v2의 목적이다(이중 선언 제거). digest 대조는 v1·v2 모두 그대로 한다.
    pair_revision = pair["full"].get("source_revision")
    if (
        pair_revision is not None and isolated_map_revision != pair_revision
    ) or map_value["full_openapi_sha256"] != pair["full"]["openapi_sha256"]:
        raise AttestationError("M05 isolated Map runtime provenance differs from the pair")
    map_images = {
        "admin": _isolated_image_id(
            map_value["admin_image_id"], name="M05 isolated Map admin image"
        ),
        "api": _isolated_image_id(
            map_value["api_image_id"], name="M05 isolated Map API image"
        ),
        "frontend": _isolated_image_id(
            map_value["frontend_image_id"], name="M05 isolated Map frontend image"
        ),
    }
    pinvi_value = _object(envelope["pinvi"], name="M05 isolated PinVi runtime")
    if set(pinvi_value) != {
        "api_image_id",
        "dagster_image_id",
        "source_revision",
        "web_image_id",
    }:
        raise AttestationError("M05 isolated PinVi runtime schema is invalid")
    if (
        _commit(pinvi_value["source_revision"], name="M05 isolated PinVi source revision")
        != pinvi_source_revision
    ):
        raise AttestationError("M05 isolated PinVi runtime provenance differs from the source")
    pinvi_images = {
        "api": _isolated_image_id(
            pinvi_value["api_image_id"], name="M05 isolated PinVi API image"
        ),
        "web": _isolated_image_id(
            pinvi_value["web_image_id"], name="M05 isolated PinVi Web image"
        ),
        "dagster": _isolated_image_id(
            pinvi_value["dagster_image_id"], name="M05 isolated PinVi Dagster image"
        ),
    }
    return {
        "execution_identity_sha256": execution_identity,
        "manager_source_revision": manager_revision,
        "map_images": map_images,
        "map_source_revision": isolated_map_revision,
        "pinset_sha256": pinset,
        "pinvi_images": pinvi_images,
        "sha256": _sha256(raw),
    }


def _url(base: str, path: str) -> str:
    base = _string(base.rstrip("/"), name="URL")
    if not base.startswith(("http://", "https://")):
        raise AttestationError("URL must use http or https")
    return f"{base}{path}"


def _assert_clean_checkout(
    root: Path,
    *,
    expected_revision: str,
    label: str,
    allowed_revisions: set[str] | None = None,
) -> None:
    """producer가 dirty/임의 checkout에서 실행되지 않도록 source identity를 고정한다."""

    if root.is_symlink() or not root.is_dir():
        raise AttestationError(f"{label} must be a regular directory")
    try:
        top = subprocess.run(
            [_host_tool("git"), "-C", str(root), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
            env=_git_env(),
        ).stdout.strip()
        revision = subprocess.run(
            [_host_tool("git"), "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            env=_git_env(),
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
            env=_git_env(),
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AttestationError(f"{label} git identity could not be verified") from exc
    if Path(top).resolve() != root.resolve() or status:
        raise AttestationError(f"{label} checkout must be clean and canonical")
    if allowed_revisions is not None:
        if revision not in allowed_revisions:
            raise AttestationError(f"{label} HEAD is not one of the pinned revisions")
    elif revision != expected_revision:
        raise AttestationError(f"{label} HEAD does not match the pinned revision")


def _assert_docker_endpoint(
    item: dict[str, object], *, container: str, endpoint_url: str, container_port: int
) -> None:
    """HTTP 대상이 caller가 고른 임의 서버가 아니라 지정 container의 host binding인지 확인한다."""

    try:
        parsed = urlsplit(endpoint_url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise AttestationError(f"service endpoint is invalid for {container}") from exc
    if (
        parsed.scheme != "http"
        or host not in {"127.0.0.1", "localhost"}
        or port is None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise AttestationError(
            f"service endpoint must be a loopback HTTP root for {container}"
        )
    network = _object(item.get("NetworkSettings"), name=f"docker network {container}")
    ports = network.get("Ports")
    if not isinstance(ports, dict):
        raise AttestationError(f"docker endpoint binding is missing for {container}")
    bindings = ports.get(f"{container_port}/tcp")
    if not isinstance(bindings, list) or not any(
        isinstance(binding, dict)
        and str(binding.get("HostPort")) == str(port)
        and binding.get("HostIp") == "127.0.0.1"
        for binding in bindings
    ):
        raise AttestationError(f"service endpoint is not bound to {container}")


def _http_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    opener: Any | None = None,
    method: str = "GET",
    body: object | None = None,
) -> tuple[object, bytes]:
    request = Request(
        url,
        data=None if body is None else _canonical_json(body),
        headers={"Accept": "application/json", **(headers or {})},
        method=method,
    )
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with (opener or _direct_opener()).open(request, timeout=30) as response:
            if 300 <= response.status < 400:
                raise AttestationError(f"live HTTP redirect is not allowed: {url}")
            if not 200 <= response.status < 300:
                raise AttestationError(
                    f"live HTTP response status is not successful: {url}"
                )
            _assert_loopback_response(response, expected_url=url)
            raw = response.read()
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise AttestationError(
            f"live HTTP verification failed: {url} [{_http_failure_diagnostic(exc)}]"
        ) from exc
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicate_keys), raw
    except (UnicodeDecodeError, json.JSONDecodeError, AttestationError) as exc:
        raise AttestationError(f"live HTTP response is not valid JSON: {url}") from exc


_TRANSPORT_DIAGNOSTICS: frozenset[str] = frozenset(
    {
        "BadStatusLine",
        "ConnectionAbortedError",
        "ConnectionRefusedError",
        "ConnectionResetError",
        "IncompleteRead",
        "RemoteDisconnected",
        "TimeoutError",
        "gaierror",
    }
)


def _http_failure_diagnostic(exc: BaseException) -> str:
    """live HTTP 실패를 **비밀 없는 고정 어휘**로 좁힌다.

    종전에는 `HTTPError`·`URLError`·`TimeoutError`·`OSError`가 한 문자열로 접혀
    429(스로틀)·401(자격증명)·ConnectionRefused(컨테이너 헬스)가 구분되지 않았다.
    셋의 처방이 서로 배타적인데 증거는 하나였다 — 2026-09-02에 그 때문에
    1~2시간짜리 격리 실행 1회를 태우고도 원인을 몰랐다.

    내보내는 값의 생산자는 둘뿐이다: `HTTPError.code`(http.client가 만든 int, 범위
    검증 후) 와 stdlib 예외 클래스명. 어느 쪽도 요청 헤더(proxy secret)·본문
    (email/password)·환경변수·파일경로에서 파생되지 않는다. 구조적으로 비밀이 될 수
    없다.

    `str(HTTPError)`·`exc.read()`·`exc.headers`·`str(URLError.reason)`은 **쓰지
    않는다** — 응답 본문·헤더·원문 사유가 섞일 수 있다.
    """

    if isinstance(exc, HTTPError):
        code = exc.code
        if type(code) is int and 100 <= code <= 599:
            return f"http_status_{code}"
        return "http_status_invalid"
    reason = getattr(exc, "reason", None)
    name = type(reason if isinstance(reason, BaseException) else exc).__name__
    return f"transport_{name}" if name in _TRANSPORT_DIAGNOSTICS else "transport_other"


def _data(value: object, *, name: str) -> dict[str, object]:
    envelope = _object(value, name=name)
    data = envelope.get("data")
    return _object(data, name=f"{name}.data")


def _map_headers() -> dict[str, str]:
    secret = os.environ.get("M05_MAP_ADMIN_PROXY_SECRET", "")
    actor = os.environ.get("M05_MAP_ADMIN_ACTOR", "pinvi-m05-attestation")
    if not secret or any(char.isspace() for char in secret):
        raise AttestationError(
            "M05_MAP_ADMIN_PROXY_SECRET must be supplied via environment"
        )
    return {
        "X-Kor-Travel-Map-Admin-Proxy-Secret": secret,
        "X-Kor-Travel-Map-Actor": _string(actor, name="M05_MAP_ADMIN_ACTOR"),
    }


def _m04_server_side_chain(
    *,
    map_admin_url: str,
    m04: dict[str, str],
    map_case: dict[str, object],
) -> dict[str, str]:
    """M04 UI receipt의 Map request가 M05 old Feature와 같은 객체인지 결박한다."""

    request_id = _uuid(m04["feature_request_id"], name="M04 feature request ID")
    value, _ = _http_json(
        _url(map_admin_url, f"/v1/admin/feature-requests/{request_id}"),
        headers=_map_headers(),
    )
    request_data = _data(value, name="Map M04 feature request")
    if _uuid(request_data.get("request_id"), name="Map M04 request ID") != request_id:
        raise AttestationError("Map M04 request does not match the UI receipt")
    if request_data.get("status") != "approved":
        raise AttestationError("Map M04 request is not approved")
    # 승인 응답의 feature_id는 T-VN-32C 규약대로 **UUID 정본**이고, provenance
    # 리더의 최상위 feature_id는 해석된 opaque TEXT storage identity다(Map
    # admin_features 모델 주석). 결박은 feature_uuid 축으로 해야 한다 — TEXT와
    # UUID의 동일성 요구는 원리적으로 항상 실패한다(적대 리뷰, e2e15 이후
    # 잠재 관문으로 실측 예측됨).
    feature_ref = _uuid(request_data.get("feature_id"), name="Map M04 feature ref")
    provenance_value, _ = _http_json(
        _url(
            map_admin_url,
            f"/v1/admin/features/{quote(feature_ref, safe='')}/creation-provenance",
        ),
        headers=_map_headers(),
    )
    provenance = _data(provenance_value, name="Map M04 feature provenance")
    feature_id = _string(provenance.get("feature_id"), name="Map M04 feature ID")
    feature_uuid = _uuid(provenance.get("feature_uuid"), name="Map M04 feature UUID")
    if feature_uuid != feature_ref:
        raise AttestationError("Map M04 provenance does not match the approved feature")
    origin = _object(provenance.get("origin"), name="Map M04 feature origin")
    if origin.get("origin_kind") != "manual_request":
        raise AttestationError("Map M04 feature origin is not manual_request")

    manual_feature = _object(
        map_case.get("manual_feature"), name="Map M05 manual feature"
    )
    manual_feature_id = _string(
        manual_feature.get("feature_id"), name="Map M05 manual feature ID"
    )
    manual_feature_uuid = _uuid(
        manual_feature.get("feature_uuid"), name="Map M05 manual feature UUID"
    )
    event = _object(map_case.get("event"), name="Map M05 event")
    old_feature = _object(event.get("old_feature"), name="Map M05 old feature")
    old_feature_id = _string(old_feature.get("feature_id"), name="Map M05 old feature ID")
    old_feature_uuid = _uuid(
        old_feature.get("feature_uuid"), name="Map M05 old feature UUID"
    )
    if (
        feature_id != manual_feature_id
        or feature_id != old_feature_id
        or feature_uuid != manual_feature_uuid
        or manual_feature_uuid != old_feature_uuid
    ):
        raise AttestationError(
            "M04 approved feature does not match the M05 old feature"
        )
    return {
        "feature_request_id": request_id,
        "map_feature_id": feature_id,
        "map_feature_uuid": feature_uuid,
        "map_provenance_sha256": _sha256(_canonical_json(provenance)),
        "map_request_sha256": _sha256(_canonical_json(request_data)),
    }


def _map_case_snapshot(
    *,
    map_admin_url: str,
    case_id: str,
    event_id: str,
) -> tuple[dict[str, object], dict[str, object], str, str]:
    value, _ = _http_json(
        _url(map_admin_url, f"/v1/admin/manual-provider-dedup-cases/{case_id}"),
        headers=_map_headers(),
    )
    data = _data(value, name="Map case detail")
    if data.get("status") != "terminal":
        raise AttestationError("Map M05 case is not terminal")
    event = _object(data.get("event"), name="Map case event")
    if _uuid(event.get("event_id"), name="Map event ID") != event_id:
        raise AttestationError("Map case event does not match the requested event")
    event_sha_value = event.get("event_sha256")
    event_sha: str | None = (
        _string(event_sha_value, name="Map event hash")
        if event_sha_value is not None
        else None
    )
    sequence = event.get("event_sequence")
    if type(sequence) is not int or sequence < 1:
        raise AttestationError("Map event sequence is invalid")
    subscriptions = data.get("subscriptions")
    if not isinstance(subscriptions, list):
        raise AttestationError("Map subscription delivery evidence is missing")
    expected_principal = "service:feature-reference-reconciliation"
    matching = [
        _object(item, name="Map subscription")
        for item in subscriptions
        if isinstance(item, dict) and item.get("principal_id") == expected_principal
    ]
    if len(matching) != 1:
        raise AttestationError("Map M05 service subscription is not unique")
    subscription = matching[0]
    acked = subscription.get("acked_through_sequence")
    if type(acked) is not int or acked < sequence:
        raise AttestationError("Map ACK cursor has not reached the event")
    ack = _object(subscription.get("ack"), name="Map ACK")
    if _uuid(ack.get("event_id"), name="Map ACK event ID") != event_id:
        raise AttestationError("Map ACK does not bind to the event")
    ack_sha = _string(ack.get("event_sha256"), name="Map ACK event hash")
    if event_sha is None:
        # The current Map case-detail projection exposes the immutable hash on
        # the ACK, while its event payload omits the column. The ACK is still
        # bound to this event ID and sequence, so use that hash as the proof.
        event_sha = ack_sha
    if _SHA256_RE.fullmatch(event_sha) is None or ack_sha != event_sha:
        raise AttestationError("Map event hash is invalid")
    local_receipt_sha = _string(
        ack.get("local_receipt_sha256"), name="Map local receipt hash"
    )
    if _SHA256_RE.fullmatch(local_receipt_sha) is None:
        raise AttestationError("Map local receipt hash is invalid")
    map_data_hash = _sha256(_canonical_json(data))
    ack_hash = _sha256(_canonical_json(ack))
    return data, ack, map_data_hash, ack_hash


def _map_case_event_hash(data: dict[str, object], ack: dict[str, object]) -> str:
    """Return the Map event hash, using the ACK projection when event hash is omitted."""

    event = _object(data.get("event"), name="Map case event")
    event_sha_value = event.get("event_sha256")
    event_sha = (
        _string(event_sha_value, name="Map event hash")
        if event_sha_value is not None
        else _string(ack.get("event_sha256"), name="Map ACK event hash")
    )
    if _SHA256_RE.fullmatch(event_sha) is None:
        raise AttestationError("Map event hash is invalid")
    return event_sha


def _pinvi_case_event_hash(data: dict[str, object]) -> str:
    receipt = _object(data.get("receipt"), name="Pinvi local receipt")
    event_sha = _string(receipt.get("event_sha256"), name="Pinvi receipt event hash")
    if _SHA256_RE.fullmatch(event_sha) is None:
        raise AttestationError("Pinvi receipt event hash is invalid")
    return event_sha


def _pinvi_admin_opener(*, pinvi_api_url: str, email: str, password: str) -> Any:
    if not email or not password:
        raise AttestationError("Pinvi admin email and password are required")
    cookie_jar = CookieJar()
    opener = _direct_opener(HTTPCookieProcessor(cookie_jar))
    login, _ = _http_json(
        _url(pinvi_api_url, "/auth/login"),
        opener=opener,
        method="POST",
        body={"email": email, "password": password},
    )
    login_data = _data(login, name="Pinvi login")
    roles = login_data.get("roles")
    if not isinstance(roles, list) or not any(
        role in {"admin", "operator", "cpo"} for role in roles
    ):
        raise AttestationError("Pinvi live account is not an admin role")
    return opener


def _pinvi_m04_approval_snapshot(
    *,
    pinvi_api_url: str,
    request_id: str,
    email: str,
    password: str,
) -> dict[str, str]:
    """Pinvi가 저장한 M04 승인 결과를 marker fingerprint와 독립적으로 다시 계산한다."""

    request_id = _uuid(request_id, name="M04 feature request ID")
    opener = _pinvi_admin_opener(
        pinvi_api_url=pinvi_api_url,
        email=email,
        password=password,
    )
    value, _ = _http_json(
        _url(pinvi_api_url, "/admin/feature-requests?status=approved&limit=100"),
        opener=opener,
    )
    page = _data(value, name="Pinvi M04 approved feature requests")
    items = page.get("items")
    if not isinstance(items, list):
        raise AttestationError("Pinvi M04 approved feature-request list is invalid")
    matches = [
        _object(item, name="Pinvi M04 approved feature request")
        for item in items
        if isinstance(item, dict) and item.get("request_id") == request_id
    ]
    if len(matches) != 1:
        raise AttestationError(
            "Pinvi M04 approved feature request is not uniquely present"
        )
    item = matches[0]
    if item.get("status") != "approved":
        raise AttestationError("Pinvi M04 feature request is not approved")
    map_receipt = _object(item.get("kor_travel_map_ref"), name="Pinvi M04 Map receipt")
    if (
        _uuid(map_receipt.get("request_id"), name="Pinvi M04 Map request ID")
        != request_id
        or map_receipt.get("state") != "pending"
        or map_receipt.get("review_mode") != "feature_request_queue"
        or map_receipt.get("action") != "submit"
    ):
        raise AttestationError("Pinvi M04 Map pending receipt is invalid")
    approval = {
        "kor_travel_map_ref": map_receipt,
        "request_id": request_id,
        "resolved_at": _string(item.get("resolved_at"), name="Pinvi M04 resolved_at"),
        "reviewed_by_admin_id": _uuid(
            item.get("reviewed_by_admin_id"), name="Pinvi M04 reviewer ID"
        ),
        "status": "approved",
    }
    return {
        "map_pending_receipt_sha256": _sha256(_canonical_json(map_receipt)),
        "pinvi_approval_sha256": _sha256(_canonical_json(approval)),
    }


def _pinvi_case_snapshot(
    *,
    pinvi_api_url: str,
    event_id: str,
    email: str,
    password: str,
) -> tuple[dict[str, object], str, str]:
    opener = _pinvi_admin_opener(
        pinvi_api_url=pinvi_api_url,
        email=email,
        password=password,
    )
    value, _ = _http_json(
        _url(pinvi_api_url, f"/admin/feature-reference-reconciliations/{event_id}"),
        opener=opener,
    )
    data = _data(value, name="Pinvi M05 detail")
    if data.get("status") != "applied":
        raise AttestationError("Pinvi M05 local receipt is not applied")
    receipt = _object(data.get("receipt"), name="Pinvi local receipt")
    if _uuid(receipt.get("event_id"), name="Pinvi receipt event ID") != event_id:
        raise AttestationError("Pinvi receipt does not match the requested event")
    event_sha = _string(receipt.get("event_sha256"), name="Pinvi receipt event hash")
    if _SHA256_RE.fullmatch(event_sha) is None:
        raise AttestationError("Pinvi receipt event hash is invalid")
    receipt_sha = _string(receipt.get("receipt_sha256"), name="Pinvi receipt hash")
    if _SHA256_RE.fullmatch(receipt_sha) is None:
        raise AttestationError("Pinvi receipt hash is invalid")
    attempts = data.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        raise AttestationError("Pinvi M05 delivery attempts are missing")
    latest = _object(attempts[0], name="Pinvi latest attempt")
    if latest.get("status") != "applied" or latest.get("event_sha256") != event_sha:
        raise AttestationError("Pinvi latest attempt is not the applied event")
    impacts = data.get("impacts")
    if not isinstance(impacts, list) or len(impacts) != receipt.get("impact_count"):
        raise AttestationError("Pinvi impact count does not match its terminal receipt")
    return data, _sha256(_canonical_json(data)), receipt_sha


def _map_feature_reference(value: object, *, name: str) -> dict[str, object]:
    reference = _object(value, name=name)
    row_revision = reference.get("row_revision")
    if type(row_revision) is not int or row_revision < 1:
        raise AttestationError(f"{name}.row_revision is invalid")
    return {
        "feature_id": _string(reference.get("feature_id"), name=f"{name}.feature_id"),
        "feature_uuid": _uuid(
            reference.get("feature_uuid"), name=f"{name}.feature_uuid"
        ),
        "row_revision": row_revision,
    }


def _validate_pinvi_impact_evidence(
    value: dict[str, object],
    *,
    map_case: dict[str, object],
    map_ack: dict[str, object],
) -> None:
    """PinVi local rows와 Map event material에서 terminal receipt를 재계산한다."""

    map_event = _object(map_case.get("event"), name="Map M05 event")
    event_id = _uuid(map_event.get("event_id"), name="Map M05 event ID")
    event_sha = _map_case_event_hash(map_case, map_ack)
    event_sequence = map_event.get("event_sequence")
    if type(event_sequence) is not int or event_sequence < 1:
        raise AttestationError("Map M05 event sequence is invalid")
    action = map_event.get("action")
    if action not in {"rebind", "detach"}:
        raise AttestationError("Map M05 event action is invalid")
    old_feature = _map_feature_reference(
        map_event.get("old_feature"), name="Map M05 old feature"
    )
    replacement_value = map_event.get("replacement_feature")
    replacement_feature = (
        None
        if replacement_value is None
        else _map_feature_reference(
            replacement_value, name="Map M05 replacement feature"
        )
    )
    if (action == "rebind") != (replacement_feature is not None):
        raise AttestationError("Map M05 action and replacement feature disagree")

    receipt = _object(value.get("receipt"), name="PinVi local receipt")
    if value.get("status") != "applied":
        raise AttestationError("PinVi M05 local receipt is not applied")
    if _uuid(receipt.get("event_id"), name="PinVi receipt event ID") != event_id:
        raise AttestationError("PinVi receipt does not match the Map event")
    if receipt.get("event_sequence") != event_sequence:
        raise AttestationError(
            "PinVi receipt event sequence does not match the Map event"
        )
    if receipt.get("event_sha256") != event_sha:
        raise AttestationError("PinVi receipt event hash does not match the Map event")
    if receipt.get("action") != action:
        raise AttestationError("PinVi receipt action does not match the Map event")
    if (
        receipt.get("old_feature_id") != old_feature["feature_id"]
        or _uuid(receipt.get("old_feature_uuid"), name="PinVi receipt old feature UUID")
        != old_feature["feature_uuid"]
    ):
        raise AttestationError(
            "PinVi receipt old feature pair does not match the Map event"
        )

    receipt_replacement_id = receipt.get("replacement_feature_id")
    receipt_replacement_uuid = receipt.get("replacement_feature_uuid")
    if replacement_feature is None:
        if receipt_replacement_id is not None or receipt_replacement_uuid is not None:
            raise AttestationError("detach receipt contains a replacement feature")
    elif (
        receipt_replacement_id != replacement_feature["feature_id"]
        or _uuid(
            receipt_replacement_uuid, name="PinVi receipt replacement feature UUID"
        )
        != replacement_feature["feature_uuid"]
    ):
        raise AttestationError(
            "PinVi receipt replacement pair does not match the Map event"
        )

    impacts_value = value.get("impacts")
    if not isinstance(impacts_value, list):
        raise AttestationError("PinVi impact rows are missing")
    impact_count = receipt.get("impact_count")
    if (
        type(impact_count) is not int
        or impact_count < 0
        or len(impacts_value) != impact_count
    ):
        raise AttestationError("PinVi impact count does not match its terminal receipt")

    expected_keys = {
        "event_id",
        "impact_index",
        "target_relation",
        "target_id",
        "old_feature_id",
        "old_feature_uuid",
        "replacement_feature_id",
        "replacement_feature_uuid",
        "outcome",
        "recorded_at",
    }
    canonical_impacts: list[dict[str, object]] = []
    targets: set[tuple[str, str]] = set()
    for expected_index, raw_impact in enumerate(impacts_value):
        impact = _object(raw_impact, name="PinVi impact row")
        if set(impact) != expected_keys:
            raise AttestationError("PinVi impact row schema is invalid")
        if _uuid(impact.get("event_id"), name="PinVi impact event ID") != event_id:
            raise AttestationError("PinVi impact row does not match the Map event")
        if impact.get("impact_index") != expected_index:
            raise AttestationError("PinVi impact indexes are not contiguous")
        relation = impact.get("target_relation")
        if relation not in {
            "trip_day_pois",
            "curated_plan_pois",
            "feature_suggestions",
        }:
            raise AttestationError("PinVi impact target relation is invalid")
        target_id = _uuid(impact.get("target_id"), name="PinVi impact target ID")
        target_key = (relation, target_id)
        if target_key in targets:
            raise AttestationError("PinVi impact targets are duplicated")
        targets.add(target_key)
        if (
            impact.get("old_feature_id") != old_feature["feature_id"]
            or _uuid(
                impact.get("old_feature_uuid"), name="PinVi impact old feature UUID"
            )
            != old_feature["feature_uuid"]
        ):
            raise AttestationError("PinVi impact old feature pair is invalid")
        if replacement_feature is None:
            if (
                impact.get("replacement_feature_id") is not None
                or impact.get("replacement_feature_uuid") is not None
            ):
                raise AttestationError("detach impact contains a replacement feature")
            replacement_canonical = None
        else:
            if (
                impact.get("replacement_feature_id")
                != replacement_feature["feature_id"]
                or _uuid(
                    impact.get("replacement_feature_uuid"),
                    name="PinVi impact replacement feature UUID",
                )
                != replacement_feature["feature_uuid"]
            ):
                raise AttestationError("PinVi impact replacement pair is invalid")
            replacement_canonical = replacement_feature
        if impact.get("outcome") != action:
            raise AttestationError("PinVi impact outcome does not match the Map action")
        canonical_impacts.append(
            {
                "target_relation": relation,
                "target_id": target_id,
                "old_feature": old_feature,
                "replacement_feature": replacement_canonical,
                "outcome": action,
            }
        )

    ordered_impacts = sorted(
        canonical_impacts,
        key=lambda row: (str(row["target_relation"]), str(row["target_id"])),
    )
    if canonical_impacts != ordered_impacts:
        raise AttestationError("PinVi impact rows are not in canonical order")
    impact_root = _sha256(_canonical_json(ordered_impacts))
    if receipt.get("impact_root_sha256") != impact_root:
        raise AttestationError(
            "PinVi receipt impact root does not match its impact rows"
        )
    receipt_sha = _string(receipt.get("receipt_sha256"), name="PinVi receipt hash")
    expected_receipt_sha = _sha256(
        _canonical_json(
            {
                "version": "pinvi-feature-reference-reconciliation-receipt-v1",
                "event_id": event_id,
                "event_sequence": event_sequence,
                "event_sha256": event_sha,
                "action": action,
                "old_feature": old_feature,
                "replacement_feature": replacement_feature,
                "impact_root_sha256": impact_root,
                "impact_count": impact_count,
            }
        )
    )
    if receipt_sha != expected_receipt_sha:
        raise AttestationError("PinVi receipt hash does not match its receipt material")

    attempts = value.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        raise AttestationError("PinVi M05 delivery attempts are missing")
    latest = _object(attempts[0], name="PinVi latest attempt")
    if (
        latest.get("status") != "applied"
        or _uuid(latest.get("event_id"), name="PinVi latest attempt event ID")
        != event_id
        or latest.get("event_sequence") != event_sequence
        or latest.get("event_sha256") != event_sha
        or latest.get("block_fingerprint_sha256") is not None
    ):
        raise AttestationError("PinVi latest applied attempt is invalid")
    observation_root = _sha256(
        _canonical_json(
            {
                "version": "pinvi-feature-reference-reconciliation-observation-v1",
                "event_id": event_id,
                "event_sequence": event_sequence,
                "event_sha256": event_sha,
                "blocks": [],
                "impacts": ordered_impacts,
            }
        )
    )
    if latest.get("observation_root_sha256") != observation_root:
        raise AttestationError(
            "PinVi applied observation root does not match its impact rows"
        )


def _docker_inspect(
    container: str,
    *,
    expected_revision: str,
    expected_environment: str,
    require_environment_label: bool = True,
    expected_image_digest: str | None = None,
    expected_compose_project: str | None = None,
    expected_compose_service: str | None = None,
    endpoint_url: str | None = None,
    endpoint_container_port: int = 8000,
) -> dict[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", container):
        raise AttestationError("container name is invalid")
    try:
        completed = subprocess.run(
            [_host_tool("docker"), "inspect", "--format", "{{json .}}", container],
            check=True,
            capture_output=True,
            text=True,
            env=_docker_env(),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AttestationError(f"docker inspect failed for {container}") from exc
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AttestationError(
            f"docker inspect output is invalid for {container}"
        ) from exc
    item = _object(value, name=f"docker inspect {container}")
    container_id = item.get("Id")
    if (
        not isinstance(container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}\Z", container_id) is None
    ):
        raise AttestationError(f"runtime container ID is invalid for {container}")
    state = _object(item.get("State"), name=f"docker state {container}")
    if state.get("Running") is not True:
        raise AttestationError(f"runtime container is not running for {container}")
    started_at = _string(state.get("StartedAt"), name=f"{container}.state.started_at")
    image_id = item.get("Image")
    if not isinstance(image_id, str) or _DIGEST_RE.fullmatch(image_id) is None:
        raise AttestationError(f"runtime image ID is not immutable for {container}")
    if expected_image_digest is not None and image_id != expected_image_digest:
        raise AttestationError(f"runtime image digest mismatch for {container}")
    config = _object(item.get("Config"), name=f"docker config {container}")
    labels = config.get("Labels")
    labels = (
        _object(labels, name=f"docker labels {container}") if labels is not None else {}
    )
    revision = _string(
        labels.get("org.opencontainers.image.revision"),
        name=f"{container}.org.opencontainers.image.revision",
    )
    if revision != expected_revision:
        raise AttestationError(f"runtime source revision mismatch for {container}")
    environment_label = labels.get("io.pinvi.build.environment")
    if require_environment_label and environment_label is None:
        raise AttestationError(
            f"runtime build environment label is missing for {container}"
        )
    if (
        environment_label is not None
        and _string(environment_label, name=f"{container}.io.pinvi.build.environment")
        != expected_environment
    ):
        raise AttestationError(f"runtime build environment mismatch for {container}")
    compose_project = labels.get("com.docker.compose.project")
    compose_service = labels.get("com.docker.compose.service")
    compose_project = (
        _string(compose_project, name=f"{container}.com.docker.compose.project")
        if compose_project is not None
        else ""
    )
    compose_service = (
        _string(compose_service, name=f"{container}.com.docker.compose.service")
        if compose_service is not None
        else ""
    )
    if expected_compose_project is not None:
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", expected_compose_project) is None:
            raise AttestationError("expected Docker Compose project is invalid")
        if compose_project != expected_compose_project:
            raise AttestationError(f"runtime Compose project mismatch for {container}")
    if expected_compose_service is not None:
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", expected_compose_service) is None:
            raise AttestationError("expected Docker Compose service is invalid")
        if compose_service != expected_compose_service:
            raise AttestationError(f"runtime Compose service mismatch for {container}")
    if endpoint_url is not None:
        _assert_docker_endpoint(
            item,
            container=container,
            endpoint_url=endpoint_url,
            container_port=endpoint_container_port,
        )
    return {
        "container_id": container_id,
        "digest": image_id,
        "image_id": image_id,
        "environment": expected_environment,
        "source_revision": expected_revision,
        "revision_label": revision,
        "compose_project": compose_project,
        "compose_service": compose_service,
        "started_at": started_at,
    }


def _docker_image_identity(image_ref: str) -> dict[str, str]:
    """M05 browser는 공식 이미지의 immutable registry digest만 허용한다."""

    if _PLAYWRIGHT_IMAGE_RE.fullmatch(image_ref) is None:
        raise AttestationError(
            "M05 Playwright runner image must be an immutable official digest reference"
        )
    repository, expected_digest = image_ref.rsplit("@", 1)
    try:
        completed = subprocess.run(
            [
                _host_tool("docker"),
                "image",
                "inspect",
                "--format",
                "{{json .}}",
                image_ref,
            ],
            check=True,
            capture_output=True,
            text=True,
            env=_docker_env(),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AttestationError("M05 Playwright runner image inspect failed") from exc
    try:
        item = _object(json.loads(completed.stdout), name="Playwright runner image")
    except json.JSONDecodeError as exc:
        raise AttestationError(
            "M05 Playwright runner image inspect output is invalid"
        ) from exc
    image_id = item.get("Id")
    if not isinstance(image_id, str) or _DIGEST_RE.fullmatch(image_id) is None:
        raise AttestationError("M05 Playwright runner image ID is not immutable")
    repo_digests = item.get("RepoDigests")
    if (
        not isinstance(repo_digests, list)
        or f"{repository.split(':', 1)[0]}@{expected_digest}" not in repo_digests
    ):
        raise AttestationError(
            "M05 Playwright runner image is not attested by the official registry digest"
        )
    return {"image_id": image_id, "image_ref": image_ref}


def _assert_runtime_identity(
    before: dict[str, str], after: dict[str, str], *, label: str
) -> None:
    for field in (
        "container_id",
        "digest",
        "image_id",
        "environment",
        "source_revision",
        "revision_label",
        "compose_project",
        "compose_service",
        "started_at",
    ):
        if before[field] != after[field]:
            raise AttestationError(
                f"runtime identity changed during live verification: {label}"
            )


def _git_blob(source_root: Path, *, revision: str, relative_path: str) -> bytes:
    if source_root.is_symlink() or not source_root.is_dir():
        raise AttestationError("Map source root must be a regular directory")
    try:
        completed = subprocess.run(
            [
                _host_tool("git"),
                "-C",
                str(source_root),
                "show",
                f"{revision}:{relative_path}",
            ],
            check=True,
            capture_output=True,
            env=_git_env(),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AttestationError(
            f"Map source revision does not contain the pinned artifact: {revision}:{relative_path}"
        ) from exc
    return completed.stdout


def _hash_source_openapi(
    source_root: Path,
    *,
    expected: dict[str, dict[str, str]],
    revisions: dict[str, str],
) -> dict[str, str]:
    actual: dict[str, str] = {}
    for name, relative_path in _SURFACE_PATHS.items():
        # 계약이 아니라 **호출부가 배선한** revision을 쓴다. v1에서는 계약값이,
        # v2에서는 표면별 정본에서 파생된 값이 여기로 온다(`_surface_revisions`).
        revision = revisions[name]
        source_raw = _git_blob(
            source_root, revision=revision, relative_path=relative_path
        )
        digest = _sha256(source_raw)
        if digest != expected[name]["openapi_sha256"]:
            raise AttestationError(
                f"Map source OpenAPI does not match the tracked pair: {name}"
            )
        try:
            source_value = json.loads(
                source_raw, object_pairs_hook=_reject_duplicate_keys
            )
        except (UnicodeDecodeError, json.JSONDecodeError, AttestationError) as exc:
            raise AttestationError(
                f"Map source OpenAPI is not valid JSON: {name}"
            ) from exc
        if (
            _sha256(_canonical_json(source_value))
            != expected[name]["source_canonical_sha256"]
        ):
            raise AttestationError(
                f"Map source OpenAPI canonical hash does not match the tracked pair: {name}"
            )
        if (
            _openapi_operation_contract_sha256(
                source_value, name=f"Map source {name} OpenAPI"
            )
            != expected[name]["source_operation_contract_sha256"]
        ):
            raise AttestationError(
                f"Map source OpenAPI operation contract does not match the tracked pair: {name}"
            )
        actual[name] = digest
    return actual


def _service_release_revision() -> str:
    """service 표면의 릴리스 revision을 그 값의 정본 문서에서 읽는다."""

    raw, _ = _read_json(_SERVICE_PROVENANCE_PATH)
    document = _object(raw, name="Map service provenance")
    return _commit(
        document.get("map_release_revision"),
        name="service provenance map_release_revision",
    )


def _surface_revisions(
    pair: dict[str, dict[str, str]],
    *,
    version: int,
    map_source_revision: str,
    service_release_revision: str,
) -> dict[str, str]:
    """네 표면이 각각 **어느 revision의 blob**에서 나오는지 정한다.

    v1은 계약이 표면마다 그 값을 스스로 선언했다. v2는 그 선언을 걷어냈으므로
    여기서 각 값의 정본을 직접 가리킨다 — 걷어내는 것은 사본이지 값이 아니다.

    - `admin`·`full`·`user` → Map pinned revision. 정본은 Manager pin registry이고
      격리 envelope나 `--map-source-revision`으로 들어온다.
    - `service` → service 릴리스 revision. 정본은 `_SERVICE_PROVENANCE_PATH`다.
      이 표면을 pinned revision으로 착각해 배선하면 `config.py`가 부팅 시
      `map_service_source_revision` 불일치로 거부한다 — 두 값은 재핀 주기가
      다르고 실제로 갈라져 있다.
    """

    if version == 1:
        return {name: pair[name]["source_revision"] for name in _SURFACES}
    return {
        "admin": map_source_revision,
        "full": map_source_revision,
        "service": service_release_revision,
        "user": map_source_revision,
    }


def _openapi_operations(value: object, *, name: str) -> dict[str, set[str]]:
    document = _object(value, name=name)
    paths = _object(document.get("paths"), name=f"{name}.paths")
    operations: dict[str, set[str]] = {}
    for path, raw_operations in paths.items():
        if not isinstance(path, str):
            raise AttestationError(f"{name} contains an invalid path")
        operation_object = _object(raw_operations, name=f"{name}.paths.{path}")
        operations[path] = {
            method
            for method in operation_object
            if method
            in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
        }
    return operations


def _openapi_surface_sha256(operations: dict[str, set[str]]) -> str:
    return _sha256(
        _canonical_json(
            {path: sorted(methods) for path, methods in sorted(operations.items())}
        )
    )


_OPENAPI_OPERATION_BINDING_KEYS = (
    "operationId",
    "parameters",
    "requestBody",
    "responses",
    "security",
)


def _openapi_operation_contract(value: object, *, name: str) -> dict[str, object]:
    operation = _object(value, name=name)
    return {
        key: operation[key]
        for key in _OPENAPI_OPERATION_BINDING_KEYS
        if key in operation
    }


def _openapi_operation_contract_sha256(value: object, *, name: str) -> str:
    document = _object(value, name=name)
    paths = _object(document.get("paths"), name=f"{name}.paths")
    operations: dict[str, dict[str, dict[str, object]]] = {}
    for path, raw_path in paths.items():
        path_object = _object(raw_path, name=f"{name}.paths.{path}")
        operations[path] = {
            method: _openapi_operation_contract(
                raw_operation, name=f"{name}.paths.{path}.{method}"
            )
            for method, raw_operation in path_object.items()
            if method
            in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
        }
    return _sha256(_canonical_json(operations))


def _assert_openapi_surface_covered(
    runtime_value: object, *, expected_value: object
) -> str:
    runtime_operations = _openapi_operations(runtime_value, name="runtime Map OpenAPI")
    expected_operations = _openapi_operations(expected_value, name="full Map OpenAPI")
    runtime_paths = _object(
        _object(runtime_value, name="runtime Map OpenAPI").get("paths"),
        name="runtime Map OpenAPI.paths",
    )
    expected_paths = _object(
        _object(expected_value, name="full Map OpenAPI").get("paths"),
        name="full Map OpenAPI.paths",
    )
    for path, methods in expected_operations.items():
        if path not in runtime_operations or not methods.issubset(
            runtime_operations[path]
        ):
            raise AttestationError(
                f"live Map OpenAPI does not cover the pinned full surface: {path}"
            )
        expected_path = _object(
            expected_paths[path], name=f"full Map OpenAPI.paths.{path}"
        )
        runtime_path = _object(
            runtime_paths[path], name=f"runtime Map OpenAPI.paths.{path}"
        )
        for method in methods:
            expected_operation = _object(
                expected_path[method],
                name=f"full Map OpenAPI operation {path} {method}",
            )
            runtime_operation = _object(
                runtime_path[method],
                name=f"runtime Map OpenAPI operation {path} {method}",
            )
            if expected_operation.get("operationId") != runtime_operation.get(
                "operationId"
            ):
                raise AttestationError(
                    f"live Map OpenAPI operation identity differs from the pinned full surface: {path}"
                )
    return _openapi_operation_contract_sha256(runtime_value, name="runtime Map OpenAPI")


def _runtime_map_openapi(
    *,
    map_admin_url: str,
    source_root: Path,
    expected: dict[str, dict[str, str]],
    revisions: dict[str, str],
) -> dict[str, dict[str, str]]:
    """실행 중 full/admin과 source-bound service/user surface를 대조한다.

    Map API는 service/user profile을 별도 HTTP route로 제공하지 않고, 같은 full
    application에서 생성한 vendored artifact로 관리한다. 따라서 HTTP proof는
    실제 ``/openapi.json``에만 적용하고, service/user는 pinned Git blob을
    ``source-artifact`` transport로 봉인한다.
    """

    runtime_value, runtime_raw = _http_json(
        _url(map_admin_url, "/openapi.json"),
        headers=_map_headers(),
    )
    runtime_source_raw = _git_blob(
        source_root,
        revision=revisions["admin"],
        relative_path=_SURFACE_PATHS["admin"],
    )
    try:
        runtime_source_value = json.loads(
            runtime_source_raw, object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError, AttestationError) as exc:
        raise AttestationError("pinned Map admin OpenAPI is not valid JSON") from exc
    runtime_canonical = _sha256(_canonical_json(runtime_value))
    source_canonical = _sha256(_canonical_json(runtime_source_value))
    if (
        runtime_canonical != source_canonical
        or source_canonical != expected["admin"]["source_canonical_sha256"]
    ):
        raise AttestationError(
            "live Map admin OpenAPI does not match the pinned source artifact"
        )
    full_source_raw = _git_blob(
        source_root,
        revision=revisions["full"],
        relative_path=_SURFACE_PATHS["full"],
    )
    try:
        full_source_value = json.loads(
            full_source_raw, object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError, AttestationError) as exc:
        raise AttestationError("pinned Map full OpenAPI is not valid JSON") from exc
    full_surface_coverage_sha256 = _assert_openapi_surface_covered(
        runtime_value, expected_value=full_source_value
    )
    full_source_canonical = _sha256(_canonical_json(full_source_value))
    if full_source_canonical != expected["full"]["source_canonical_sha256"]:
        raise AttestationError("pinned Map full OpenAPI canonical hash is not tracked")
    runtime_surface_sha256 = _openapi_operation_contract_sha256(
        runtime_value, name="runtime Map OpenAPI"
    )
    if (
        runtime_surface_sha256 != expected["admin"]["runtime_operation_contract_sha256"]
        or full_surface_coverage_sha256
        != expected["full"]["runtime_operation_contract_sha256"]
    ):
        raise AttestationError("live Map OpenAPI operation contract is not pinned")

    result: dict[str, dict[str, str]] = {}
    result["admin_openapi"] = {
        "canonical_sha256": runtime_canonical,
        "source_canonical_sha256": source_canonical,
        "source_revision": revisions["admin"],
        "source_sha256": expected["admin"]["openapi_sha256"],
        "surface_coverage_sha256": runtime_surface_sha256,
        "transport": "http",
        "transport_sha256": _sha256(runtime_raw),
    }
    result["full_openapi"] = {
        "canonical_sha256": runtime_canonical,
        "source_canonical_sha256": full_source_canonical,
        "source_revision": revisions["full"],
        "source_sha256": expected["full"]["openapi_sha256"],
        "surface_coverage_sha256": full_surface_coverage_sha256,
        "transport": "http",
        "transport_sha256": _sha256(runtime_raw),
    }
    for name in ("service", "user"):
        source_raw = _git_blob(
            source_root,
            revision=revisions[name],
            relative_path=_SURFACE_PATHS[name],
        )
        try:
            source_value = json.loads(
                source_raw, object_pairs_hook=_reject_duplicate_keys
            )
        except (UnicodeDecodeError, json.JSONDecodeError, AttestationError) as exc:
            raise AttestationError(
                f"pinned Map {name} OpenAPI is not valid JSON"
            ) from exc
        source_canonical = _sha256(_canonical_json(source_value))
        source_surface_sha256 = _openapi_operation_contract_sha256(
            source_value, name=f"pinned Map {name} OpenAPI"
        )
        if (
            source_canonical != expected[name]["source_canonical_sha256"]
            or source_surface_sha256
            != expected[name]["source_operation_contract_sha256"]
        ):
            raise AttestationError(f"pinned Map {name} OpenAPI hashes are not tracked")
        result[f"{name}_openapi"] = {
            "canonical_sha256": source_canonical,
            "source_canonical_sha256": source_canonical,
            "source_revision": revisions[name],
            "source_sha256": expected[name]["openapi_sha256"],
            "surface_coverage_sha256": source_surface_sha256,
            "transport": "source-artifact",
            "transport_sha256": _sha256(source_raw),
        }
    return result


def _validate_ui_marker(
    value: object,
    *,
    event_id: str,
    source_revision: str,
    verification_id: str,
    runner_image: dict[str, str],
    pinvi_detail: dict[str, object],
    pinvi_detail_sha256: str,
    expected_pinvi_api_endpoint: str,
    expected_old_feature_id: str,
    expected_replacement_feature_id: str,
    expected_impact_count: int,
) -> None:
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
    if set(marker) != expected or marker.get("status") != "passed":
        raise AttestationError("UI evidence marker schema/status is invalid")
    if _uuid(marker.get("event_id"), name="UI marker event ID") != event_id:
        raise AttestationError("UI marker event does not match the requested event")
    if (
        _commit(marker.get("source_revision"), name="UI marker source revision")
        != source_revision
    ):
        raise AttestationError("UI marker source revision does not match the runtime")
    if marker.get("pinvi_api_endpoint") != expected_pinvi_api_endpoint:
        raise AttestationError("UI marker does not bind the actual Pinvi API endpoint")
    if (
        _uuid(marker.get("verification_id"), name="UI marker verification ID")
        != verification_id
    ):
        raise AttestationError("UI marker verification ID does not match this run")
    if marker.get("playwright_runner_image_ref") != runner_image["image_ref"]:
        raise AttestationError(
            "UI marker Playwright image reference does not match this run"
        )
    if marker.get("playwright_runner_image_id") != runner_image["image_id"]:
        raise AttestationError("UI marker Playwright image ID does not match this run")
    if not isinstance(marker["assertions"], list) or not marker["assertions"]:
        raise AttestationError("UI marker assertions are missing")
    if not isinstance(marker["impact_count"], int) or marker["impact_count"] < 0:
        raise AttestationError("UI marker impact count is invalid")
    digest = marker["pinvi_detail_sha256"]
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise AttestationError("UI marker Pinvi detail hash is invalid")
    if digest != pinvi_detail_sha256:
        raise AttestationError(
            "UI marker does not bind the after-run Pinvi detail response"
        )
    if marker["old_feature_id"] != expected_old_feature_id:
        raise AttestationError("UI marker old Feature ID does not match the live input")
    if marker["replacement_feature_id"] != expected_replacement_feature_id:
        raise AttestationError(
            "UI marker replacement Feature ID does not match the live input"
        )
    if marker["impact_count"] != expected_impact_count:
        raise AttestationError("UI marker impact count does not match the live input")
    receipt = _object(pinvi_detail.get("receipt"), name="UI marker Pinvi receipt")
    for marker_field, receipt_field in (
        ("old_feature_id", "old_feature_id"),
        ("replacement_feature_id", "replacement_feature_id"),
        ("impact_count", "impact_count"),
    ):
        if marker[marker_field] != receipt.get(receipt_field):
            raise AttestationError(
                f"UI marker does not bind Pinvi receipt field: {receipt_field}"
            )


def _validate_m04_ui_marker(
    value: object,
    *,
    feature_request_id: str,
    source_revision: str,
    verification_id: str,
    runner_image: dict[str, str],
    expected_pinvi_api_endpoint: str,
    expected_pinvi_approval_sha256: str,
    expected_map_pending_receipt_sha256: str,
) -> dict[str, str]:
    marker = _object(value, name="M04 UI evidence marker")
    expected = {
        "assertions",
        "feature_request_id",
        "map_action",
        "map_pending_receipt_sha256",
        "map_request_id",
        "map_review_mode",
        "map_state",
        "pinvi_api_endpoint",
        "pinvi_approval_sha256",
        "playwright_runner_image_id",
        "playwright_runner_image_ref",
        "source_revision",
        "status",
        "verification_id",
    }
    if set(marker) != expected or marker.get("status") != "passed":
        raise AttestationError("M04 UI evidence marker schema/status is invalid")
    if (
        _uuid(marker.get("feature_request_id"), name="M04 UI marker request ID")
        != feature_request_id
    ):
        raise AttestationError("M04 UI marker request does not match this run")
    if (
        _uuid(marker.get("map_request_id"), name="M04 UI marker Map request ID")
        != feature_request_id
    ):
        raise AttestationError("M04 UI marker does not bind the Map request")
    if (
        marker.get("map_state") != "pending"
        or marker.get("map_review_mode") != "feature_request_queue"
        or marker.get("map_action") != "submit"
    ):
        raise AttestationError("M04 UI marker does not bind the Map pending receipt")
    if (
        _commit(marker.get("source_revision"), name="M04 UI marker source revision")
        != source_revision
    ):
        raise AttestationError(
            "M04 UI marker source revision does not match the runtime"
        )
    if marker.get("pinvi_api_endpoint") != expected_pinvi_api_endpoint:
        raise AttestationError(
            "M04 UI marker does not bind the actual Pinvi API endpoint"
        )
    if (
        _uuid(marker.get("verification_id"), name="M04 UI marker verification ID")
        != verification_id
    ):
        raise AttestationError("M04 UI marker verification ID does not match this run")
    if marker.get("playwright_runner_image_ref") != runner_image["image_ref"]:
        raise AttestationError(
            "M04 UI marker Playwright image reference does not match this run"
        )
    if marker.get("playwright_runner_image_id") != runner_image["image_id"]:
        raise AttestationError(
            "M04 UI marker Playwright image ID does not match this run"
        )
    if marker.get("assertions") != [
        "pinvi_approved",
        "pinvi_approval_binding",
        "map_request_id",
        "map_pending_receipt",
        "map_pending_receipt_fingerprint",
        "same_origin",
    ]:
        raise AttestationError("M04 UI marker assertion inventory is invalid")
    approval_sha = _string(
        marker.get("pinvi_approval_sha256"), name="M04 UI marker Pinvi approval hash"
    )
    map_receipt_sha = _string(
        marker.get("map_pending_receipt_sha256"),
        name="M04 UI marker Map pending receipt hash",
    )
    if (
        _SHA256_RE.fullmatch(approval_sha) is None
        or _SHA256_RE.fullmatch(map_receipt_sha) is None
        or approval_sha != expected_pinvi_approval_sha256
        or map_receipt_sha != expected_map_pending_receipt_sha256
    ):
        raise AttestationError(
            "M04 UI marker does not match Pinvi's persisted approval receipt"
        )
    return {
        "feature_request_id": feature_request_id,
        "map_action": "submit",
        "map_request_id": feature_request_id,
        "map_review_mode": "feature_request_queue",
        "map_state": "pending",
        "map_pending_receipt_sha256": map_receipt_sha,
        "pinvi_approval_sha256": approval_sha,
    }


def _load_private_key(
    path: Path, *, require_root_owned: bool
) -> Ed25519PrivateKey | _OpenSslEd25519PrivateKey:
    raw = _secure_read(
        path, require_root_owned=require_root_owned, label="M05 private key"
    )
    if not _CRYPTOGRAPHY_AVAILABLE:
        return _OpenSslEd25519PrivateKey(raw)
    try:
        value = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError) as exc:
        raise AttestationError("M05 private key is invalid") from exc
    if not isinstance(value, Ed25519PrivateKey):
        raise AttestationError("M05 private key is not Ed25519")
    return value


def _sign(
    private_key: Ed25519PrivateKey | _OpenSslEd25519PrivateKey, payload: bytes
) -> bytes:
    return private_key.sign(payload)


def _public_key_bytes(
    private_key: Ed25519PrivateKey | _OpenSslEd25519PrivateKey,
) -> bytes:
    if isinstance(private_key, _OpenSslEd25519PrivateKey):
        return private_key.public_bytes_raw()
    return private_key.public_key().public_bytes_raw()


def _runtime_snapshot(
    args: argparse.Namespace,
    *,
    pair: dict[str, dict[str, str]],
    source_revision: str,
    map_admin_revision: str,
    pinvi_image_digests: Mapping[str, str] | None = None,
) -> dict[str, dict[str, str]]:
    # 세 Map 컨테이너의 OCI revision 라벨은 **admin 표면**의 revision과 대조한다.
    # receipt `_map_pair`도 같은 표면으로 대조하므로 두 단계가 같은 것을 요구한다.
    # v1 계약은 표면마다 revision이 다를 수 있어서 다른 표면을 쓰면 두 단계가 서로
    # 모순된 요구를 하게 된다(2차 적대 리뷰).
    return {
        "map_admin": _docker_inspect(
            args.map_admin_container,
            expected_revision=map_admin_revision,
            expected_environment=args.scope,
            expected_image_digest=pair["runtime_image_digests"]["admin"],
            expected_compose_project=args.map_docker_project,
            expected_compose_service=args.map_admin_service,
            endpoint_url=args.map_admin_url,
            endpoint_container_port=13701,
        ),
        "map_api": _docker_inspect(
            args.map_api_container,
            expected_revision=map_admin_revision,
            expected_environment=args.scope,
            expected_image_digest=pair["runtime_image_digests"]["api"],
            expected_compose_project=args.map_docker_project,
            expected_compose_service=args.map_api_service,
        ),
        "map_frontend": _docker_inspect(
            args.map_frontend_container,
            expected_revision=map_admin_revision,
            expected_environment=args.scope,
            expected_image_digest=pair["runtime_image_digests"]["frontend"],
            expected_compose_project=args.map_docker_project,
            expected_compose_service=args.map_frontend_service,
        ),
        "pinvi_api": _docker_inspect(
            args.pinvi_api_container,
            expected_revision=source_revision,
            expected_environment=args.scope,
            expected_image_digest=(
                pinvi_image_digests["api"] if pinvi_image_digests is not None else None
            ),
            expected_compose_project=args.pinvi_docker_project,
            expected_compose_service="app-api",
            endpoint_url=args.pinvi_api_url,
        ),
        "pinvi_web": _docker_inspect(
            args.pinvi_web_container,
            expected_revision=source_revision,
            expected_environment=args.scope,
            expected_image_digest=(
                pinvi_image_digests["web"] if pinvi_image_digests is not None else None
            ),
            expected_compose_project=args.pinvi_docker_project,
            expected_compose_service="app-web",
            endpoint_url=args.pinvi_web_url,
            endpoint_container_port=3000,
        ),
        "pinvi_dagster": _docker_inspect(
            args.pinvi_dagster_container,
            expected_revision=source_revision,
            expected_environment=args.scope,
            expected_image_digest=(
                pinvi_image_digests["dagster"] if pinvi_image_digests is not None else None
            ),
            expected_compose_project=args.pinvi_docker_project,
            expected_compose_service="app-dagster",
        ),
    }


def _assert_runtime_snapshots_unchanged(
    before: dict[str, dict[str, str]],
    after: dict[str, dict[str, str]],
) -> None:
    for name, runtime in before.items():
        _assert_runtime_identity(runtime, after[name], label=name)


def _assert_evidence_directory(path: Path, *, require_root_owned: bool) -> None:
    if path.is_symlink() or not path.is_dir():
        raise AttestationError("evidence directory must already exist")
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise AttestationError("evidence directory mode must be 0700")
    if require_root_owned and metadata.st_uid != 0:
        raise AttestationError("evidence directory must be root-owned")


def _m04_runtime_snapshot(
    args: argparse.Namespace, *, source_revision: str
) -> dict[str, dict[str, str]]:
    return {
        "pinvi_api": _docker_inspect(
            args.pinvi_api_container,
            expected_revision=source_revision,
            expected_environment=args.scope,
            endpoint_url=args.pinvi_api_url,
        ),
        "pinvi_web": _docker_inspect(
            args.pinvi_web_container,
            expected_revision=source_revision,
            expected_environment=args.scope,
            endpoint_url=args.pinvi_web_url,
            endpoint_container_port=3000,
        ),
    }


def _read_secure_json_evidence(
    path: Path, *, require_root_owned: bool, label: str
) -> tuple[object, str]:
    raw = _secure_read(path, require_root_owned=require_root_owned, label=label)
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicate_keys), _sha256(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, AttestationError) as exc:
        raise AttestationError(f"{label} is not valid JSON") from exc


def _m04(args: argparse.Namespace) -> int:
    evidence_dir: Path = args.evidence_dir
    _assert_evidence_directory(evidence_dir, require_root_owned=args.require_root_owned)
    feature_request_id = _uuid(args.feature_request_id, name="M04 feature request ID")
    source_revision = _commit(args.pinvi_source_revision, name="Pinvi source revision")
    if args.scope not in {"smoke", "isolated", "staging", "production"}:
        raise AttestationError("M04 attestation scope is invalid")
    if args.scope in {"isolated", "staging", "production"} and not args.require_root_owned:
        raise AttestationError(
            "M04 isolated/staging/production attestation requires root-owned evidence"
        )
    pinvi_source_root = Path(__file__).resolve().parents[1]
    _assert_clean_checkout(
        pinvi_source_root,
        expected_revision=source_revision,
        label="Pinvi source",
    )
    if not os.environ.get("PINVI_M04_LIVE_EMAIL") or not os.environ.get(
        "PINVI_M04_LIVE_PASSWORD"
    ):
        raise AttestationError("M04 signed live UI requires admin email and password")
    runtime_initial = _m04_runtime_snapshot(args, source_revision=source_revision)
    runner_image = _docker_image_identity(args.playwright_runner_image)
    private_key = _load_private_key(
        args.private_key, require_root_owned=args.require_root_owned
    )
    verification_id = str(uuid4())
    m04_created_at = int(time.time())
    marker_path = evidence_dir / "m04-ui-run.json"
    if marker_path.is_symlink() or marker_path.exists():
        raise AttestationError(
            "M04 UI evidence marker must not pre-exist the pinned run"
        )

    command = list(args.ui_command)
    if command and command[0] == "--":
        command = command[1:]
    runner_path = pinvi_source_root / "scripts/n150-playwright-runner.sh"
    expected_command = [
        str(runner_path),
        "--",
        "npm",
        "-w",
        "@pinvi/web",
        "run",
        "test:e2e:live-mutating",
        "--",
        "apps/web/e2e/admin-feature-request-queue-live-mutating.live.ts",
        "--workers=1",
    ]
    if not command or Path(command[0]).resolve() != runner_path.resolve():
        raise AttestationError("M04 live UI must use the repository Playwright runner")
    command[0] = str(runner_path)
    if command != expected_command:
        raise AttestationError("live UI command is not the pinned M04 Playwright test")

    child_env = os.environ.copy()
    for name in tuple(child_env):
        if name.startswith(("GIT_", "DOCKER_")) or name.lower() in {
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        }:
            child_env.pop(name)
    child_env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
    child_env["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    child_env["PINVI_M04_LIVE_E2E"] = "1"
    child_env["PINVI_M04_LIVE_FEATURE_REQUEST_ID"] = feature_request_id
    child_env["PINVI_M04_UI_EVIDENCE_DIR"] = str(evidence_dir)
    child_env["PINVI_M04_UI_VERIFICATION_ID"] = verification_id
    child_env["PINVI_M04_PLAYWRIGHT_RUNNER_IMAGE_REF"] = runner_image["image_ref"]
    child_env["PINVI_M04_PLAYWRIGHT_RUNNER_IMAGE_ID"] = runner_image["image_id"]
    child_env["PINVI_PLAYWRIGHT_RUNNER_IMAGE"] = runner_image["image_ref"]
    child_env["PINVI_PLAYWRIGHT_RUNNER_NETWORK"] = "host"
    child_env["PINVI_PLAYWRIGHT_RUNNER_REPO_ROOT"] = str(pinvi_source_root)
    child_env["PINVI_PLAYWRIGHT_RUNNER_SKIP_NPM_CI"] = "0"
    child_env["PINVI_LIVE_WEB_URL"] = args.pinvi_web_url
    child_env["PINVI_LIVE_API_URL"] = args.pinvi_api_url
    child_env["PINVI_M04_UI_API_URL"] = args.pinvi_api_url
    child_env["PINVI_SOURCE_REVISION"] = source_revision
    child_env["PINVI_LIVE_EXPECTED_REVISION"] = source_revision
    completed = subprocess.run(command, check=False, env=child_env)
    if completed.returncode != 0:
        raise AttestationError(
            f"M04 live UI command exited with {completed.returncode}"
        )
    _assert_clean_checkout(
        pinvi_source_root,
        expected_revision=source_revision,
        label="Pinvi source after M04 live UI",
    )
    marker, marker_raw_hash = _read_json(marker_path)
    approval_snapshot = _pinvi_m04_approval_snapshot(
        pinvi_api_url=args.pinvi_api_url,
        request_id=feature_request_id,
        email=os.environ["PINVI_M04_LIVE_EMAIL"],
        password=os.environ["PINVI_M04_LIVE_PASSWORD"],
    )
    marker_data = _validate_m04_ui_marker(
        marker,
        feature_request_id=feature_request_id,
        source_revision=source_revision,
        verification_id=verification_id,
        runner_image=runner_image,
        expected_pinvi_api_endpoint=args.pinvi_api_url.rstrip("/"),
        expected_pinvi_approval_sha256=approval_snapshot["pinvi_approval_sha256"],
        expected_map_pending_receipt_sha256=approval_snapshot[
            "map_pending_receipt_sha256"
        ],
    )
    runtime_after = _m04_runtime_snapshot(args, source_revision=source_revision)
    _assert_runtime_snapshots_unchanged(runtime_initial, runtime_after)

    live_ui = {
        **marker_data,
        "m04_created_at": m04_created_at,
        "pinvi_api_container_id": runtime_initial["pinvi_api"]["container_id"],
        "pinvi_api_endpoint": args.pinvi_api_url.rstrip("/"),
        "pinvi_source_revision": source_revision,
        "pinvi_web_container_id": runtime_initial["pinvi_web"]["container_id"],
        "pinvi_web_endpoint": args.pinvi_web_url.rstrip("/"),
        "playwright_runner_image_id": runner_image["image_id"],
        "playwright_runner_image_ref": runner_image["image_ref"],
        "runner_exit_code": completed.returncode,
        "runtime_identity_verified": True,
        "status": "passed",
        "ui_evidence_sha256": marker_raw_hash,
        "verification_id": verification_id,
    }
    live_ui_hash = _write_json(evidence_dir / "m04-live-ui.json", live_ui)
    payload = {
        "created_at": m04_created_at,
        "feature_request_id": feature_request_id,
        "map_pending_receipt_sha256": marker_data["map_pending_receipt_sha256"],
        "m04_live_ui_sha256": live_ui_hash,
        "pinvi_api_endpoint": args.pinvi_api_url.rstrip("/"),
        "pinvi_approval_sha256": marker_data["pinvi_approval_sha256"],
        "pinvi_source_revision": source_revision,
        "pinvi_web_endpoint": args.pinvi_web_url.rstrip("/"),
        "playwright_runner_image_id": runner_image["image_id"],
        "playwright_runner_image_ref": runner_image["image_ref"],
        "scope": args.scope,
        "status": "passed",
        "verification_id": verification_id,
        "version": 2,
    }
    attestation = {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(
            _sign(private_key, _canonical_json(payload))
        )
        .decode("ascii")
        .rstrip("="),
    }
    attestation_hash = _write_json(evidence_dir / "m04-attestation.json", attestation)
    print(f"m04_attestation_sha256={attestation_hash}")
    print(f"feature_request_id={feature_request_id}")
    return 0


def _read_m04_evidence(
    evidence_dir: Path,
    *,
    require_root_owned: bool,
    public_key_bytes: bytes,
    source_revision: str,
    scope: str,
    expected_pinvi_api_endpoint: str,
    expected_pinvi_api_container_id: str,
    expected_pinvi_web_endpoint: str,
    expected_pinvi_web_container_id: str,
) -> dict[str, str]:
    _assert_evidence_directory(evidence_dir, require_root_owned=require_root_owned)
    live, live_hash = _read_secure_json_evidence(
        evidence_dir / "m04-live-ui.json",
        require_root_owned=require_root_owned,
        label="M04 live UI evidence",
    )
    attestation, attestation_hash = _read_secure_json_evidence(
        evidence_dir / "m04-attestation.json",
        require_root_owned=require_root_owned,
        label="M04 attestation",
    )
    live_data = _object(live, name="M04 live UI evidence")
    expected_live = {
        "feature_request_id",
        "map_action",
        "map_pending_receipt_sha256",
        "map_request_id",
        "map_review_mode",
        "map_state",
        "m04_created_at",
        "pinvi_api_container_id",
        "pinvi_api_endpoint",
        "pinvi_approval_sha256",
        "pinvi_source_revision",
        "pinvi_web_container_id",
        "pinvi_web_endpoint",
        "playwright_runner_image_id",
        "playwright_runner_image_ref",
        "runner_exit_code",
        "runtime_identity_verified",
        "status",
        "ui_evidence_sha256",
        "verification_id",
    }
    if set(live_data) != expected_live or live_data.get("status") != "passed":
        raise AttestationError("M04 live UI evidence schema/status is invalid")
    if live_data.get("runtime_identity_verified") is not True:
        raise AttestationError("M04 live UI runtime identity was not verified")
    if live_data.get("runner_exit_code") != 0:
        raise AttestationError("M04 live UI runner did not exit successfully")
    feature_request_id = _uuid(
        live_data.get("feature_request_id"), name="M04 live UI request ID"
    )
    if (
        _uuid(live_data.get("map_request_id"), name="M04 live UI Map request ID")
        != feature_request_id
    ):
        raise AttestationError("M04 live UI Map request does not match the request")
    if (
        live_data.get("map_action") != "submit"
        or live_data.get("map_review_mode") != "feature_request_queue"
        or live_data.get("map_state") != "pending"
    ):
        raise AttestationError("M04 live UI Map pending receipt is invalid")
    if live_data.get("pinvi_api_endpoint") != expected_pinvi_api_endpoint:
        raise AttestationError("M04 live UI Pinvi API endpoint does not match")
    if _container_id(
        live_data.get("pinvi_api_container_id"),
        name="M04 live UI Pinvi API container ID",
    ) != _container_id(
        expected_pinvi_api_container_id, name="expected Pinvi API container ID"
    ):
        raise AttestationError("M04 live UI Pinvi API runtime does not match")
    if live_data.get("pinvi_web_endpoint") != expected_pinvi_web_endpoint:
        raise AttestationError("M04 live UI Pinvi web endpoint does not match")
    if _container_id(
        live_data.get("pinvi_web_container_id"),
        name="M04 live UI Pinvi web container ID",
    ) != _container_id(
        expected_pinvi_web_container_id, name="expected Pinvi web container ID"
    ):
        raise AttestationError("M04 live UI Pinvi web runtime does not match")
    if (
        _commit(
            live_data.get("pinvi_source_revision"), name="M04 live UI source revision"
        )
        != source_revision
    ):
        raise AttestationError("M04 live UI source revision does not match")
    verification_id = _uuid(
        live_data.get("verification_id"), name="M04 live UI verification ID"
    )
    m04_created_at = live_data.get("m04_created_at")
    if type(m04_created_at) is not int or m04_created_at <= 0:
        raise AttestationError("M04 live UI creation time is invalid")
    approval_sha = _string(
        live_data.get("pinvi_approval_sha256"), name="M04 live UI approval hash"
    )
    map_pending_receipt_sha = _string(
        live_data.get("map_pending_receipt_sha256"),
        name="M04 live UI Map pending receipt hash",
    )
    ui_evidence_sha = _string(
        live_data.get("ui_evidence_sha256"), name="M04 live UI marker hash"
    )
    if (
        _SHA256_RE.fullmatch(approval_sha) is None
        or _SHA256_RE.fullmatch(map_pending_receipt_sha) is None
        or _SHA256_RE.fullmatch(ui_evidence_sha) is None
    ):
        raise AttestationError("M04 live UI evidence hash is invalid")
    for name in ("playwright_runner_image_id", "playwright_runner_image_ref"):
        if not isinstance(live_data.get(name), str):
            raise AttestationError("M04 live UI Playwright runner identity is invalid")
    if _DIGEST_RE.fullmatch(str(live_data["playwright_runner_image_id"])) is None:
        raise AttestationError("M04 live UI Playwright image ID is invalid")
    if (
        _PLAYWRIGHT_IMAGE_RE.fullmatch(str(live_data["playwright_runner_image_ref"]))
        is None
    ):
        raise AttestationError("M04 live UI Playwright image reference is invalid")

    envelope = _object(attestation, name="M04 attestation")
    if set(envelope) != {"payload", "signature"}:
        raise AttestationError("M04 attestation envelope is invalid")
    payload = _object(envelope.get("payload"), name="M04 attestation payload")
    expected_payload = {
        "created_at",
        "feature_request_id",
        "map_pending_receipt_sha256",
        "m04_live_ui_sha256",
        "pinvi_api_endpoint",
        "pinvi_approval_sha256",
        "pinvi_source_revision",
        "pinvi_web_endpoint",
        "playwright_runner_image_id",
        "playwright_runner_image_ref",
        "scope",
        "status",
        "verification_id",
        "version",
    }
    if (
        set(payload) != expected_payload
        or payload.get("version") != 2
        or payload.get("status") != "passed"
        or payload.get("scope") != scope
        or type(payload.get("created_at")) is not int
    ):
        raise AttestationError("M04 attestation payload schema/status is invalid")
    if (
        _uuid(payload.get("feature_request_id"), name="M04 attestation request ID")
        != feature_request_id
        or _uuid(payload.get("verification_id"), name="M04 attestation verification ID")
        != verification_id
        or _commit(
            payload.get("pinvi_source_revision"), name="M04 attestation source revision"
        )
        != source_revision
        or payload.get("pinvi_api_endpoint") != expected_pinvi_api_endpoint
        or payload.get("pinvi_web_endpoint") != expected_pinvi_web_endpoint
        or payload.get("playwright_runner_image_id")
        != live_data["playwright_runner_image_id"]
        or payload.get("playwright_runner_image_ref")
        != live_data["playwright_runner_image_ref"]
        or payload.get("m04_live_ui_sha256") != live_hash
        or payload.get("created_at") != m04_created_at
        or payload.get("pinvi_approval_sha256") != approval_sha
        or payload.get("map_pending_receipt_sha256") != map_pending_receipt_sha
    ):
        raise AttestationError("M04 attestation does not bind the live UI evidence")
    signature = envelope.get("signature")
    if (
        not isinstance(signature, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{86}\Z", signature) is None
    ):
        raise AttestationError("M04 attestation signature is invalid")
    try:
        signature_bytes = base64.urlsafe_b64decode(
            signature + "=" * (-len(signature) % 4)
        )
        _verify_ed25519_signature(
            public_key_bytes, signature_bytes, _canonical_json(payload)
        )
    except (ValueError, TypeError, AttestationError) as exc:
        raise AttestationError("M04 attestation signature is invalid") from exc
    return {
        "attestation_sha256": attestation_hash,
        "feature_request_id": feature_request_id,
        "m04_created_at": str(m04_created_at),
        "map_pending_receipt_sha256": map_pending_receipt_sha,
        "pinvi_approval_sha256": approval_sha,
        "ui_evidence_sha256": ui_evidence_sha,
        "verification_id": verification_id,
    }


def _live(args: argparse.Namespace) -> int:
    evidence_dir: Path = args.evidence_dir
    _assert_evidence_directory(evidence_dir, require_root_owned=args.require_root_owned)

    event_id = _uuid(args.event_id, name="M05 event ID")
    case_id = _uuid(args.map_case_id, name="Map case ID")
    source_revision = _commit(args.pinvi_source_revision, name="Pinvi source revision")
    if args.scope not in {"isolated", "staging", "production"}:
        raise AttestationError("attestation scope must be isolated, staging, or production")
    if not args.require_root_owned:
        raise AttestationError("M05 live attestation requires root-owned evidence")
    email = os.environ.get("M05_PINVI_EMAIL", "")
    password = os.environ.get("M05_PINVI_PASSWORD", "")
    if not email or not password:
        raise AttestationError("M05 live attestation requires admin email and password")
    old_feature_id = _string(
        os.environ.get("PINVI_M05_LIVE_OLD_FEATURE_ID", ""),
        name="M05 old Feature ID",
    )
    replacement_feature_id = _string(
        os.environ.get("PINVI_M05_LIVE_REPLACEMENT_FEATURE_ID", ""),
        name="M05 replacement Feature ID",
    )
    impact_count = os.environ.get("PINVI_M05_LIVE_IMPACT_COUNT", "")
    if re.fullmatch(r"[0-9]+", impact_count) is None:
        raise AttestationError("M05 impact count must be a non-negative integer")

    pair, pair_envelope_version = _load_pair()
    isolated_runtime: dict[str, object] | None = None
    if args.scope == "isolated":
        if (
            args.isolated_runtime_provenance is None
            or args.isolated_manager_source_revision is None
            or args.isolated_pinset_sha256 is None
            or args.isolated_execution_identity_sha256 is None
        ):
            raise AttestationError("isolated M05 attestation requires runtime provenance")
        isolated_runtime = _load_isolated_runtime_provenance(
            args.isolated_runtime_provenance,
            pair=pair,
            pinvi_source_revision=source_revision,
            expected_manager_source_revision=args.isolated_manager_source_revision,
            expected_pinset_sha256=args.isolated_pinset_sha256,
            expected_execution_identity_sha256=args.isolated_execution_identity_sha256,
            require_root_owned=True,
        )
        pair["runtime_image_digests"] = cast(
            dict[str, str], isolated_runtime["map_images"]
        )
    elif args.isolated_runtime_provenance is not None:
        raise AttestationError("runtime provenance is only valid for isolated M05 attestation")

    # Map source revision의 **단일 생산자**를 여기서 정한다.
    #   v1  계약이 스스로 선언한 값(pin registry 선언의 사본)
    #   v2  계약은 선언하지 않는다 — 격리 envelope(Manager가 pin registry에서 만든 것)
    #       또는 명시 인자에서 온다. 둘 다 없으면 **조용히 넘어가지 않고** 무엇을
    #       배선해야 하는지 이름을 대며 거절한다.
    map_source_revision: str | None = pair["full"].get("source_revision")
    if map_source_revision is None and isolated_runtime is not None:
        map_source_revision = cast(str, isolated_runtime["map_source_revision"])
    if map_source_revision is None and args.map_source_revision is not None:
        map_source_revision = _commit(
            args.map_source_revision, name="--map-source-revision"
        )
    if map_source_revision is None:
        raise AttestationError(
            "v2 pair envelope declares no Map source revision; pass "
            "--map-source-revision (pin registry is the producer) or run with "
            "isolated runtime provenance"
        )
    # Map runtime image digest의 **단일 생산자**를 여기서 정한다.
    #   v1  계약이 스스로 선언한 값(pin registry 선언의 사본). 그 사본은 두 pinset
    #       낡은 채 방치돼 있던 적이 있다.
    #   v2  격리 실행은 Manager가 실측한 격리 envelope가, 그 밖의 scope는 pin
    #       registry 파생값을 명시 인자로 받는다. 어느 쪽도 없으면 **조용히 검사를
    #       건너뛰지 않고** 무엇을 배선해야 하는지 이름을 대며 거절한다.
    if pair_envelope_version == 2 and not pair.get("runtime_image_digests"):
        declared = {
            "admin": args.map_admin_image_digest,
            "api": args.map_api_image_digest,
            "frontend": args.map_frontend_image_digest,
        }
        if any(value is None for value in declared.values()):
            raise AttestationError(
                "v2 pair envelope declares no Map runtime image digests; pass "
                "--map-admin-image-digest/--map-api-image-digest/"
                "--map-frontend-image-digest (pin registry is the producer) or run "
                "with isolated runtime provenance"
            )
        for name, value in declared.items():
            if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
                raise AttestationError(f"--map-{name}-image-digest is invalid")
        pair["runtime_image_digests"] = dict(cast(dict[str, str], declared))
    # 표면마다 **누가 그 revision을 만드는가**를 여기서 한 번 정하고, 아래의
    # checkout 대조와 두 OpenAPI 함수는 그 결과만 쓴다.
    surface_revisions = _surface_revisions(
        pair,
        version=pair_envelope_version,
        map_source_revision=map_source_revision,
        service_release_revision=_service_release_revision(),
    )
    pinvi_image_digests = (
        cast(dict[str, str], isolated_runtime["pinvi_images"])
        if isolated_runtime is not None
        else None
    )
    pinvi_source_root = Path(__file__).resolve().parents[1]
    _assert_clean_checkout(
        pinvi_source_root,
        expected_revision=source_revision,
        label="Pinvi source",
    )
    _assert_clean_checkout(
        args.map_source_root,
        expected_revision=map_source_revision,
        # 표면별 revision이 서로 다를 수 있다(service는 릴리스 revision이다).
        # checkout이 그 전부를 담고 있어야 blob을 읽을 수 있다.
        allowed_revisions=set(surface_revisions.values()),
        label="Map source",
    )
    private_key = _load_private_key(
        args.private_key, require_root_owned=args.require_root_owned
    )
    runtime_initial = _runtime_snapshot(
        args,
        pair=pair,
        source_revision=source_revision,
        map_admin_revision=surface_revisions["admin"],
        pinvi_image_digests=pinvi_image_digests,
    )
    m04 = _read_m04_evidence(
        args.m04_evidence_dir,
        require_root_owned=args.require_root_owned,
        public_key_bytes=_public_key_bytes(private_key),
        source_revision=source_revision,
        scope=args.scope,
        expected_pinvi_api_endpoint=args.pinvi_api_url.rstrip("/"),
        expected_pinvi_api_container_id=runtime_initial["pinvi_api"]["container_id"],
        expected_pinvi_web_endpoint=args.pinvi_web_url.rstrip("/"),
        expected_pinvi_web_container_id=runtime_initial["pinvi_web"]["container_id"],
    )
    m04_created_at = int(m04["m04_created_at"])
    now = int(time.time())
    if m04_created_at > now + 60 or now - m04_created_at > _M04_MAX_AGE_SECONDS:
        raise AttestationError("M04 evidence is outside the allowed activation window")
    m04_approval_before = _pinvi_m04_approval_snapshot(
        pinvi_api_url=args.pinvi_api_url,
        request_id=m04["feature_request_id"],
        email=email,
        password=password,
    )
    if (
        m04_approval_before["pinvi_approval_sha256"] != m04["pinvi_approval_sha256"]
        or m04_approval_before["map_pending_receipt_sha256"]
        != m04["map_pending_receipt_sha256"]
    ):
        raise AttestationError(
            "M04 approval receipt no longer matches its signed evidence"
        )

    before_map, before_ack, before_map_hash, _before_ack_hash = _map_case_snapshot(
        map_admin_url=args.map_admin_url,
        case_id=case_id,
        event_id=event_id,
    )
    m04_chain = _m04_server_side_chain(
        map_admin_url=args.map_admin_url,
        m04=m04,
        map_case=before_map,
    )
    before_pinvi, before_pinvi_hash, before_receipt_sha = _pinvi_case_snapshot(
        pinvi_api_url=args.pinvi_api_url,
        event_id=event_id,
        email=email,
        password=password,
    )
    _validate_pinvi_impact_evidence(
        before_pinvi,
        map_case=before_map,
        map_ack=before_ack,
    )
    before_map_event_sha = _map_case_event_hash(before_map, before_ack)
    before_pinvi_event_sha = _pinvi_case_event_hash(before_pinvi)
    if before_map_event_sha != before_pinvi_event_sha:
        raise AttestationError(
            "Map event hash does not match the Pinvi receipt event hash"
        )
    before_local_receipt_sha = _string(
        before_ack.get("local_receipt_sha256"), name="Map local receipt hash"
    )
    if before_local_receipt_sha != before_receipt_sha:
        raise AttestationError(
            "Map ACK local receipt hash does not match the Pinvi terminal receipt"
        )
    runtime_before_ui = _runtime_snapshot(
        args,
        pair=pair,
        source_revision=source_revision,
        map_admin_revision=surface_revisions["admin"],
        pinvi_image_digests=pinvi_image_digests,
    )
    _assert_runtime_snapshots_unchanged(runtime_initial, runtime_before_ui)

    command = list(args.ui_command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise AttestationError("a real Playwright command is required after --")
    runner_path = pinvi_source_root / "scripts/n150-playwright-runner.sh"
    if Path(command[0]).resolve() != runner_path.resolve():
        raise AttestationError("live UI must use the repository Playwright runner")
    command[0] = str(runner_path)
    expected_command = [
        str(runner_path),
        "--",
        "npm",
        "-w",
        "@pinvi/web",
        "run",
        "test:e2e:live-mutating",
        "--",
        "apps/web/e2e/admin-feature-reference-reconciliations-live-mutating.live.ts",
        "--workers=1",
    ]
    if command != expected_command:
        raise AttestationError("live UI command is not the pinned M05 Playwright test")
    runner_image = _docker_image_identity(args.playwright_runner_image)
    verification_id = m04["verification_id"]
    marker_path = evidence_dir / "ui-run.json"
    if marker_path.is_symlink() or marker_path.exists():
        raise AttestationError("UI evidence marker must not pre-exist the pinned run")
    child_env = os.environ.copy()
    for name in tuple(child_env):
        if name.startswith(("GIT_", "DOCKER_")) or name.lower() in {
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        }:
            child_env.pop(name)
    child_env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
    child_env["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    # M05 rebind UI 스펙의 beforeAll 게이트 — M04 쌍둥이(:PINVI_M04_LIVE_E2E)와
    # 대칭이어야 한다. 빠지면 스펙이 브라우저 동작 하나 없이 중단되고 격리
    # execution 하나가 통째로 소각된다(2026-09-01 정합성 스윕 blocker).
    child_env["PINVI_M05_LIVE_E2E"] = "1"
    child_env["PINVI_M05_UI_EVIDENCE_DIR"] = str(evidence_dir)
    child_env["PINVI_M05_LIVE_EVENT_ID"] = event_id
    child_env["PINVI_M05_LIVE_OLD_FEATURE_ID"] = old_feature_id
    child_env["PINVI_M05_LIVE_REPLACEMENT_FEATURE_ID"] = replacement_feature_id
    child_env["PINVI_M05_LIVE_IMPACT_COUNT"] = impact_count
    child_env["PINVI_M05_LIVE_EMAIL"] = email
    child_env["PINVI_M05_LIVE_PASSWORD"] = password
    child_env["M05_PINVI_EMAIL"] = email
    child_env["M05_PINVI_PASSWORD"] = password
    child_env["PINVI_M05_UI_VERIFICATION_ID"] = verification_id
    child_env["PINVI_M05_PLAYWRIGHT_RUNNER_IMAGE_REF"] = runner_image["image_ref"]
    child_env["PINVI_M05_PLAYWRIGHT_RUNNER_IMAGE_ID"] = runner_image["image_id"]
    child_env["PINVI_PLAYWRIGHT_RUNNER_IMAGE"] = runner_image["image_ref"]
    child_env["PINVI_PLAYWRIGHT_RUNNER_NETWORK"] = "host"
    child_env["PINVI_PLAYWRIGHT_RUNNER_REPO_ROOT"] = str(pinvi_source_root)
    child_env["PINVI_PLAYWRIGHT_RUNNER_SKIP_NPM_CI"] = "0"
    child_env["PINVI_LIVE_WEB_URL"] = args.pinvi_web_url
    child_env["PINVI_LIVE_API_URL"] = args.pinvi_api_url
    child_env["PINVI_M05_UI_API_URL"] = args.pinvi_api_url
    child_env["PINVI_SOURCE_REVISION"] = source_revision
    child_env["PINVI_LIVE_EXPECTED_REVISION"] = source_revision
    completed = subprocess.run(command, check=False, env=child_env)
    if completed.returncode != 0:
        raise AttestationError(f"live UI command exited with {completed.returncode}")
    _assert_clean_checkout(
        pinvi_source_root,
        expected_revision=source_revision,
        label="Pinvi source after live UI",
    )
    marker, marker_raw_hash = _read_json(marker_path)

    after_map, after_ack, after_map_hash, after_ack_hash = _map_case_snapshot(
        map_admin_url=args.map_admin_url,
        case_id=case_id,
        event_id=event_id,
    )
    after_m04_chain = _m04_server_side_chain(
        map_admin_url=args.map_admin_url,
        m04=m04,
        map_case=after_map,
    )
    if after_m04_chain != m04_chain:
        raise AttestationError("M04→M05 server-side chain drifted during the UI flow")
    m04_approval_after = _pinvi_m04_approval_snapshot(
        pinvi_api_url=args.pinvi_api_url,
        request_id=m04["feature_request_id"],
        email=email,
        password=password,
    )
    if m04_approval_after != m04_approval_before:
        raise AttestationError("M04 approval receipt drifted during the UI flow")
    after_pinvi, after_pinvi_hash, after_receipt_sha = _pinvi_case_snapshot(
        pinvi_api_url=args.pinvi_api_url,
        event_id=event_id,
        email=email,
        password=password,
    )
    _validate_pinvi_impact_evidence(
        after_pinvi,
        map_case=after_map,
        map_ack=after_ack,
    )
    after_map_event_sha = _map_case_event_hash(after_map, after_ack)
    after_pinvi_event_sha = _pinvi_case_event_hash(after_pinvi)
    if after_map_event_sha != after_pinvi_event_sha:
        raise AttestationError(
            "Map event hash does not match the Pinvi receipt event hash"
        )
    after_local_receipt_sha = _string(
        after_ack.get("local_receipt_sha256"), name="Map local receipt hash"
    )
    if after_local_receipt_sha != after_receipt_sha:
        raise AttestationError(
            "Map ACK local receipt hash does not match the Pinvi terminal receipt"
        )
    if before_map_hash != after_map_hash or before_pinvi_hash != after_pinvi_hash:
        raise AttestationError("M05 remote state drifted during the read-only UI flow")
    if before_map != after_map or before_pinvi != after_pinvi:
        raise AttestationError(
            "M05 remote snapshot is not byte-stable across the UI flow"
        )
    _validate_ui_marker(
        marker,
        event_id=event_id,
        source_revision=source_revision,
        verification_id=verification_id,
        runner_image=runner_image,
        pinvi_detail=after_pinvi,
        pinvi_detail_sha256=after_pinvi_hash,
        expected_pinvi_api_endpoint=args.pinvi_api_url.rstrip("/"),
        expected_old_feature_id=old_feature_id,
        expected_replacement_feature_id=replacement_feature_id,
        expected_impact_count=int(impact_count),
    )
    marker = _object(marker, name="M05 UI evidence marker")
    runtime_after_ui = _runtime_snapshot(
        args,
        pair=pair,
        source_revision=source_revision,
        map_admin_revision=surface_revisions["admin"],
        pinvi_image_digests=pinvi_image_digests,
    )
    _assert_runtime_snapshots_unchanged(runtime_initial, runtime_after_ui)

    source_openapi = _hash_source_openapi(
        args.map_source_root, expected=pair, revisions=surface_revisions
    )
    runtime_map_openapi = _runtime_map_openapi(
        map_admin_url=args.map_admin_url,
        source_root=args.map_source_root,
        expected=pair,
        revisions=surface_revisions,
    )
    runtime_after_openapi = _runtime_snapshot(
        args,
        pair=pair,
        source_revision=source_revision,
        map_admin_revision=surface_revisions["admin"],
        pinvi_image_digests=pinvi_image_digests,
    )
    _assert_runtime_snapshots_unchanged(runtime_after_ui, runtime_after_openapi)
    map_pair = {
        "admin": pair["admin"],
        "full": pair["full"],
        "service": pair["service"],
        "user": pair["user"],
        "admin_image_digest": runtime_after_openapi["map_admin"]["digest"],
        "api_image_digest": runtime_after_openapi["map_api"]["digest"],
        "frontend_image_digest": runtime_after_openapi["map_frontend"]["digest"],
        "runtime": {
            **runtime_map_openapi,
            "admin": runtime_after_openapi["map_admin"],
            "api": runtime_after_openapi["map_api"],
            "frontend": runtime_after_openapi["map_frontend"],
            "full_openapi_sha256": source_openapi["full"],
        },
    }
    pinvi_images = {
        "api": runtime_after_openapi["pinvi_api"],
        "web": runtime_after_openapi["pinvi_web"],
        "dagster": runtime_after_openapi["pinvi_dagster"],
    }

    live_ui = {
        "event_id": event_id,
        "event_sha256": after_map_event_sha,
        "m04_attestation_sha256": m04["attestation_sha256"],
        "m04_created_at": m04_created_at,
        "m04_feature_request_id": m04_chain["feature_request_id"],
        "m04_map_feature_uuid": m04_chain["map_feature_uuid"],
        "m04_map_pending_receipt_sha256": m04["map_pending_receipt_sha256"],
        "m04_map_provenance_sha256": m04_chain["map_provenance_sha256"],
        "m04_map_request_sha256": m04_chain["map_request_sha256"],
        "m04_pinvi_approval_sha256": m04["pinvi_approval_sha256"],
        "m04_server_side_chain_verified": True,
        "m04_verification_id": m04["verification_id"],
        "map_admin_endpoint": args.map_admin_url.rstrip("/"),
        "map_ack_sha256": after_ack_hash,
        "map_local_receipt_sha256": after_local_receipt_sha,
        "map_snapshot_before_sha256": before_map_hash,
        "map_snapshot_after_sha256": after_map_hash,
        "pinvi_snapshot_before_sha256": before_pinvi_hash,
        "pinvi_snapshot_after_sha256": after_pinvi_hash,
        "pinvi_source_revision": source_revision,
        "pinvi_api_endpoint": args.pinvi_api_url.rstrip("/"),
        "pinvi_web_endpoint": args.pinvi_web_url.rstrip("/"),
        "pinvi_receipt_sha256": after_receipt_sha,
        "old_feature_id": marker["old_feature_id"],
        "replacement_feature_id": marker["replacement_feature_id"],
        "impact_count": marker["impact_count"],
        "pinvi_detail_sha256": marker["pinvi_detail_sha256"],
        "playwright_runner_image_id": runner_image["image_id"],
        "playwright_runner_image_ref": runner_image["image_ref"],
        "runner_exit_code": completed.returncode,
        "server_side_ack_verified": True,
        "status": "passed",
        "ui_evidence_sha256": marker_raw_hash,
        "verification_id": verification_id,
    }
    if isolated_runtime is not None:
        live_ui.update(
            {
                "isolated_execution_identity_sha256": isolated_runtime[
                    "execution_identity_sha256"
                ],
                "isolated_manager_source_revision": isolated_runtime[
                    "manager_source_revision"
                ],
                "isolated_pinset_sha256": isolated_runtime["pinset_sha256"],
                "isolated_runtime_provenance_sha256": isolated_runtime["sha256"],
            }
        )
    output_hashes = {
        "ui-run": marker_raw_hash,
        "live-ui": _write_json(evidence_dir / "live-ui.json", live_ui),
        "map-pair": _write_json(evidence_dir / "map-pair.json", map_pair),
        "pinvi-images": _write_json(evidence_dir / "pinvi-images.json", pinvi_images),
    }
    # reviews/restore는 사람 리뷰와 복구 드릴의 **외부** 증거다 — staging/
    # production 활성화 경로에서만 존재하고, 격리 harness는 기계 체인만
    # 증명하므로 생산하지 않는다. isolated에서 이를 요구하면 UI가 완전히
    # green이어도 봉인 직전에 'invalid JSON evidence: reviews.json'으로
    # 죽는다(정합성 스윕 high). 격리 payload는 이미 별도 버전(v4)이다.
    if args.scope != "isolated":
        for name in ("reviews", "restore"):
            path = evidence_dir / f"{name}.json"
            _value, output_hashes[name] = _read_json(path)

    attestation_payload = {
        "created_at": int(time.time()),
        "event_id": event_id,
        "evidence_sha256": output_hashes,
        "map_ack_sha256": after_ack_hash,
        "m04_attestation_sha256": m04["attestation_sha256"],
        "m04_created_at": m04_created_at,
        "m04_feature_request_id": m04_chain["feature_request_id"],
        "m04_map_feature_uuid": m04_chain["map_feature_uuid"],
        "m04_map_pending_receipt_sha256": m04["map_pending_receipt_sha256"],
        "m04_map_provenance_sha256": m04_chain["map_provenance_sha256"],
        "m04_map_request_sha256": m04_chain["map_request_sha256"],
        "m04_pinvi_approval_sha256": m04["pinvi_approval_sha256"],
        "m04_server_side_chain_verified": True,
        "m04_verification_id": m04["verification_id"],
        "local_receipt_sha256": after_receipt_sha,
        "map_admin_endpoint": args.map_admin_url.rstrip("/"),
        "map_snapshot_sha256": after_map_hash,
        "old_feature_id": marker["old_feature_id"],
        "replacement_feature_id": marker["replacement_feature_id"],
        "impact_count": marker["impact_count"],
        "pinvi_detail_sha256": marker["pinvi_detail_sha256"],
        "pinvi_snapshot_sha256": after_pinvi_hash,
        "pinvi_api_endpoint": args.pinvi_api_url.rstrip("/"),
        "pinvi_web_endpoint": args.pinvi_web_url.rstrip("/"),
        "pinvi_source_revision": source_revision,
        "playwright_runner_image_id": runner_image["image_id"],
        "playwright_runner_image_ref": runner_image["image_ref"],
        "scope": args.scope,
        "status": "passed",
        "verification_id": verification_id,
        "version": 4 if isolated_runtime is not None else 3,
    }
    if isolated_runtime is not None:
        attestation_payload.update(
            {
                "isolated_execution_identity_sha256": isolated_runtime[
                    "execution_identity_sha256"
                ],
                "isolated_manager_source_revision": isolated_runtime[
                    "manager_source_revision"
                ],
                "isolated_pinset_sha256": isolated_runtime["pinset_sha256"],
                "isolated_runtime_provenance_sha256": isolated_runtime["sha256"],
            }
        )
    attestation = {
        "payload": attestation_payload,
        "signature": base64.urlsafe_b64encode(
            _sign(private_key, _canonical_json(attestation_payload))
        )
        .decode("ascii")
        .rstrip("="),
    }
    attestation_hash = _write_json(evidence_dir / "attestation.json", attestation)
    print(f"attestation_sha256={attestation_hash}")
    print(f"event_id={event_id}")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    m04 = subparsers.add_parser("m04")
    m04.add_argument("--evidence-dir", type=Path, required=True)
    m04.add_argument("--private-key", type=Path, required=True)
    m04.add_argument("--pinvi-api-url", required=True)
    m04.add_argument("--pinvi-api-container", required=True)
    m04.add_argument("--pinvi-web-url", required=True)
    m04.add_argument("--pinvi-web-container", required=True)
    m04.add_argument("--feature-request-id", required=True)
    m04.add_argument("--pinvi-source-revision", required=True)
    m04.add_argument(
        "--scope", choices=("smoke", "isolated", "staging", "production"), required=True
    )
    m04.add_argument("--playwright-runner-image", required=True)
    m04.add_argument("--require-root-owned", action="store_true")
    m04.add_argument("ui_command", nargs=argparse.REMAINDER)
    m04.set_defaults(handler=_m04)

    live = subparsers.add_parser("live")
    live.add_argument("--evidence-dir", type=Path, required=True)
    live.add_argument("--private-key", type=Path, required=True)
    live.add_argument("--map-admin-url", required=True)
    # v2 pair 계약은 Map revision도 runtime image digest도 선언하지 않는다. 격리
    # 실행은 runtime provenance가 그 값을 싣고 오지만, 그 밖의 scope는 pin registry
    # 파생값을 여기로 받아야 한다.
    live.add_argument("--map-source-revision")
    live.add_argument("--map-admin-image-digest")
    live.add_argument("--map-api-image-digest")
    live.add_argument("--map-frontend-image-digest")
    live.add_argument("--map-case-id", required=True)
    live.add_argument("--map-docker-project", required=True)
    live.add_argument("--map-admin-container", required=True)
    live.add_argument("--map-admin-service", required=True)
    live.add_argument("--map-api-container", required=True)
    live.add_argument("--map-api-service", required=True)
    live.add_argument("--map-frontend-container", required=True)
    live.add_argument("--map-frontend-service", required=True)
    live.add_argument("--map-source-root", type=Path, required=True)
    live.add_argument("--m04-evidence-dir", type=Path, required=True)
    live.add_argument("--pinvi-api-url", required=True)
    live.add_argument("--pinvi-docker-project", required=True)
    live.add_argument("--pinvi-api-container", required=True)
    live.add_argument("--pinvi-web-url", required=True)
    live.add_argument("--pinvi-web-container", required=True)
    live.add_argument("--pinvi-dagster-container", required=True)
    live.add_argument("--event-id", required=True)
    live.add_argument("--pinvi-source-revision", required=True)
    live.add_argument("--scope", choices=("isolated", "staging", "production"), required=True)
    live.add_argument("--isolated-runtime-provenance", type=Path)
    live.add_argument("--isolated-manager-source-revision")
    live.add_argument("--isolated-pinset-sha256")
    live.add_argument("--isolated-execution-identity-sha256")
    live.add_argument("--playwright-runner-image", required=True)
    live.add_argument("--require-root-owned", action="store_true")
    live.add_argument("ui_command", nargs=argparse.REMAINDER)
    live.set_defaults(handler=_live)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return cast(int, args.handler(args))
    except (AttestationError, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"M05 live attestation failed: {exc}") from None


if __name__ == "__main__":
    raise SystemExit(main())
