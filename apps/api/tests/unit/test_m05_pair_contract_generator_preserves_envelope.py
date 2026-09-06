"""계약 생성기가 **소비자가 읽을 수 있는 판**을 내는지 본다.

`scripts/generate_m05_pair_contract.py`는 v2 봉투(`{"map", "version": 2}`)를
계산한다. 그런데 커밋된 계약은 v1이고, 소비자
`apps/api/app/core/config.py:_load_m05_pair_provenance`는
`set(raw) == {"map", "runtime_image_digests", "version"}`과 `version == 1`을
요구한다 — 그리고 그 검사는 **모듈 스코프**에서 돈다.

즉 생성기의 문서가 처방하는 `--write` 한 번이 PinVi API 컨테이너를 import에서
죽인다(`RuntimeError: Map M05 pair provenance envelope is invalid`). Manager의
격리 preflight는 v1/v2를 함께 읽으므로 회전 전에 잡지 못하고, 실패는 71분짜리
pinned rebuild를 태운 뒤에야 드러난다(2026-09-03 적대 리뷰가 선적발).

그래서 생성기는 **봉투 판을 정하지 않는다** — 커밋된 계약이 v1이면 v1로 담아
돌려준다. v2 전환은 소비자를 함께 옮기는 의도된 한 걸음이어야 하고, 재생성이
그것을 대신 결정하면 안 된다.

여기서는 텍스트가 아니라 **동작**을 본다: 생성기 출력을 소비자에게 그대로 먹인다.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[4]
_GENERATOR = _ROOT / "scripts" / "generate_m05_pair_contract.py"
_CONTRACT = _ROOT / "contracts" / "kor-travel-map-m05-pair-provenance-v1.json"


def _generator() -> Any:
    spec = importlib.util.spec_from_file_location("_generate_m05_pair", _GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _committed() -> dict[str, Any]:
    return json.loads(_CONTRACT.read_text(encoding="utf-8"))


def test_the_generator_reproduces_the_committed_contract_exactly() -> None:
    """`--write`가 무해해야 한다 — 유도값이 커밋된 것과 같아야 그렇다."""
    assert _generator().build_contract() == _committed()


def test_the_generator_never_changes_the_envelope() -> None:
    """판(version)과 최상위 키 집합은 생성기가 정하지 않는다."""
    derived = _generator().build_contract()
    committed = _committed()
    assert set(derived) == set(committed)
    assert derived["version"] == committed["version"]


def test_the_consumer_accepts_the_generated_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """생성기 출력을 소비자에게 그대로 먹여 본다 — 텍스트가 아니라 동작이다."""
    from app.core import config

    rendered = (
        json.dumps(_generator().build_contract(), indent=2, sort_keys=True, ensure_ascii=False)
        + "\n"
    )
    monkeypatch.setattr(config, "_m05_pair_provenance_text", lambda: rendered)
    config._load_m05_pair_provenance()


def test_the_consumer_now_reads_a_v2_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """소비자가 v2 봉투를 읽는다 — 종전에는 여기서 죽는 것을 고정한 게이트였다.

    이 테스트의 이전 판(`test_a_v2_envelope_would_break_the_consumer`)은 "v2를 먹이면
    소비자가 죽는다"를 의도적으로 고정했고, 독스트링이 "소비자가 v2를 받아들이도록
    바뀌면 여기서 깨진다. 그때가 봉투 전환을 의도적으로 수행할 시점"이라 적었다.
    2026-09-07이 그때다(`T-VN-PAIR-V2` 해제 조건 §1).

    v2에서 사라지는 두 필드는 **조용히 비워지지 않는다** — surface의 revision 자리는
    `None`이고 runtime image digest 표는 비며, 그 값을 실제로 쓰는 활성화 경로가
    무엇을 배선해야 하는지 이름을 대며 fail-close한다.
    """
    from app.core import config

    v2 = _committed()
    assert v2["version"] == 2, "커밋된 계약이 v2여야 이 테스트가 실제를 본다"
    committed = v2
    monkeypatch.setattr(
        config, "_m05_pair_provenance_text", lambda: json.dumps(v2, ensure_ascii=False)
    )
    provenance, image_digests, details, version = config._load_m05_pair_provenance()
    assert version == 2
    assert image_digests == {}
    assert set(provenance) == {"admin", "full", "service", "user"}
    for name, entry in provenance.items():
        assert entry[0] == committed["map"][name]["openapi_sha256"], name
        assert entry[1] is None, f"v2는 revision을 선언하지 않는다: {name}"
    assert set(details) == {"admin", "full", "service", "user"}


def test_the_consumer_still_reads_a_v1_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """dual-read의 나머지 절반 — v1도 계속 읽어야 한다.

    커밋된 계약은 2026-09-07에 v2가 됐다(`T-VN-PAIR-V2` §3). 그래도 v1 경로를 지우지
    않는다 — 롤백 경로이고, Manager도 같은 이유로 v1 분기를 §7까지 남긴다. 그래서
    여기서는 커밋본이 아니라 **합성 v1 문서**로 고정한다.
    """

    from app.core import config

    committed = _committed()
    revision = "0" * 40
    v1 = {
        "map": {
            name: {**surface, "source_revision": revision}
            for name, surface in committed["map"].items()
        },
        "runtime_image_digests": {
            name: "sha256:" + "0" * 64 for name in ("admin", "api", "frontend")
        },
        "version": 1,
    }
    monkeypatch.setattr(
        config, "_m05_pair_provenance_text", lambda: json.dumps(v1, ensure_ascii=False)
    )
    provenance, image_digests, _details, version = config._load_m05_pair_provenance()
    assert version == 1
    assert set(image_digests) == {"admin", "api", "frontend"}
    for name, entry in provenance.items():
        assert entry[1] == revision, name


def test_an_unknown_envelope_version_is_still_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """dual-read가 '아무 판이나 받는다'가 되면 안 된다."""

    from app.core import config

    committed = _committed()
    for version in (0, 3, 99):
        broken = {**committed, "version": version}
        monkeypatch.setattr(
            config, "_m05_pair_provenance_text", lambda b=broken: json.dumps(b, ensure_ascii=False)
        )
        with pytest.raises(RuntimeError, match="envelope is invalid"):
            config._load_m05_pair_provenance()


def test_a_v2_envelope_that_still_declares_a_revision_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v2를 선언하면서 v1 필드를 남기면 거부한다 — Manager도 같은 규칙이다."""

    from app.core import config

    committed = _committed()
    half = {
        "map": {
            name: {**surface, "source_revision": "0" * 40}
            for name, surface in committed["map"].items()
        },
        "version": 2,
    }
    monkeypatch.setattr(
        config, "_m05_pair_provenance_text", lambda: json.dumps(half, ensure_ascii=False)
    )
    with pytest.raises(RuntimeError, match="entry is invalid"):
        config._load_m05_pair_provenance()
