# Live mutating E2E Runbook

N150 live 환경에서 실제 상태 변경을 수행하는 Playwright suite다. 기존
mock e2e와 Admin read-only live matrix와 분리하며, 각 suite의 명시적 opt-in 환경변수가 없으면
항상 skip한다. Playwright runner는 N150 Docker runner만 사용한다. N150에서 실행할 수 없으면
gate를 중단하고 사유를 기록한다.

## M05 Docker Manager pinning·결박 정본

M05의 runtime pinning, Map·PinVi source pair 결박, isolated launcher 실행은
**`kor-travel-docker-manager` trusted release의 `ktdctl`만 사용한다.** PinVi script, Compose,
환경변수, 수동 SHA 전사로 current pinset을 만들거나 바꾸지 않는다. 새 후보는
`ktdctl pin rotate-pair` 한 번으로 Map·PinVi revision을 함께 회전한다. role별 회전이나
terminal pinset 재사용은 금지한다.

`PINVI_ENVIRONMENT=isolated`의 PinVi `scripts/docker-app.sh` 변이도 이 원칙의 예외가 아니다.
호출자가 설정할 수 있는 `PINVI_M05_ISOLATED_MANAGER_HARNESS` 환경변수는 권한 근거로 쓰지
않으며, Manager root driver가 private runtime directory에 만든 `0600` admission 파일을
no-follow로 검증한 경우만 허용한다. admission은 exact transaction project, pinset, Manager·Map·PinVi
source revision을 함께 결박한다. 검증기는 root EUID에서만 `/usr/bin/python3 -I`를 깨끗한
환경으로 실행하므로 호출자 `PATH`·`PYTHON*`은 interpreter·import를 바꾸지 못한다. 직접 Compose,
임의 root marker, 수동 environment 설정은 이 검증을 대신하지 못한다.

one-shot 전에는 인증된 Manager API `GET /api/v1/runtime-pins`와
`GET /api/v1/pinned-runtime/generation` 공개 사본을 확인한다. generation의
`pinset_binding`은 새 pair 회전 직후 완전한 이전 committed generation 또는 Manager registry가
Map·PinVi revision과 pinset까지 exact로 차단한 unconditional terminal generation의
`pending_rebuild` 또는 `match`여야 한다. partial·malformed·phase-scoped block·`drift`·`unknown`이면
이 runbook을 중단한다. 새 launcher가
끝난 뒤 activation attestation을 승격하려면 반드시 `match`를 다시 확인한다. private
manifest/journal, raw launcher output, 이전 terminal artifact는 PinVi가 읽거나
보관하지 않는다. PinVi M05 provenance의 Map `admin`·`full` source revision은 Manager registry
pair와 정확히 같아야 하며, v6/v8 generation schema 변경은 Map·Manager와 paired PR로만 허용한다.

## 1. 범위

- `apps/web/e2e/trip-realtime-live-mutating.live.ts`
- `apps/web/e2e/trip-day-hole-live-mutating.live.ts`
- `apps/web/e2e/trip-feature-resolution-live-mutating.live.ts`
- `apps/web/e2e/admin-backup-live-mutating.live.ts`
- `apps/web/e2e/admin-feature-request-queue-live-mutating.live.ts`
- `apps/web/e2e/admin-feature-reference-reconciliations-live-mutating.live.ts`
- verified 사용자 계정으로 두 browser context를 로그인한다.
- test prefix가 붙은 임시 Trip을 생성하고, 실제 `WS /ws/trips/{trip_id}` 연결 상태를 확인한다.
- API `PATCH /trips/{trip_id}` mutation이 다른 context의 Trip 상세 화면에 WebSocket broadcast
  reload로 반영되는지 확인한다.
- browser에서 WebSocket을 닫아 client reconnect를 유도한 뒤, 두 번째 mutation이 최신 snapshot으로
  보이는지 확인한다.
- 종료 시 생성한 Trip은 사용자 API `DELETE /trips/{trip_id}` `soft_delete`로 활성 데이터에서
  제거한다. DB row와 POI는 retention 정책 대상이며 즉시 hard-delete하지 않는다.
- Feature resolution suite는 실 Map DB의 `found|retired|suppressed|missing` fixture를 Trip POI로
  연결하고, 만료 cache의 `row_revision` 재검증(`unchanged`), proxy 강제 503의 `unverified`, 복구를
  owner 목록·API 상태·집계에서 확인한다. 같은 suite가 실 weather 값이 있는 feature, 공개 parent지만
  weather가 없는 feature, retired parent를 40일 여행의 sparse 다중 날짜 batch로 조회한다.
  직접 Trip read 한 번당 weather batch POST가 정확히 1회인지, 40일차가 과거 31일 상한으로
  생략되지 않는지 검증한다. weather batch만 강제 503으로 바꿔 `unavailable`과 복구를 확인하고
  단건 weather 요청이 0회인지도 고정한다. 격리 API는 짧은 TTL의 feature cache를 켜고, 40일
  fixture 생성 요청이 일반 사용자 rate limit을 소진하지 않도록 rate limit을 비활성화한다.
- Trip day hole suite는 날짜가 있는 3박 4일 여행을 실제 UI에서 생성하고, 1~4일차 자동 생성,
  1일차 삭제 후 가장 빠른 빈 day 재생성, 일자 설정 팝업의 날짜 수정, 진행 중 스크린샷 저장을 확인한다.
- Backup mutating suite는 staging admin 계정으로 `/admin/backup` 수동 snapshot을 1회 생성하고,
  `backup://<filename>` masking, 최근 audit의 `backup.snapshot`, snapshot 목록 limit cap을 확인한다.
  restore hotswap endpoint는 호출하지 않으며, 호출이 발생하면 실패한다. snapshot 삭제 API는 아직
  없으므로 테스트가 만든 staging snapshot은 audit evidence로 남기고 운영 retention/스토리지 정책으로
  관리한다.
- M04 Feature 요청 큐 suite는 **격리된** Map/PinVi compatible pair에서 사전에 만든 pending
  `new_place` fixture 하나만 관리자 UI로 승인한다. PinVi 응답의 `approved`와 Map queue
  `pending` receipt(`request_id`, `review_mode=feature_request_queue`, `action=submit`)를 함께
  확인한다. production, shared staging, 재실행한 fixture에는 절대 사용하지 않는다.
- M05 Feature 참조 조정 suite는 같은 격리 pair에서 M04 승인과 Map의 명시적 `rebind` 결정 뒤에만
  실행한다. worker가 local terminal receipt를 commit하고 Map ACK을 마친 event 하나를 UI에서 읽는다.
  이 suite는 추가 mutation을 하지 않으며, applied receipt의 이전/대체 Feature와 impact 수만 검증한다.

## 2. 필수 환경변수

```bash
export PINVI_LIVE_MUTATING_E2E=1
export PINVI_LIVE_WEB_URL="https://pinvi.example.com"
export PINVI_LIVE_API_URL="https://pinvi-api.example.com"
export PINVI_LIVE_EMAIL="<verified user email>"
export PINVI_LIVE_PASSWORD="<verified user password>"
```

Backup staging mutating:

```bash
export PINVI_BACKUP_LIVE_MUTATING_E2E=1
export PINVI_BACKUP_LIVE_STAGING=1
export PINVI_LIVE_WEB_URL="https://pinvi.example.com"
export PINVI_BACKUP_LIVE_EMAIL="<staging admin email>"
export PINVI_BACKUP_LIVE_PASSWORD="<staging admin password>"
```

선택:

```bash
export PINVI_LIVE_TRIP_PREFIX="[codex-live-ws]"
export PINVI_BACKUP_LIVE_REASON_PREFIX="[codex-backup-live]"
export PINVI_BACKUP_LIVE_STORAGE_STATE="/path/to/admin-storage-state.json"
export PINVI_LIVE_TEST_TIMEOUT_MS=120000
export PINVI_LIVE_WORKERS=1
```

실제 도메인과 credential은 공개 repo에 기록하지 않는다. 운영 노드 접속·도메인·계정 값은
gitignore된 `docs/deploy-runbook.local.md` 또는 로컬 env 파일에만 둔다.

## 3. 실행

아래 명령을 실행하기 전에 이미 검증한 release candidate의 full SHA를 외부 입력으로 지정하고,
runner가 사용할 Playwright image를 고정한다. image는 공식 registry의 immutable digest를 포함해야
하며, tag는 선택 사항이다.

```bash
cd ~/pinvi
: "${PINVI_LIVE_EXPECTED_REVISION:?export the trusted release-candidate full SHA before running live UI}"
export PINVI_LIVE_EXPECTED_REVISION
export PINVI_PLAYWRIGHT_RUNNER_IMAGE="${PINVI_PLAYWRIGHT_RUNNER_IMAGE:-mcr.microsoft.com/playwright@sha256:9bd26ad900bb5e0f4dee75839e957a89ae89c2b7ab1e76050e559790e946b948}"
```

```bash
cd ~/pinvi
npm run test:e2e:live-mutating:list
PINVI_LIVE_MUTATING_E2E=1 \
PINVI_LIVE_WEB_URL=http://127.0.0.1:12805 \
PINVI_LIVE_API_URL=http://127.0.0.1:12801 \
PINVI_LIVE_EMAIL="$PINVI_LIVE_EMAIL" \
PINVI_LIVE_PASSWORD="$PINVI_LIVE_PASSWORD" \
scripts/n150-playwright-runner.sh -- npm -w @pinvi/web run test:e2e:live-mutating
```

Trip day hole 단건:

```bash
PINVI_LIVE_MUTATING_E2E=1 \
PINVI_LIVE_WEB_URL=http://127.0.0.1:12805 \
PINVI_LIVE_API_URL=http://127.0.0.1:12801 \
PINVI_LIVE_EMAIL="$PINVI_LIVE_EMAIL" \
PINVI_LIVE_PASSWORD="$PINVI_LIVE_PASSWORD" \
PINVI_LIVE_SCREENSHOT_DIR="$PWD/../../.codex_tmp/live-e2e/trip-day-hole" \
scripts/n150-playwright-runner.sh -- npm -w @pinvi/web run test:e2e:live-mutating -- trip-day-hole-live-mutating.live.ts --workers=1
```

### Feature resolution 단건

동시 실행이 다른 run을 정리하지 않도록 `PINVI_LIVE_TRIP_PREFIX`는 run마다 고유해야 한다. 격리 API는
feature cache를 켜고 TTL을 짧게 설정한다. Map DB에서 확인한 서로 다른
`found|retired|suppressed|missing` ID와 `found` projection의 이름·좌표를 테스트 프로세스에
전달한다. 격리 API에는 Map API와 같은 service token을 설정한다. 테스트는 batch validator와
`unchanged` 응답을 함께 검증하므로 cache가 꺼졌거나 proxy를 우회하거나 service token이 다르면
실패한다.

```bash
# 격리 API container/server 환경
export PINVI_FEATURE_CACHE_ENABLED=true
export PINVI_FEATURE_CACHE_TTL_SECONDS=0.1
export PINVI_RATE_LIMIT_ENABLED=false
export PINVI_KOR_TRAVEL_MAP_API_BASE_URL=http://127.0.0.1:13701
export PINVI_KOR_TRAVEL_MAP_SERVICE_TOKEN="<same-token-as-isolated-map-api>"

# Playwright 환경
PINVI_LIVE_FEATURE_RESOLUTION_E2E=1 \
PINVI_LIVE_FEATURE_CACHE_REVALIDATION=1 \
PINVI_LIVE_FEATURE_CACHE_WAIT_MS=250 \
PINVI_LIVE_FOUND_FEATURE_ID="<fixture-found-id>" \
PINVI_LIVE_FOUND_FEATURE_NAME="<fixture-found-name>" \
PINVI_LIVE_FOUND_FEATURE_LON="<fixture-found-lon>" \
PINVI_LIVE_FOUND_FEATURE_LAT="<fixture-found-lat>" \
PINVI_LIVE_RETIRED_FEATURE_ID="<fixture-retired-id>" \
PINVI_LIVE_SUPPRESSED_FEATURE_ID="<fixture-suppressed-id>" \
PINVI_LIVE_MISSING_FEATURE_ID="<fixture-missing-id>" \
PINVI_LIVE_WEATHER_DATE="<YYYY-MM-DD>" \
PINVI_LIVE_WEATHER_FEATURE_ID="<fixture-weather-found-id>" \
PINVI_LIVE_WEATHER_FEATURE_NAME="<fixture-weather-found-name>" \
PINVI_LIVE_WEATHER_FEATURE_LON="<fixture-weather-found-lon>" \
PINVI_LIVE_WEATHER_FEATURE_LAT="<fixture-weather-found-lat>" \
PINVI_LIVE_WEATHER_NO_DATA_FEATURE_ID="<fixture-weather-no-data-id>" \
PINVI_LIVE_WEATHER_NO_DATA_FEATURE_NAME="<fixture-weather-no-data-name>" \
PINVI_LIVE_WEATHER_NO_DATA_FEATURE_LON="<fixture-weather-no-data-lon>" \
PINVI_LIVE_WEATHER_NO_DATA_FEATURE_LAT="<fixture-weather-no-data-lat>" \
PINVI_LIVE_TRIP_PREFIX="[codex-tvn11-<unique-run-id>]" \
PINVI_LIVE_WEB_URL=http://127.0.0.1:13805 \
PINVI_LIVE_API_URL=http://127.0.0.1:13801 \
PINVI_LIVE_MAP_PROXY_PORT=13701 \
PINVI_LIVE_MAP_UPSTREAM_PORT="<isolated-map-api-port>" \
PINVI_LIVE_EMAIL="$PINVI_LIVE_EMAIL" \
PINVI_LIVE_PASSWORD="$PINVI_LIVE_PASSWORD" \
scripts/n150-playwright-runner.sh -- npm -w @pinvi/web run test:e2e:live-mutating -- trip-feature-resolution-live-mutating.live.ts --workers=1
```

격리 stack만 사용한다. 실제 서비스 API를 proxy base URL로 재기동하지 않는다. 아래 live mutation 실행은
모두 N150의 `scripts/n150-playwright-runner.sh`를 통해 exact checkout·clean worktree·digest-pinned
Playwright image를 검증한 뒤 수행한다. 직접 `npm` 실행은 catalog list 확인에만 사용한다. 실패 시 현재 run이 출력한
고유 prefix로 활성 Trip만 수동 soft-delete하며, 다른 prefix의 Trip을 일괄 삭제하지 않는다. VWorld
key가 없는 fallback 환경에서는 지도 popup이 마운트되지 않으므로 상태 문구는 owner 목록의 접근성
label로 검증하고 지도 좌표·marker 상태는 숨김 legend와 API 상태 검증으로 보완한다.
weather 날짜는 fixture의 `valid_at|observed_at|issued_at` 범위 안에서 고른다. `weather found`와
`no_data` feature는 공개 parent여야 하고, retired fixture는 현재 공개 parent가 아니어야 한다.
`PINVI_RATE_LIMIT_ENABLED=false`는 격리 API에만 적용한다. 40일 여행 생성은 39개의 추가 POI
mutation을 포함하므로 기본 분당 60회 제한을 그대로 쓰면 본 검증이 아니라 마지막 cleanup이
429로 실패할 수 있다.

Backup staging:

```bash
cd ~/pinvi
npm run test:e2e:live-mutating:list
PINVI_BACKUP_LIVE_MUTATING_E2E=1 \
PINVI_BACKUP_LIVE_STAGING=1 \
PINVI_LIVE_WEB_URL=http://127.0.0.1:12805 \
PINVI_BACKUP_LIVE_EMAIL="$PINVI_BACKUP_LIVE_EMAIL" \
PINVI_BACKUP_LIVE_PASSWORD="$PINVI_BACKUP_LIVE_PASSWORD" \
scripts/n150-playwright-runner.sh -- npm -w @pinvi/web run test:e2e:live-mutating -- admin-backup-live-mutating.live.ts --workers=1
```

### M04 Map Feature 요청 큐 단건

Map #1029와 PinVi #458의 검증한 exact image pair만 격리 포트/DB로 기동한다. admin UI에 보이는
새 pending `new_place` fixture UUID를 한 번만 발급하고, 값은 tracked 파일이나 로그에 기록하지
않는다. Map service writer token은 PinVi API process에만 주입한다.

```bash
cd ~/pinvi
: "${PINVI_M04_UI_EVIDENCE_DIR:?set a new empty root-owned evidence directory}"
: "${PINVI_M04_PRIVATE_KEY:?set the root-owned M05 signing key path}"
: "${PINVI_M04_PINVI_API_CONTAINER:?set the isolated Pinvi API container name}"
: "${PINVI_M04_PINVI_WEB_CONTAINER:?set the isolated Pinvi Web container name}"
: "${PINVI_M04_LIVE_FEATURE_REQUEST_ID:?set the isolated pending feature-request UUID}"
: "${PINVI_M04_LIVE_EMAIL:?set the isolated admin email}"
: "${PINVI_M04_LIVE_PASSWORD:?set the isolated admin password}"
export PINVI_M04_LIVE_EMAIL PINVI_M04_LIVE_PASSWORD
python scripts/m05_activation_attestation.py m04 \
  --evidence-dir "$PINVI_M04_UI_EVIDENCE_DIR" \
  --private-key "$PINVI_M04_PRIVATE_KEY" \
  --pinvi-api-url http://127.0.0.1:13801 \
  --pinvi-api-container "$PINVI_M04_PINVI_API_CONTAINER" \
  --pinvi-web-url http://127.0.0.1:13805 \
  --pinvi-web-container "$PINVI_M04_PINVI_WEB_CONTAINER" \
  --feature-request-id "$PINVI_M04_LIVE_FEATURE_REQUEST_ID" \
  --pinvi-source-revision "$PINVI_LIVE_EXPECTED_REVISION" \
  --scope isolated \
  --playwright-runner-image "$PINVI_PLAYWRIGHT_RUNNER_IMAGE" \
  --require-root-owned \
  -- scripts/n150-playwright-runner.sh -- npm -w @pinvi/web run test:e2e:live-mutating -- apps/web/e2e/admin-feature-request-queue-live-mutating.live.ts --workers=1
```

성공 뒤 PinVi 응답 및 Map 격리 로그에서 같은 request UUID와 pending receipt를 대조한다. 실패한
fixture는 다시 승인하지 않고, 격리 DB만 폐기하거나 해당 제안을 운영 절차로 거절한다.

M04와 M05를 activation 증적으로 사용할 때는 위 직접 실행만으로는 충분하지 않다.
`scripts/m05_activation_attestation.py m04`가 정확히 이 suite를 immutable Playwright image로
실행하고, API/Web container ID·source revision·Map pending receipt를 Ed25519 증적에 묶는다.
이어지는 `live` 실행은 `--m04-evidence-dir`를 필수로 받고, 같은 PinVi API/Web container에서
승인된 Map 요청의 `manual_request` provenance와 M05의 old Feature UUID가 동일한지 전후로
검증한다. Docker Manager가 만드는 일회성 격리 harness는 `--scope isolated`만 사용하며,
root-owned `0700` evidence directory와 `0600` key를 사용한다. 이는 production activation receipt나
staging 증적이 아니며 그 환경의 receipt 생성 명령을 호출하지 않는다. smoke는 격리 pair에서만 허용하고,
staging/production 증적도 같은 root-owned 파일 보호를 요구한다.

### M05 Feature 참조 조정 증거 단건

M04 승인, Map `rebind` 결정, PinVi worker receipt/ACK가 모두 같은 격리 pair에서 끝난 뒤에만 실행한다.
이벤트 UUID와 기대 Feature ID·영향 행 수는 해당 일회성 fixture에서만 가져오며, tracked 파일이나 로그에
기록하지 않는다. 실행 자체는 읽기 전용이다.

```bash
cd ~/pinvi
: "${PINVI_M05_UI_EVIDENCE_DIR:?set a new empty root-owned evidence directory}"
: "${PINVI_M04_UI_EVIDENCE_DIR:?set the matching signed M04 evidence directory}"
: "${PINVI_M05_PRIVATE_KEY:?set the root-owned M05 signing key path}"
: "${PINVI_M05_ISOLATED_RUNTIME_PROVENANCE:?set the root-owned Manager isolated runtime provenance receipt}"
: "${PINVI_M05_MAP_ADMIN_URL:?set the isolated Map admin loopback URL}"
: "${PINVI_M05_MAP_CASE_ID:?set the isolated Map M05 case UUID}"
: "${PINVI_M05_MAP_DOCKER_PROJECT:?set the isolated Map Compose project}"
: "${PINVI_M05_MAP_ADMIN_CONTAINER:?set the isolated Map admin container name}"
: "${PINVI_M05_MAP_ADMIN_SERVICE:?set the isolated Map admin Compose service}"
: "${PINVI_M05_MAP_API_CONTAINER:?set the isolated Map API container name}"
: "${PINVI_M05_MAP_API_SERVICE:?set the isolated Map API Compose service}"
: "${PINVI_M05_MAP_FRONTEND_CONTAINER:?set the isolated Map frontend container name}"
: "${PINVI_M05_MAP_FRONTEND_SERVICE:?set the isolated Map frontend Compose service}"
: "${PINVI_M05_MAP_SOURCE_ROOT:?set the clean pinned Map source checkout}"
: "${PINVI_M05_PINVI_API_CONTAINER:?set the isolated Pinvi API container name}"
: "${PINVI_M05_PINVI_DOCKER_PROJECT:?set the isolated Pinvi Compose project}"
: "${PINVI_M05_PINVI_WEB_CONTAINER:?set the isolated Pinvi Web container name}"
: "${PINVI_M05_PINVI_DAGSTER_CONTAINER:?set the isolated Pinvi Dagster container name}"
: "${PINVI_M05_LIVE_EVENT_ID:?set the applied M05 event UUID}"
: "${PINVI_M05_LIVE_OLD_FEATURE_ID:?set the old opaque Feature ID from the fixture}"
: "${PINVI_M05_LIVE_REPLACEMENT_FEATURE_ID:?set the replacement opaque Feature ID from the fixture}"
: "${PINVI_M05_LIVE_IMPACT_COUNT:?set the expected impact row count}"
: "${PINVI_M05_LIVE_EMAIL:?set the isolated admin email}"
: "${PINVI_M05_LIVE_PASSWORD:?set the isolated admin password}"
export PINVI_M05_LIVE_E2E=1
export PINVI_LIVE_WEB_URL=http://127.0.0.1:13805
export PINVI_LIVE_API_URL=http://127.0.0.1:13801
export PINVI_M05_LIVE_EMAIL PINVI_M05_LIVE_PASSWORD
export M05_PINVI_EMAIL="$PINVI_M05_LIVE_EMAIL"
export M05_PINVI_PASSWORD="$PINVI_M05_LIVE_PASSWORD"
export PINVI_M05_LIVE_OLD_FEATURE_ID
export PINVI_M05_LIVE_REPLACEMENT_FEATURE_ID
export PINVI_M05_LIVE_IMPACT_COUNT
python scripts/m05_activation_attestation.py live \
  --evidence-dir "$PINVI_M05_UI_EVIDENCE_DIR" \
  --private-key "$PINVI_M05_PRIVATE_KEY" \
  --map-admin-url "$PINVI_M05_MAP_ADMIN_URL" \
  --map-case-id "$PINVI_M05_MAP_CASE_ID" \
  --map-docker-project "$PINVI_M05_MAP_DOCKER_PROJECT" \
  --map-admin-container "$PINVI_M05_MAP_ADMIN_CONTAINER" \
  --map-admin-service "$PINVI_M05_MAP_ADMIN_SERVICE" \
  --map-api-container "$PINVI_M05_MAP_API_CONTAINER" \
  --map-api-service "$PINVI_M05_MAP_API_SERVICE" \
  --map-frontend-container "$PINVI_M05_MAP_FRONTEND_CONTAINER" \
  --map-frontend-service "$PINVI_M05_MAP_FRONTEND_SERVICE" \
  --map-source-root "$PINVI_M05_MAP_SOURCE_ROOT" \
  --m04-evidence-dir "$PINVI_M04_UI_EVIDENCE_DIR" \
  --pinvi-api-url http://127.0.0.1:13801 \
  --pinvi-docker-project "$PINVI_M05_PINVI_DOCKER_PROJECT" \
  --pinvi-api-container "$PINVI_M05_PINVI_API_CONTAINER" \
  --pinvi-web-url http://127.0.0.1:13805 \
  --pinvi-web-container "$PINVI_M05_PINVI_WEB_CONTAINER" \
  --pinvi-dagster-container "$PINVI_M05_PINVI_DAGSTER_CONTAINER" \
  --event-id "$PINVI_M05_LIVE_EVENT_ID" \
  --pinvi-source-revision "$PINVI_LIVE_EXPECTED_REVISION" \
  --scope isolated \
  --isolated-runtime-provenance "$PINVI_M05_ISOLATED_RUNTIME_PROVENANCE" \
  --playwright-runner-image "$PINVI_PLAYWRIGHT_RUNNER_IMAGE" \
  --require-root-owned \
  -- scripts/n150-playwright-runner.sh -- npm -w @pinvi/web run test:e2e:live-mutating -- apps/web/e2e/admin-feature-reference-reconciliations-live-mutating.live.ts --workers=1
```

`m05_activation_attestation.py live`가 M04 증적의 verification ID를 M05 activation nonce로
의도적으로 재사용하고, 실제 runner image ID/ref를 생성해 child suite에 전달하므로 이 두 값을
수동으로 지정하지 않는다. M04 challenge와 M05 activation을 같은 nonce로 결박하는 계약이다.
M05 event가 목록 첫 페이지에 없거나
terminal receipt가 없으면 fixture/worker/ACK 상태를 먼저 확인한다.
activation gate에서는 단독 UI pass가 아니라, 앞 절의 서명된 M04 증적과 `live`의 Map 결정·ACK
server-side 대조까지 모두 성공해야 한다.

### v2 pair 계약에서 비격리(`--scope staging|production`) 실행

pair 계약이 v2가 되면 계약은 **Map source revision도 runtime image digest도 선언하지
않는다**(`T-VN-PAIR-V2` — 정본은 `kor-travel-map` 저장소 `docs/tasks-acceptance.md`의 같은
이름 절이다). 격리 실행은 Manager가 만든 root-owned runtime provenance가 그 값을 싣고
오지만, 비격리 scope에서는 **운영자가 pin registry에서 가져와 명시적으로 넘겨야 한다**:

```bash
  --map-source-revision "$MAP_PINNED_REVISION"   --map-admin-image-digest "$MAP_ADMIN_IMAGE_DIGEST"   --map-api-image-digest "$MAP_API_IMAGE_DIGEST"   --map-frontend-image-digest "$MAP_FRONTEND_IMAGE_DIGEST" ```

넷 다 **Manager pin registry**가 정본이다. n150에서:

- revision: `ktdctl pin show`의 Map source revision
- image digest 셋: 그 pinset의 root-owned `pinned-runtime-rebuild-v8-<pinset>.json`
  (Map admin/api/frontend의 build 결과 image ID)

하나라도 빠지면 attestation이 **무엇을 배선해야 하는지 이름을 대며** 거절한다. 조용히
검사를 건너뛰지 않는다.

**이 값들의 보증 범위를 정확히 알아 둘 것.** attestation은 넘겨받은 digest를 실행 중
컨테이너와 대조한다 — 즉 "지금 떠 있는 것이 pin registry가 의도한 이미지인가"를 보는
것이고, 그 판정의 근거는 위 문서 하나다. v1 계약이 담고 있던 사본은 독립 앵커처럼
보였지만 실제로는 두 pinset 낡은 채 방치된 적이 있어 앵커 구실을 못 했다. `docker
inspect`로 읽은 값을 되돌려 넣으면 자기확인이 되므로, **반드시 pin registry 문서에서**
가져온다.

`--scope isolated`는 Manager가 root-owned `0600`으로 만든 runtime provenance receipt를 반드시
함께 받는다. 이 receipt는 exact Map/PinVi source, Map full OpenAPI, 새로 build한 여섯 runtime image
ID를 고정한다. 기존 canonical runtime image ID를 재사용하거나 production/staging receipt로 바꾸는
입력은 attestation이 거부한다.

일반 live-mutating suite는 공개 HTTPS origin을 사용할 수 있다. 단,
`m05_activation_attestation.py m04/live`는 API·Web·Map의 runtime peer를 검증하므로
`127.0.0.1`/`localhost` loopback URL만 허용한다. `--scope production`은 증적의 운영 범위를
뜻하며 공개 HTTPS URL을 허용한다는 뜻이 아니다. production 증적이 필요하면 승인된 N150에서
실제 API/Web/Map container의 `127.0.0.1` host binding과 정확히 같은 port를 가리키는 loopback
port-forward/proxy를 통해 실행한다. proxy가 다른 host port로 변환되면 attestation의 Docker
binding 검증이 실패하므로, container port와 host port 매핑을 증적 전에 확인한다. 공개 도메인을
attestation CLI의 `*_URL` 인자로 직접 넣지 않는다. runner의 exact SHA와 digest-pinned image
조건은 그대로 유지한다.

## 4. 실패 처리

- 로그인 실패: test 계정의 이메일 인증, 비밀번호, CORS/cookie 설정을 확인한다.
- host에서 격리 API를 직접 띄우며 운영 container env를 재사용할 때
  `PROMETHEUS_MULTIPROC_DIR`가 container 내부 전용 경로면 해제하거나 실제 writable 디렉터리로
  바꾼다. 그렇지 않으면 health는 통과해도 첫 metric label 생성 요청부터 500이 날 수 있다.
- Live 계정은 `EmailStr`이 허용하는 실제 형식의 도메인을 써야 한다. 예약·special-use 도메인은
  DB에 직접 만든 계정이어도 login request validation에서 422가 된다.
- 긴 UI timeout 전에 같은 Origin의 OAuth provider GET·login POST를 직접 확인해 CORS, API 생존,
  계정 계약을 checkpoint로 고정한다. 실패 시 clone/build부터 반복하지 않고 이 checkpoint부터
  재개한다.
- Trip 생성 실패: 계정 상태, API rate limit, `POST /trips` 응답을 확인한다.
- WebSocket 연결 실패: Web build의 `NEXT_PUBLIC_PINVI_API_URL`, API `/ws/trips/{trip_id}`
  cookie 전달, reverse proxy WebSocket upgrade 설정을 확인한다.
- broadcast reload 실패: API mutation 응답, backend `realtime_broker.publish_event_nowait`,
  API worker 수를 확인한다. ADR-035 현재 구조에서는 `PINVI_API_WORKERS=1`이어야 한다.
- cleanup 실패: 생성된 Trip title prefix로 검색해 수동 정리하고, 실패 내용을 `docs/journal.md`에
  남긴다.
- Backup snapshot 생성 실패: API `POST /admin/backup/snapshot` 응답, `PINVI_BACKUP_DIR` 디스크
  여유, `pg_dump` 설치, `PINVI_BACKUP_MIN_FREE_BYTES` guard를 확인한다.
- Backup audit 확인 실패: `/admin/audit` 최근 100건에 `backup.snapshot`이 보이는지, admin 계정
  권한과 audit append commit 상태를 확인한다.
