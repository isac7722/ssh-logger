# API 계약

모든 시각은 UTC Unix epoch 밀리초다. 응답은 JSON이며 오류는 `{"error":"설명"}`이다. API는 동일 출처 웹 화면과 수집기 전용이며 CORS를 열지 않는다.

## 관리자 인증

`POST /api/login`에 `{"username":"admin","password":"..."}`를 보내면 HttpOnly 세션 쿠키와 `{"csrf":"...","username":"admin"}`를 받는다. 로그인 요청의 `Origin`은 `PUBLIC_ORIGIN`과 일치해야 한다. 로그인 후 변경 요청에는 같은 Origin과 `X-CSRF-Token`이 필요하다. `GET /api/me`로 현재 CSRF 토큰과 계정명을 확인하고 `POST /api/logout`으로 세션을 폐기한다.

서버 세션은 12시간 후 만료된다. IP별 15분 동안 인증 실패가 10회 누적되면 이후 로그인 요청을 차단한다. 인증 실패만 횟수에 포함하며, 차단 전에 로그인에 성공하면 해당 IP의 실패 횟수를 초기화한다. 차단된 요청은 제한 시간을 연장하지 않는다. 프록시 환경에서는 기본적으로 프록시 IP 기준이며 임의의 X-Forwarded-For를 신뢰하지 않는다.

## 관리자 계정 관리

모든 관리자는 같은 권한을 갖는다. 아래 API는 로그인 세션이 필요하며 변경 요청은 Origin·CSRF 검사를 적용한다.

| API | 동작 |
| --- | --- |
| `GET /api/admins` | `[{"username":"admin"}]` 형태로 계정명만 반환 |
| `POST /api/admins` | `{"username":"operator","password":"..."}`로 관리자 생성, 201 및 계정명 반환. 중복 계정명은 409 |
| `PUT /api/me/password` | `{"current_password":"...","new_password":"..."}`로 자신의 비밀번호 변경. 성공하면 200 및 `{"status":"ok"}` 반환, 해당 계정의 모든 세션 폐기 |

새 계정명은 영문·숫자로 시작하는 1–64자의 영문·숫자·점·밑줄·하이픈이다. 비밀번호는 UTF-8 기준 12–72바이트이며 bcrypt 해시로 저장한다. 현재 비밀번호 오류, 새 비밀번호 형식 오류와 동일한 비밀번호로 변경하는 요청은 400이다. 다른 관리자의 세션은 유지한다. 비밀번호 변경 후 새 비밀번호로 다시 로그인해야 한다.

스키마 3은 인증 세션에 관리자 계정명을 저장한다. 버전 1·2에서 이전할 때 소유자를 알 수 없는 기존 인증 세션은 폐기하며 계정과 감사 기록은 유지한다.

## 조회 및 관리

| API | 동작 |
| --- | --- |
| `GET /api/health` | 인증 없는 최소 상태 점검 |
| `GET /api/overview?day_start=<ms>` | 현재 세션, 오늘 세션 시작·인증 실패 기록, 서버 수집 상태 집계 |
| `GET /api/servers` | 폐기되지 않은 서버 상태 및 누적 손실·공백 카운터 |
| `POST /api/servers` | `{"name":"prod-01"}` 등록, id/token 한 번 반환 |
| `POST /api/servers/{id}/rotate` | 기존 토큰 무효화, 새 토큰 반환 |
| `POST /api/servers/{id}/revoke` | 서버 논리 삭제 및 수집 인증 폐기, DB 기록 유지 |
| `GET /api/events` | 활동 검색 |
| `GET /api/sessions` | 접속 세션 조회 |
| `GET /api/settings` | 보관 기간 조회 |
| `PUT /api/settings` | `{"retention_days":30}`, 1–365일 |

서버 폐기는 `revoked=1`로 표시하는 논리 삭제다. 폐기된 서버와 관련 활동·세션은 조회 API, 활동 건수 및 전체 현황 집계에서 제외한다. `server_id`를 직접 지정해도 기록을 반환하지 않는다. 기존에 폐기된 서버에도 동일하게 적용한다. 토큰 재발급 및 재폐기 요청은 404이며, 기존 토큰 수집 요청은 401이다. DB 행은 즉시 삭제하지 않고 기존 보관 기간 정책에 따라 정리한다. 이름의 고유 제약은 유지하므로 새 서버 등록 시 다른 이름을 사용해야 한다.

events 필터: `from`, `to`(밀리초, 기본 최근 24시간, 최대 366일), `server_id`, `user`, `ip`, `session_id`, `kind`, `q`, `page`(0부터). q는 프로그램·인자의 대소문자를 구분하는 부분 문자열 검색이다. sessions 필터: `server_id`, `user`, `ip`, `active=1`(종료가 관측되지 않은 세션), `page`.

이벤트는 시각 내림차순, 같은 시각이면 서버 내부 seq 내림차순이다. 한 페이지 표시량은 50개이며 다음 페이지 존재 여부 확인을 위해 최대 51개를 반환한다. 세션은 접속 시각 내림차순이다. `active`는 최근 서버 상태 및 /proc에서 확인된 세션, `unknown`은 상태 확인 불가, `ended`는 종료 기록 관측을 의미한다. `linked=0` 실행은 SSH 세션임을 확정하지 않는다.

## 수집

`POST /api/ingest`, `Authorization: Bearer <서버별 토큰>`.

```json
{
  "events": [{
    "id": "boot-id:audit-time:serial:exec",
    "time": 1789128000000,
    "kind": "exec",
    "session_id": "boot-id:7",
    "user": "alice",
    "login_uid": "1000",
    "effective_user": "root",
    "ip": "",
    "program": "/usr/bin/id",
    "args": ["id"],
    "outcome": "yes"
  }],
  "health": "ok",
  "backlog": 1,
  "dropped": 0,
  "active_sessions": ["boot-id:7"]
}
```

kind는 `login_success`, `login_failure`, `session_start`, `session_end`, `exec`다. exec의 outcome은 exec 시스템 호출의 결과이며 프로그램 종료 코드가 아니다. 세션 ID는 부팅 ID와 Linux 감사 세션 ID의 조합이다.

최대 본문 2MiB, 최대 이벤트 500개. 기본 수집기는 한 번에 최대 100개, 약 1MiB로 묶어 전송한다. `(server_id,id)`로 중복을 제거한다. 전체 배치가 유효하고 SQLite 커밋이 완료되어야 HTTP 200을 반환한다. 수집기는 200 이후에만 큐에서 삭제한다. 토큰 오류는 401, 형식 오류는 400, 저장 실패는 503이다.

정상 시 최대 5초 주기로 상태와 이벤트를 전송한다. 실패 시 5초부터 최대 60초까지 재시도 간격을 늘린다. 서버 시계가 중앙보다 5분 이상 미래인 이벤트는 거부하므로 NTP 동기화가 필요하다.

## 활동 분류 및 프로세스 필드

`GET /api/events`는 `activity=important|all|routine`을 받는다. 기본값은 하위 호환을 위해 `all`이며 웹 UI는 `important`를 명시한다. 조건을 페이지 분할 전에 적용한다. 각 항목에 `routine_reason`(주요 활동은 빈 문자열), `pid`, `ppid`(미수집은 null)를 반환한다.

`summary=1`이면 배열 대신 다음 객체를 반환한다. 건수는 같은 검색 조건의 전체 범위 기준이며 페이지 크기가 아니다. `items`는 기존과 동일하게 최대 51개다.

```json
{"items":[],"total_count":125,"routine_count":120,"visible_count":5,"activity":"important"}
```

수집 이벤트에 선택적으로 `pid`(1–2147483647), `ppid`(0–2147483647)를 보낼 수 있다. 생략 또는 null은 미수집이다. 부모 PID 0도 유효한 값이다. 오래된 수집기가 필드를 보내지 않아도 수신하며, 기존 기록에 PID를 소급하여 채우지 않는다. 이 필드만으로 부모 프로그램명이나 정확한 프로세스 수명을 확정하지 않는다.
