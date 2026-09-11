.DEFAULT_GOAL := help

COMPOSE_FILE ?= compose.yaml

.PHONY: up down reload status help check-compose init logs agent test backup restore integration

help:
	@printf '%s\n' \
	  'SSH Logger 관리 명령' \
	  '  make up      이미지 빌드 후 백그라운드 실행' \
	  '  make down    컨테이너 종료 및 제거 (영구 볼륨 유지)' \
	  '  make reload  이미지 재빌드 및 컨테이너 재생성 (잠시 중단)' \
	  '  make status  중지된 컨테이너를 포함한 상태 확인' \
	  '  make help    사용법 표시' \
	  '' \
	  '기본 Compose 파일: compose.yaml (COMPOSE_FILE로 변경 가능)' \
	  '  make init    초기 설정과 관리자 비밀번호 파일 생성' \
	  '  make logs    중앙 서비스 로그 보기' \
	  '  make agent   현재 아키텍처의 Linux 수집기 빌드' \
	  '  make test    Go 테스트와 프론트엔드 빌드' \
	  '  make integration  격리된 수집기·브라우저 통합 검증' \
	  '  make backup  backups/에 SQLite 백업 생성' \
	  '  make restore BACKUP=경로  현재 DB 백업 후 지정 파일 복원'

check-compose:
	@test -f "$(COMPOSE_FILE)" || { printf '%s\n' 'Compose 파일이 없습니다: $(COMPOSE_FILE)' '앱과 Compose 설정이 아직 준비되지 않았다면 운영 명령을 실행할 수 없습니다.' >&2; exit 1; }
	@command -v docker >/dev/null 2>&1 || { printf '%s\n' 'Docker를 설치해야 합니다.' >&2; exit 1; }
	@docker compose version >/dev/null 2>&1 || { printf '%s\n' 'Docker Compose v2 플러그인이 필요합니다.' >&2; exit 1; }

up: check-compose init
	docker compose -f "$(COMPOSE_FILE)" up -d --build --wait

down: check-compose
	docker compose -f "$(COMPOSE_FILE)" down

reload: check-compose init
	docker compose -f "$(COMPOSE_FILE)" up -d --build --force-recreate --wait

status: check-compose
	docker compose -f "$(COMPOSE_FILE)" ps --all

init:
	python3 scripts/init.py

logs: check-compose
	docker compose -f "$(COMPOSE_FILE)" logs -f --tail=100

agent:
	docker build --target agent --output type=local,dest=bin .

test:
	docker run --rm -v "$(CURDIR):/src" -w /src -v sshlogger-gomod:/go/pkg/mod -v sshlogger-gocache:/root/.cache/go-build golang:1.26-alpine go test ./...
	docker run --rm -v "$(CURDIR)/web:/app" -w /app node:24-alpine sh -c 'npm ci && npm run build'

backup: check-compose
	COMPOSE_FILE="$(COMPOSE_FILE)" python3 scripts/backup.py

restore: check-compose
	COMPOSE_FILE="$(COMPOSE_FILE)" BACKUP="$(BACKUP)" python3 scripts/restore.py

integration: check-compose init
	docker compose -f "$(COMPOSE_FILE)" build
	$(MAKE) agent
	bash scripts/test-integration.sh
