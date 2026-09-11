#!/usr/bin/env bash
# Install the audit collector on Ubuntu 24.04 x86_64 or ARM64.
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo '지원 환경: Ubuntu 24.04 LTS / x86_64 또는 ARM64' >&2
  exit 1
fi
case $(uname -m) in
  x86_64) agent_arch=amd64 ;;
  aarch64|arm64) agent_arch=arm64 ;;
  *) echo '지원 CPU: x86_64 또는 ARM64 (32비트 ARM 미지원)' >&2; exit 1 ;;
esac
if [[ ! -r /etc/os-release ]]; then
  echo '/etc/os-release를 확인할 수 없습니다.' >&2
  exit 1
fi
. /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]]; then
  echo '이 설치 스크립트는 Ubuntu 24.04 LTS를 지원합니다.' >&2
  exit 1
fi
if ! command -v systemctl >/dev/null || [[ ! -d /run/systemd/system ]]; then
  echo 'systemd로 실행 중인 호스트에서 설치하세요.' >&2
  exit 1
fi
if [[ -e /etc/ssh-logger/token || -e /usr/local/bin/ssh-logger-agent ]]; then
  echo '기존 수집기가 있습니다. 설정을 보존하려면 README의 수집기 업데이트 절차를 사용하세요.' >&2
  exit 1
fi
privilege=()
if (( EUID != 0 )); then
  if ! command -v sudo >/dev/null; then
    echo 'sudo가 필요합니다. sudo를 설치하거나 root로 실행하세요.' >&2
    exit 1
  fi
  privilege=(sudo)
  sudo -v
fi
ref=${SSH_LOGGER_REF:-main}
if [[ ! $ref =~ ^[a-zA-Z0-9][a-zA-Z0-9._/-]*$ ]]; then
  echo 'SSH_LOGGER_REF는 브랜치, 태그 또는 커밋이어야 합니다.' >&2
  exit 1
fi
work=$(mktemp -d -t ssh-logger-install.XXXXXXXX)
cleanup() { chmod -R u+w -- "$work"; rm -rf -- "$work"; }
trap cleanup EXIT
printf '%s\n' '필수 도구와 auditd를 설치합니다.'
"${privilege[@]}" apt-get update
"${privilege[@]}" apt-get install -y --no-install-recommends auditd golang-go curl ca-certificates tar
printf '%s\n' '수집기 소스를 다운로드합니다.'
curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
  "https://codeload.github.com/isac7722/ssh-logger/tar.gz/$ref" -o "$work/source.tar.gz"
mkdir "$work/source"
tar -xzf "$work/source.tar.gz" --strip-components=1 --no-same-owner -C "$work/source"
mkdir -p "$work/source/bin"
printf '%s\n' '수집기를 빌드합니다. Go 도구와 의존성 다운로드에 시간이 걸릴 수 있습니다.'
(
  cd "$work/source"
  GOOS=linux GOARCH="$agent_arch" GOTOOLCHAIN=auto GOPATH="$work/go" GOMODCACHE="$work/go/pkg/mod" GOCACHE="$work/go-cache" CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w' -o bin/ssh-logger-agent ./agent
)
"${privilege[@]}" systemctl enable --now auditd
"${privilege[@]}" bash "$work/source/deploy/install-agent.sh"
printf '%s\n' '수집기 설치를 완료했습니다. 새 SSH 세션을 열어 대시보드에서 수집 상태를 확인하세요.'
