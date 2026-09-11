#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo 'sudo bash deploy/update-agent.sh 로 실행하세요.' >&2
  exit 1
fi
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binary=/usr/local/bin/ssh-logger-agent
if [[ ! -x "$base/bin/ssh-logger-agent" || ! -x "$binary" || ! -f /etc/ssh-logger/agent.env ]]; then
  echo 'make agent로 빌드하고, 기존 수집기가 설치된 서버에서 실행하세요.' >&2
  exit 1
fi
stage=$(mktemp -d /usr/local/bin/.ssh-logger-update.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
install -m 755 "$base/bin/ssh-logger-agent" "$stage/agent"
cp -p -- "$binary" "$binary.previous"
# Atomic replacement avoids overwriting an executable that is currently running.
mv -f -- "$stage/agent" "$binary"
if ! systemctl restart ssh-logger-agent || ! systemctl is-active --quiet ssh-logger-agent; then
  install -m 755 "$binary.previous" "$stage/rollback"
  mv -f -- "$stage/rollback" "$binary"
  systemctl restart ssh-logger-agent || true
  echo '업데이트 후 시작에 실패하여 이전 바이너리를 복원했습니다. 서비스 로그를 확인하세요.' >&2
  exit 1
fi
echo '수집기를 업데이트했습니다. 기존 토큰, 설정, 감사 규칙과 로컬 전송 큐는 유지됩니다.'
