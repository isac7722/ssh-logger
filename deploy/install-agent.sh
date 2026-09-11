#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo 'sudo bash deploy/install-agent.sh 로 실행하세요.' >&2; exit 1; fi
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ ! -x "$base/bin/ssh-logger-agent" ]]; then echo '먼저 make agent로 bin/ssh-logger-agent를 빌드하고 이 서버에 복사하세요.' >&2; exit 1; fi
if ! command -v auditctl >/dev/null || ! command -v augenrules >/dev/null; then echo 'auditd를 먼저 설치하세요: sudo apt-get install auditd' >&2; exit 1; fi
if [[ $(uname -m) != x86_64 ]]; then echo '현재 제공 감사 규칙과 바이너리 기본 빌드는 x86_64용입니다.' >&2; exit 1; fi
read -r -p '중앙 서버 HTTPS 주소 (예: https://logs.example.com): ' origin
if [[ ! $origin =~ ^https://[a-zA-Z0-9._:-]+/?$ ]]; then echo 'HTTPS origin만 입력하세요 (경로나 자격 증명 제외).' >&2; exit 1; fi
read -r -s -p '서버 등록 후 발급받은 토큰: ' token
printf '\n'
if [[ ! $token =~ ^[a-f0-9]{48}$ ]]; then echo '토큰 형식이 올바르지 않습니다.' >&2; exit 1; fi
install -d -m 700 /etc/ssh-logger /var/lib/ssh-logger
umask 077
printf '%s\n' "$token" > /etc/ssh-logger/token
printf 'SSHLOGGER_URL=%s\n' "$origin" > /etc/ssh-logger/agent.env
unset token
install -m 755 "$base/bin/ssh-logger-agent" /usr/local/bin/ssh-logger-agent
install -m 644 "$base/deploy/ssh-logger-agent.service" /etc/systemd/system/ssh-logger-agent.service
if [[ -e /etc/audit/rules.d/ssh-logger.rules ]] && ! cmp -s "$base/deploy/audit.rules" /etc/audit/rules.d/ssh-logger.rules; then
 echo '기존 ssh-logger.rules가 다릅니다. 직접 검토 후 병합하세요. 기존 파일은 유지했습니다.' >&2; exit 1
fi
install -m 640 "$base/deploy/audit.rules" /etc/audit/rules.d/ssh-logger.rules
augenrules --load
systemctl daemon-reload
systemctl enable --now ssh-logger-agent
systemctl restart ssh-logger-agent
systemctl status ssh-logger-agent --no-pager
