#!/usr/bin/env bash
# Run only in a disposable container: this test changes /etc and /usr/local/bin.
set -euo pipefail
[[ ${SSHLOGGER_DISPOSABLE_TEST:-} == 1 ]] || { echo 'Disposable container required.' >&2; exit 1; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
printf 'ID=ubuntu\nVERSION_ID=24.04\n' > /etc/os-release
mkdir -p /run/systemd/system /etc/audit/rules.d /tmp/mock-bin /tmp/test-source/deploy /tmp/install-work
cp "$root"/deploy/* /tmp/test-source/deploy/
tar -czf /tmp/source.tar.gz -C /tmp test-source
export PATH=/tmp/mock-bin:$PATH TMPDIR=/tmp/install-work
cat > /tmp/mock-bin/uname <<'MOCK'
#!/bin/bash
case "$1" in -m) echo "$TEST_CPU";; -s) echo Linux;; *) exit 1;; esac
MOCK
cat > /tmp/mock-bin/curl <<'MOCK'
#!/bin/bash
set -eu
[[ "$*" == *https://codeload.github.com/isac7722/ssh-logger/tar.gz/main* ]]
cp /tmp/source.tar.gz "${@: -1}"
MOCK
cat > /tmp/mock-bin/go <<'MOCK'
#!/bin/bash
set -eu
[[ "$GOOS/$GOARCH" == "$TEST_PLATFORM" ]]
printf '#!/bin/bash\n[[ "$1" == -platform ]] || exit 1\nprintf "%%s\\n" "%s"\n' "$GOOS/$GOARCH" > bin/ssh-logger-agent
chmod +x bin/ssh-logger-agent
mkdir -p "$GOMODCACHE/readonly"
chmod 500 "$GOMODCACHE/readonly"
MOCK
for cmd in apt-get auditctl augenrules systemctl; do
  printf '#!/bin/bash\nprintf "%%s\\n" "%s $*" >> /tmp/host-calls\n' "$cmd" > "/tmp/mock-bin/$cmd"
done
chmod +x /tmp/mock-bin/*
for cpu in x86_64 aarch64 arm64; do
  export TEST_CPU=$cpu
  if [[ $cpu == x86_64 ]]; then
    export TEST_PLATFORM=linux/amd64
    rules=audit.rules
  else
    export TEST_PLATFORM=linux/arm64
    rules=audit-arm64.rules
  fi
  rm -rf /etc/ssh-logger /etc/audit/rules.d/ssh-logger.rules /usr/local/bin/ssh-logger-agent /tmp/host-calls
  printf 'https://logs.example.com\n%048d\n' 0 | bash "$root/install.sh"
  cmp "$root/deploy/$rules" /etc/audit/rules.d/ssh-logger.rules
  [[ $(/usr/local/bin/ssh-logger-agent -platform) == "$TEST_PLATFORM" ]]
  [[ $(stat -c %a /etc/ssh-logger/token) == 600 ]]
  [[ -z $(ls -A "$TMPDIR") ]]
  cp /etc/ssh-logger/token /tmp/saved-token
  cp /usr/local/bin/ssh-logger-agent /tmp/saved-agent
  mkdir -p /tmp/test-source/bin
  cp /usr/local/bin/ssh-logger-agent /tmp/test-source/bin/ssh-logger-agent
  bash /tmp/test-source/deploy/update-agent.sh
  cmp /etc/ssh-logger/token /tmp/saved-token
  cmp "$root/deploy/$rules" /etc/audit/rules.d/ssh-logger.rules
  # Wrong-platform binaries must not overwrite credentials or installed binaries.
  printf '#!/bin/bash\necho linux/wrong\n' > /tmp/test-source/bin/ssh-logger-agent
  chmod +x /tmp/test-source/bin/ssh-logger-agent
  if bash /tmp/test-source/deploy/update-agent.sh; then exit 1; fi
  if bash /tmp/test-source/deploy/install-agent.sh </dev/null; then exit 1; fi
  cmp /etc/ssh-logger/token /tmp/saved-token
  cmp /usr/local/bin/ssh-logger-agent /tmp/saved-agent
  # Reject reinstallation before APT or any host command.
  rm /tmp/host-calls
  if bash "$root/install.sh"; then exit 1; fi
  [[ ! -e /tmp/host-calls ]]
  echo "PASS: $cpu bootstrap, rules, update, mismatch rejection and cleanup"
done
for cpu in armv7l riscv64; do
  export TEST_CPU=$cpu
  if bash "$root/install.sh"; then exit 1; fi
  [[ ! -e /tmp/host-calls ]]
  echo "PASS: unsupported $cpu rejected"
done
