#!/usr/bin/env bash
# Shared preflight; source from install/update before changing host state.
check_agent_platform() {
  if [[ $(uname -s) != Linux ]]; then
    echo 'Linux 수집기만 지원합니다.' >&2; return 1
  fi
  case $(uname -m) in
    x86_64) agent_arch=amd64 ;;
    aarch64|arm64) agent_arch=arm64 ;;
    *) echo '지원 CPU: x86_64 또는 ARM64 (32비트 ARM 미지원)' >&2; return 1 ;;
  esac
  local binary_platform
  if ! binary_platform=$("$1" -platform) || [[ $binary_platform != "linux/$agent_arch" ]]; then
    echo "대상 서버는 linux/$agent_arch입니다. 해당 아키텍처로 수집기를 다시 빌드하세요." >&2
    return 1
  fi
}
