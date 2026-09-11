#!/usr/bin/env python3
"""Create local configuration without overwriting existing credentials."""
import os
from pathlib import Path
import secrets

root = Path(__file__).resolve().parent.parent
secret_dir = root / '.secrets'
secret_dir.mkdir(mode=0o700, exist_ok=True)
secret_dir.chmod(0o700)
password = secret_dir / 'admin_password'
try:
    fd = os.open(password, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    pass
else:
    with os.fdopen(fd, 'w') as stream:
        stream.write(secrets.token_urlsafe(24) + '\n')
    # Docker Compose local secrets are bind mounts; the parent directory remains
    # owner-only on the host while the unprivileged container can read this file.
    password.chmod(0o644)
    print('관리자 초기 비밀번호 생성: .secrets/admin_password (화면에는 출력하지 않음)')
try:
    fd = os.open(root / '.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    pass
else:
    with os.fdopen(fd, 'w') as stream:
        stream.write((root / '.env.example').read_text())
    print('기본 환경 설정 생성: .env')
