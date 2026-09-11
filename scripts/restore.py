#!/usr/bin/env python3
"""Explicit operator action: make restore BACKUP=backups/<file>.db."""
import os
from pathlib import Path
import sqlite3
import subprocess

source = Path(os.environ.get('BACKUP', '')).resolve()
if not source.is_file():
    raise SystemExit('복원 파일을 지정하세요: make restore BACKUP=backups/<file>.db')
with sqlite3.connect(source.as_uri() + '?mode=ro', uri=True) as db:
    if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
        raise SystemExit('백업 파일 무결성 검사 실패')
    if db.execute('SELECT version FROM schema_version').fetchone()[0] not in (1, 2, 3):
        raise SystemExit('지원하지 않는 백업 스키마')
compose = ['docker', 'compose', '-f', os.environ.get('COMPOSE_FILE', 'compose.yaml')]
# The CLI validates before replacement; always retain a fresh backup first.
subprocess.run(['python3', 'scripts/backup.py'], check=True)
subprocess.run(compose + ['stop', 'server'], check=True)
try:
    subprocess.run(compose + ['run', '--rm', '--no-deps', '-T', '--user', '0:0', '-v', str(source) + ':/restore.db:ro', 'server', '-restore', '/restore.db'], check=True)
except subprocess.CalledProcessError:
    raise SystemExit('복원 실패. 서비스는 중지 상태입니다. 기존 백업을 확인하세요.')
subprocess.run(compose + ['up', '-d', '--wait'], check=True)
print('복원 완료:', source)
