#!/usr/bin/env python3
import datetime
import os
from pathlib import Path
import subprocess

compose = ['docker', 'compose', '-f', os.environ.get('COMPOSE_FILE', 'compose.yaml')]
name = 'sshlogger-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.db'
folder = Path('backups')
folder.mkdir(mode=0o700, exist_ok=True)
remote = '/data/' + name
subprocess.run(compose + ['exec', '-T', 'server', '/app/server', '-backup', remote], check=True)
subprocess.run(compose + ['cp', 'server:' + remote, str(folder / name)], check=True)
(folder / name).chmod(0o600)
subprocess.run(compose + ['exec', '-T', 'server', 'rm', remote], check=True)
print('백업 저장:', folder / name)
