#!/usr/bin/env python3
"""Run against a disposable test server; never point this at production."""
import http.cookiejar
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

origin = os.environ.get('TEST_URL', 'http://localhost:18080')
root = Path(__file__).resolve().parent.parent
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ''

def api(path, body=None):
    headers = {'Content-Type': 'application/json', 'Origin': origin, 'X-CSRF-Token': csrf}
    req = urllib.request.Request(origin + '/api' + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
    with opener.open(req, timeout=5) as res:
        return json.load(res)

csrf = api('/login', {'username': 'admin', 'password': (root / '.secrets/admin_password').read_text().strip()})['csrf']
server = api('/servers', {'name': 'agent-fixture-' + str(time.time_ns())})
with tempfile.TemporaryDirectory(prefix='sshlogger-integration-') as tmp:
    tmp = Path(tmp)
    token = tmp / 'token'
    token.write_text(server['token'])
    token.chmod(0o600)
    source = tmp / 'audit.log'
    stamp = int(time.time()) - 10
    source.write_text(
        f'type=USER_START msg=audit({stamp}.100:10): uid=0 auid=1000 ses=12345 msg=\'acct="fixture-user" exe="/usr/sbin/sshd" addr=203.0.113.12 res=success\'\n'
        f'type=SYSCALL msg=audit({stamp}.200:11): arch=c000003e syscall=59 success=yes pid=54321 ppid=12345 auid=1000 uid=0 euid=0 ses=12345 exe="/usr/bin/curl"\n'
        f'type=EXECVE msg=audit({stamp}.200:11): argc=3 a0="curl" a1="--token" a2="must-be-redacted"\n'
        f'type=EOE msg=audit({stamp}.200:11):\n'
    )
    args = [str(root / 'bin/ssh-logger-agent'), '-url', origin, '-allow-http', '-token-file', str(token), '-audit-log', str(source), '-state', str(tmp / 'spool.db'), '-from-start']
    with open(tmp / 'agent.log', 'w') as logs:
        def run_until(expected):
            proc = subprocess.Popen(args, stdout=logs, stderr=logs)
            try:
                time.sleep(2)
                for _ in range(20):
                    events = api('/events?server_id=' + server['id'])
                    if len(events) == expected:
                        return events
                    if proc.poll() is not None:
                        raise AssertionError('agent exited unexpectedly')
                    time.sleep(1)
                raise AssertionError('agent delivery timed out')
            finally:
                proc.terminate()
                proc.wait(timeout=10)
        events = run_until(2)
        execution = next(e for e in events if e['kind'] == 'exec')
        assert execution['args'] == ['curl', '--token', '[REDACTED]'], execution
        assert execution['linked'] == 1
        assert execution['pid'] == 54321 and execution['ppid'] == 12345
        # Restart with the same checkpoint: no duplicate records.
        events = run_until(2)
        # Rename rotation; next invocation drains old inode and reads new file.
        source.rename(tmp / 'audit.log.1')
        source.write_text(f'type=USER_END msg=audit({stamp+1}.100:12): uid=0 auid=1000 ses=12345 msg=\'acct="fixture-user" exe="/usr/sbin/sshd" addr=203.0.113.12 res=success\'\n')
        run_until(3)
        sessions = api('/sessions?server_id=' + server['id'])
        assert sessions[0]['status'] == 'ended', sessions
        assert len(api('/events?server_id=' + server['id'])) == 3
print('PASS: actual agent binary → HTTP API → SQLite; redaction, session linkage, restart and rotation')
