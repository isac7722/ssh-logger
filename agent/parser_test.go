package main

import (
	"os"
	"path/filepath"
	"sshlogger/internal/model"
	"strings"
	"testing"
)

func records(lines string) []record {
	out := []record{}
	for _, l := range strings.Split(lines, "\n") {
		if r, ok := parseRecord(l); ok {
			out = append(out, r)
		}
	}
	return out
}
func TestExecAssemblyRedactionAndSudo(t *testing.T) {
	raw := `type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=59 success=yes auid=1000 uid=0 euid=0 ses=7 exe="/usr/bin/curl" key="sshlogger_exec"
 type=EXECVE msg=audit(1700000000.123:42): argc=4 a0="curl" a1="--token" a2=736563726574 a3_len=6 a3[0]="abc" a3[1]="def"
 type=EOE msg=audit(1700000000.123:42):`
	ev := eventsFor(records(raw), "boot", func(s string) string {
		if s == "1000" {
			return "alice"
		}
		return "root"
	})
	if len(ev) != 1 {
		t.Fatalf("events: %#v", ev)
	}
	e := ev[0]
	if e.User != "alice" || e.EffectiveUser != "root" || e.SessionID != "boot:7" {
		t.Fatalf("identity: %#v", e)
	}
	if strings.Join(e.Args, " ") != "curl --token [REDACTED] abcdef" {
		t.Fatal(e.Args)
	}
}
func TestSSHSessionOnly(t *testing.T) {
	for _, exe := range []string{"/usr/sbin/sshd", "/usr/bin/sudo"} {
		raw := `type=USER_START msg=audit(1700000000.123:1): pid=123 uid=0 auid=1000 ses=7 msg='op=PAM:session_open acct="alice" exe="` + exe + `" hostname=? addr=203.0.113.1 terminal=/dev/pts/0 res=success'`
		ev := eventsFor(records(raw), "boot", func(s string) string { return s })
		if strings.HasSuffix(exe, "sshd") {
			if len(ev) != 1 || ev[0].User != "alice" || ev[0].IP != "203.0.113.1" || ev[0].Kind != "session_start" {
				t.Fatal(ev)
			}
		} else if len(ev) != 0 {
			t.Fatal("sudo must not open SSH session")
		}
	}
}
func TestSpoolRestartRotationAndAck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	state := filepath.Join(dir, "spool.db")
	line := `type=USER_START msg=audit(1700000000.123:1): uid=0 auid=1000 ses=7 msg='acct="alice" exe="/usr/sbin/sshd" addr=203.0.113.1 res=success'` + "\n"
	if e := os.WriteFile(path, []byte(line), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := openSpool(state, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.collect(path, "boot", true, func(s string) string { return s }); e != nil {
		t.Fatal(e)
	}
	ev, n, e := s.batch()
	if e != nil || n != 1 {
		t.Fatalf("batch %d %v", n, e)
	}
	s.db.Close()
	s, e = openSpool(state, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	if e = s.collect(path, "boot", true, func(s string) string { return s }); e != nil {
		t.Fatal(e)
	}
	_, n, _ = s.batch()
	if n != 1 {
		t.Fatal("checkpoint not persisted")
	}
	if e = os.Rename(path, path+".1"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte(strings.ReplaceAll(line, ":1)", ":2)")), 0600); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e = s.collect(path, "boot", true, func(s string) string { return s }); e != nil {
			t.Fatal(e)
		}
	}
	_, n, _ = s.batch()
	if n != 2 {
		t.Fatalf("rotation count %d", n)
	}
	if e = s.ack(ev); e != nil {
		t.Fatal(e)
	}
	_, n, _ = s.batch()
	if n != 1 {
		t.Fatal(n)
	}
}
func TestSpoolOverflowTracksLoss(t *testing.T) {
	s, e := openSpool(filepath.Join(t.TempDir(), "s.db"), 1)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	if e = s.commit(checkpoint{}, []model.Event{{ID: "a"}}); e != nil {
		t.Fatal(e)
	}
	if s.cp.Dropped != 1 {
		t.Fatal(s.cp)
	}
}

func TestPasswordAndPublicKeyFailureRecords(t *testing.T) {
	for _, kind := range []string{"USER_AUTH", "USER_LOGIN"} {
		raw := `type=` + kind + ` msg=audit(1700000000.100:99): uid=0 auid=4294967295 ses=4294967295 msg='op=login acct="alice" exe="/usr/sbin/sshd" addr=203.0.113.9 terminal=sshd res=failed'`
		ev := eventsFor(records(raw), "boot", func(s string) string { return s })
		if len(ev) != 1 || ev[0].Kind != "login_failure" || ev[0].SessionID != "" || ev[0].IP != "203.0.113.9" {
			t.Fatal(ev)
		}
	}
}

func TestProcessIDsComeFromAuditRecord(t *testing.T) {
	raw := `type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=59 success=yes pid=54321 ppid=12345 auid=1000 uid=0 euid=0 ses=7 exe="/usr/bin/id"
 type=EXECVE msg=audit(1700000000.123:42): argc=1 a0="id"`
	ev := eventsFor(records(raw), "boot", func(s string) string { return s })
	if len(ev) != 1 || ev[0].PID == nil || *ev[0].PID != 54321 || ev[0].PPID == nil || *ev[0].PPID != 12345 {
		t.Fatal(ev)
	}
	raw = strings.ReplaceAll(raw, "pid=54321 ppid=12345 ", "")
	ev = eventsFor(records(raw), "boot", func(s string) string { return s })
	if ev[0].PID != nil || ev[0].PPID != nil {
		t.Fatal("missing IDs must remain unknown")
	}
	if processID("0", 0) == nil || *processID("0", 0) != 0 || processID("-1", 0) != nil || processID("2147483648", 0) != nil {
		t.Fatal("invalid PID handling")
	}
}
